//! Linux policy routing: the Tunnelvision (CVE-2024-3661) guard.
//!
//! # Rule layout (lower `pref` is evaluated first)
//!
//! ```text
//!   0      lookup local                                   (kernel built-in)
//!  48      ipproto udp sport 68 dport 67 lookup main      (DHCP renewals only)
//!  48      to <lan-range> lookup main suppress_prefixlength 0   (allow_lan only)
//!  49      fwmark 0x564f4944 lookup main                  (daemon's own sockets)
//!  50      not fwmark 0x564f4944 lookup 51820             (everything else -> vw0)
//!  51      not fwmark 0x564f4944 unreachable              (fail-closed fall-through)
//!  32766   lookup main
//! ```
//! Table 51820 contains only `default dev vw0` (IPv4 and IPv6).
//!
//! # Why this order and not the `wg-quick` one
//!
//! `wg-quick` installs `lookup main suppress_prefixlength 0` *before* the
//! `not fwmark` rule. `suppress_prefixlength 0` only hides routes whose prefix
//! length is 0 (the default route); every more specific route in `main` still
//! wins. Tunnelvision works exactly by having a rogue DHCP server push option
//! 121 classless routes (`0.0.0.0/1`, `128.0.0.0/1`, or any /8../32) into
//! `main` via the physical gateway. With the `wg-quick` ordering those routes
//! are consulted first by *unmarked* traffic and win, sending user traffic
//! around the tunnel.
//!
//! Here unmarked traffic never consults `main` at all: after the kernel's
//! `local` table (loopback / own addresses) the first rule it can match is
//! pref 50, which sends it to table 51820 whose only route is `default dev
//! vw0`. Injected routes in `main` therefore have no effect on it, whatever
//! their prefix length. If `vw0` is missing (boot lock, crash) the table is
//! empty and the lookup falls through to pref 51, which returns
//! `ENETUNREACH` instead of falling back to `main`.
//!
//! Marked traffic (the daemon's transport sockets carry `SO_MARK =
//! 0x564f4944`) matches pref 49 and uses `main` in full, including the
//! physical default route, so the encrypted tunnel can reach the entry node.
//!
//! `suppress_prefixlength 0` is used only where it is safe and useful: the
//! opt-in LAN rules at pref 48. A LAN-range destination uses the connected
//! route in `main`, but never `main`'s default route; with no connected route
//! it falls through to the tunnel instead of leaking to the ISP gateway. A
//! rogue route can at most redirect destinations inside the LAN ranges the
//! user explicitly allowed.
//!
//! The nftables output chain enforces the same policy independently of
//! routing (defence in depth).

use vw_core::consts::{FW_MARK, ROUTE_TABLE, RULE_PREF};

use crate::plan::LockdownPlan;

/// Opt-in LAN rules.
pub const LAN_RULE_PREF: u32 = RULE_PREF - 2;
/// Marked daemon sockets use `main`.
pub const MARK_RULE_PREF: u32 = RULE_PREF - 1;
/// Fail-closed guard when table 51820 has no route.
pub const GUARD_RULE_PREF: u32 = RULE_PREF + 1;

/// Every pref this module owns.
pub const OUR_PREFS: [u32; 4] = [LAN_RULE_PREF, MARK_RULE_PREF, RULE_PREF, GUARD_RULE_PREF];

/// Address family selector for `ip -4` / `ip -6`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Family {
    V4,
    V6,
}

impl Family {
    pub fn flag(self) -> &'static str {
        match self {
            Family::V4 => "-4",
            Family::V6 => "-6",
        }
    }
}

/// One `ip` invocation (arguments after the program name, family flag first).
pub type IpArgs = Vec<String>;

fn args(f: Family, rest: &[&str]) -> IpArgs {
    std::iter::once(f.flag())
        .chain(rest.iter().copied())
        .map(str::to_string)
        .collect()
}

fn mark() -> String {
    format!("{FW_MARK:#010x}")
}

/// Commands that install the rules and table 51820 for one family.
pub fn render_policy_routing(plan: &LockdownPlan, f: Family) -> Vec<IpArgs> {
    let mark = mark();
    let table = ROUTE_TABLE.to_string();
    let mut v = Vec::new();
    for lan in plan.effective_lan() {
        if lan.is_ipv4() != (f == Family::V4) {
            continue;
        }
        let pref = LAN_RULE_PREF.to_string();
        let to = lan.to_string();
        v.push(args(
            f,
            &[
                "rule",
                "add",
                "pref",
                &pref,
                "to",
                &to,
                "lookup",
                "main",
                "suppress_prefixlength",
                "0",
            ],
        ));
    }
    // DHCP lease renewals are unicast UDP from an ordinary socket; let them
    // use `main` so leases do not expire. Only DHCP ports are matched.
    let (dhcp_c, dhcp_s) = match f {
        Family::V4 => ("68", "67"),
        Family::V6 => ("546", "547"),
    };
    if f == Family::V4 || !plan.settings.strict_ipv6 {
        let pref = LAN_RULE_PREF.to_string();
        v.push(args(
            f,
            &[
                "rule", "add", "pref", &pref, "ipproto", "udp", "sport", dhcp_c, "dport", dhcp_s,
                "lookup", "main",
            ],
        ));
    }
    let p49 = MARK_RULE_PREF.to_string();
    let p50 = RULE_PREF.to_string();
    let p51 = GUARD_RULE_PREF.to_string();
    v.push(args(
        f,
        &[
            "rule", "add", "pref", &p49, "fwmark", &mark, "lookup", "main",
        ],
    ));
    v.push(args(
        f,
        &[
            "rule", "add", "pref", &p50, "not", "fwmark", &mark, "lookup", &table,
        ],
    ));
    v.push(args(
        f,
        &[
            "rule",
            "add",
            "pref",
            &p51,
            "not",
            "fwmark",
            &mark,
            "unreachable",
        ],
    ));
    if let Some(t) = &plan.tunnel {
        v.push(args(
            f,
            &[
                "route", "replace", "default", "dev", &t.name, "table", &table,
            ],
        ));
    }
    v
}

/// Count rules per pref in `ip rule show` output.
pub fn parse_rule_prefs(rule_show: &str) -> Vec<u32> {
    rule_show
        .lines()
        .filter_map(|l| l.trim().split_once(':'))
        .filter_map(|(p, _)| p.trim().parse::<u32>().ok())
        .collect()
}

/// Commands removing every rule we own (one `del` per occurrence, so
/// duplicates left by a crash are cleaned too) and flushing table 51820.
pub fn render_policy_teardown(rule_show: &str, f: Family) -> Vec<IpArgs> {
    let mut v: Vec<IpArgs> = parse_rule_prefs(rule_show)
        .into_iter()
        .filter(|p| OUR_PREFS.contains(p))
        .map(|p| {
            let p = p.to_string();
            args(f, &["rule", "del", "pref", &p])
        })
        .collect();
    let table = ROUTE_TABLE.to_string();
    v.push(args(f, &["route", "flush", "table", &table]));
    v
}

/// True when `ip rule show` contains the tunnel rule and the fail-closed guard.
pub fn parse_guard_active(rule_show: &str) -> bool {
    let mark = mark();
    let has = |pref: u32, needle: &str| {
        rule_show.lines().any(|l| {
            let l = l.trim();
            l.starts_with(&format!("{pref}:")) && l.contains(&mark) && l.contains(needle)
        })
    };
    has(RULE_PREF, &format!("lookup {ROUTE_TABLE}")) && has(GUARD_RULE_PREF, "unreachable")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plan::test_plans;

    fn joined(v: &[IpArgs]) -> Vec<String> {
        v.iter().map(|a| a.join(" ")).collect()
    }

    #[test]
    fn rules_and_table() {
        let r = joined(&render_policy_routing(&test_plans::full(), Family::V4));
        assert_eq!(
            r,
            [
                "-4 rule add pref 48 ipproto udp sport 68 dport 67 lookup main",
                "-4 rule add pref 49 fwmark 0x564f4944 lookup main",
                "-4 rule add pref 50 not fwmark 0x564f4944 lookup 51820",
                "-4 rule add pref 51 not fwmark 0x564f4944 unreachable",
                "-4 route replace default dev vw0 table 51820",
            ]
        );
        let r6 = joined(&render_policy_routing(&test_plans::full(), Family::V6));
        assert!(r6.contains(&"-6 route replace default dev vw0 table 51820".to_string()));
    }

    #[test]
    fn unmarked_traffic_never_reaches_main_before_tunnel() {
        // Any rule that consults `main` for unmarked traffic must not have a
        // lower pref than the tunnel rule, except LAN-scoped suppress rules.
        let mut p = test_plans::full();
        p.settings.allow_lan = true;
        let r = joined(&render_policy_routing(&p, Family::V4));
        for line in &r {
            if line.contains("lookup main")
                && !line.contains("fwmark 0x564f4944 lookup main")
                && !line.contains("ipproto udp sport 68 dport 67")
            {
                assert!(line.contains(" to "), "unscoped main lookup: {line}");
                assert!(line.contains("suppress_prefixlength 0"), "{line}");
            }
        }
        assert!(r.contains(
            &"-4 rule add pref 48 to 192.168.0.0/16 lookup main suppress_prefixlength 0"
                .to_string()
        ));
        // IPv6 LAN ranges are not used under strict_ipv6.
        let r6 = joined(&render_policy_routing(&p, Family::V6));
        assert!(!r6.iter().any(|l| l.contains("fe80")));
    }

    #[test]
    fn boot_lock_has_no_route_but_keeps_guard() {
        let r = joined(&render_policy_routing(&test_plans::boot(), Family::V4));
        assert!(!r.iter().any(|l| l.contains("route replace")));
        assert!(r.iter().any(|l| l.contains("unreachable")));
    }

    #[test]
    fn teardown_parses_rule_show() {
        let show = "0:\tfrom all lookup local\n\
                    49:\tfrom all fwmark 0x564f4944 lookup main\n\
                    50:\tnot from all fwmark 0x564f4944 lookup 51820\n\
                    50:\tnot from all fwmark 0x564f4944 lookup 51820\n\
                    51:\tnot from all fwmark 0x564f4944 unreachable\n\
                    32766:\tfrom all lookup main\n\
                    32767:\tfrom all lookup default\n";
        let t = joined(&render_policy_teardown(show, Family::V4));
        assert_eq!(
            t,
            [
                "-4 rule del pref 49",
                "-4 rule del pref 50",
                "-4 rule del pref 50",
                "-4 rule del pref 51",
                "-4 route flush table 51820",
            ]
        );
        assert!(parse_guard_active(show));
        assert!(!parse_guard_active(
            "0:\tfrom all lookup local\n32766:\tfrom all lookup main\n"
        ));
    }

    #[test]
    fn deterministic() {
        let a = render_policy_routing(&test_plans::full(), Family::V4);
        assert_eq!(a, render_policy_routing(&test_plans::full(), Family::V4));
    }
}
