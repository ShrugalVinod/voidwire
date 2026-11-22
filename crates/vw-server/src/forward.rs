//! Kernel forwarding for admitted clients: node TUN, IP forwarding and the
//! ephemeral nftables table `inet voidwire_node` (NAT44/NAT66, no
//! client-to-client, MSS clamping, no access to the node or private ranges).
//!
//! [`render_ruleset`] and [`parse_route_get`] are pure and tested everywhere;
//! applying them is Linux-only.

use std::fmt::Write as _;

use vw_core::consts::{CLIENT_POOL_V4, CLIENT_POOL_V6, TUN_NAME};

/// nftables table name.
pub const NFT_TABLE: &str = "voidwire_node";

/// Inputs of [`render_ruleset`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NatPlan {
    /// TUN interface carrying client traffic.
    pub tun: String,
    /// Egress (Internet-facing) interface.
    pub egress: String,
    /// Masquerade IPv6 too (node has global IPv6).
    pub ipv6: bool,
}

/// True for interface names that are safe to splice into a ruleset.
pub fn valid_ifname(s: &str) -> bool {
    !s.is_empty()
        && s.len() < 16
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'@'))
}

/// Render the complete `nft -f -` input. It first creates and deletes the
/// table so that applying it is an atomic replace of any previous instance.
pub fn render_ruleset(p: &NatPlan) -> String {
    let (v4, v4p) = CLIENT_POOL_V4;
    let (v6, v6p) = CLIENT_POOL_V6;
    let tun = &p.tun;
    let eg = &p.egress;
    let mut s = String::new();
    let _ = writeln!(s, "table inet {NFT_TABLE}");
    let _ = writeln!(s, "delete table inet {NFT_TABLE}");
    let _ = writeln!(s, "table inet {NFT_TABLE} {{");

    // Clients may not reach the node itself (only the userspace gateway).
    let _ = writeln!(s, "  chain input {{");
    let _ = writeln!(
        s,
        "    type filter hook input priority filter; policy accept;"
    );
    let _ = writeln!(s, "    iifname \"{tun}\" drop");
    let _ = writeln!(s, "  }}");

    let _ = writeln!(s, "  chain forward {{");
    let _ = writeln!(
        s,
        "    type filter hook forward priority filter; policy accept;"
    );
    let _ = writeln!(s, "    iifname \"{tun}\" oifname \"{tun}\" drop");
    let _ = writeln!(s, "    iifname \"{tun}\" ip saddr != {v4}/{v4p} drop");
    let _ = writeln!(s, "    iifname \"{tun}\" ip6 saddr != {v6}/{v6p} drop");
    let _ = writeln!(s, "    ip saddr {v4}/{v4p} ip daddr {v4}/{v4p} drop");
    let _ = writeln!(s, "    ip6 saddr {v6}/{v6p} ip6 daddr {v6}/{v6p} drop");
    let _ = writeln!(
        s,
        "    iifname \"{tun}\" ip daddr {{ 0.0.0.0/8, 10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.168.0.0/16, 224.0.0.0/3 }} drop"
    );
    let _ = writeln!(
        s,
        "    iifname \"{tun}\" ip6 daddr {{ ::/127, fc00::/7, fe80::/10, ff00::/8 }} drop"
    );
    let _ = writeln!(
        s,
        "    iifname \"{tun}\" tcp flags syn tcp option maxseg size set rt mtu"
    );
    let _ = writeln!(
        s,
        "    oifname \"{tun}\" tcp flags syn tcp option maxseg size set rt mtu"
    );
    let _ = writeln!(s, "    iifname \"{tun}\" oifname \"{eg}\" accept");
    let _ = writeln!(
        s,
        "    iifname \"{eg}\" oifname \"{tun}\" ct state established,related accept"
    );
    let _ = writeln!(s, "    iifname \"{tun}\" drop");
    let _ = writeln!(s, "    oifname \"{tun}\" drop");
    let _ = writeln!(s, "  }}");

    let _ = writeln!(s, "  chain postrouting {{");
    let _ = writeln!(
        s,
        "    type nat hook postrouting priority srcnat; policy accept;"
    );
    let _ = writeln!(s, "    oifname \"{eg}\" ip saddr {v4}/{v4p} masquerade");
    if p.ipv6 {
        let _ = writeln!(s, "    oifname \"{eg}\" ip6 saddr {v6}/{v6p} masquerade");
    }
    let _ = writeln!(s, "  }}");
    let _ = writeln!(s, "}}");
    s
}

/// Parse the output of `ip route get <addr>`: `(dev, src)`.
pub fn parse_route_get(out: &str) -> Option<(String, Option<String>)> {
    let toks: Vec<&str> = out.split_whitespace().collect();
    let after = |k: &str| {
        toks.windows(2)
            .find(|w| w[0] == k)
            .map(|w| w[1].to_string())
    };
    let dev = after("dev")?;
    Some((dev, after("src")))
}

/// The default TUN name used by the node.
pub fn tun_name() -> String {
    TUN_NAME.to_string()
}

#[cfg(target_os = "linux")]
pub use linux::*;

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use std::io::Write;
    use std::process::{Command, Stdio};
    use vw_core::{Result, VwError};

    /// Egress interface via `ip route get` (IPv4 or IPv6 probe target).
    pub fn detect_egress(v6: bool) -> Result<String> {
        let mut c = Command::new("ip");
        if v6 {
            c.args(["-6", "route", "get", "2606:4700:4700::1111"]);
        } else {
            c.args(["route", "get", "1.1.1.1"]);
        }
        let out = c
            .output()
            .map_err(|e| VwError::Firewall(format!("running ip: {e}")))?;
        if !out.status.success() {
            return Err(VwError::Firewall("ip route get failed".into()));
        }
        parse_route_get(&String::from_utf8_lossy(&out.stdout))
            .map(|(d, _)| d)
            .ok_or_else(|| VwError::Firewall("cannot determine egress interface".into()))
    }

    fn nft(input: &str) -> Result<()> {
        let mut child = Command::new("nft")
            .args(["-f", "-"])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| VwError::Firewall(format!("running nft: {e}")))?;
        child
            .stdin
            .take()
            .ok_or_else(|| VwError::Firewall("nft stdin".into()))?
            .write_all(input.as_bytes())?;
        let out = child.wait_with_output()?;
        if !out.status.success() {
            return Err(VwError::Firewall(format!(
                "nft failed: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            )));
        }
        Ok(())
    }

    fn write_sysctl(path: &str, value: &str) -> Result<Option<String>> {
        let old = std::fs::read_to_string(path)
            .ok()
            .map(|s| s.trim().to_string());
        std::fs::write(path, value)
            .map_err(|e| VwError::Firewall(format!("cannot set {path}: {e}")))?;
        Ok(old)
    }

    /// Installed kernel state; [`Forwarding::remove`] undoes it.
    #[derive(Debug)]
    pub struct Forwarding {
        restore: Vec<(String, String)>,
        removed: bool,
    }

    impl Forwarding {
        /// Enable IP forwarding and install the nftables table.
        pub fn install(plan: &NatPlan) -> Result<Self> {
            if !valid_ifname(&plan.tun) || !valid_ifname(&plan.egress) {
                return Err(VwError::Config("invalid interface name".into()));
            }
            let mut restore = Vec::new();
            if plan.ipv6 {
                // Forwarding disables RA acceptance unless accept_ra = 2.
                let ra = format!("/proc/sys/net/ipv6/conf/{}/accept_ra", plan.egress);
                if let Some(old) = write_sysctl(&ra, "2")? {
                    restore.push((ra, old));
                }
                let p = "/proc/sys/net/ipv6/conf/all/forwarding";
                if let Some(old) = write_sysctl(p, "1")? {
                    restore.push((p.to_string(), old));
                }
            }
            let p = "/proc/sys/net/ipv4/ip_forward";
            if let Some(old) = write_sysctl(p, "1")? {
                restore.push((p.to_string(), old));
            }
            nft(&render_ruleset(plan))?;
            Ok(Self {
                restore,
                removed: false,
            })
        }

        /// Remove the table and restore sysctls.
        pub fn remove(&mut self) -> Result<()> {
            if self.removed {
                return Ok(());
            }
            self.removed = true;
            let r = nft(&format!(
                "table inet {NFT_TABLE}\ndelete table inet {NFT_TABLE}\n"
            ));
            for (path, old) in self.restore.drain(..).rev() {
                let _ = std::fs::write(&path, old);
            }
            r
        }
    }

    impl Drop for Forwarding {
        fn drop(&mut self) {
            let _ = self.remove();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ruleset_rendering() {
        let r = render_ruleset(&NatPlan {
            tun: "vw0".into(),
            egress: "eth0".into(),
            ipv6: true,
        });
        let lines: Vec<&str> = r.lines().collect();
        assert_eq!(lines[0], "table inet voidwire_node");
        assert_eq!(lines[1], "delete table inet voidwire_node");
        assert!(r.contains("oifname \"eth0\" ip saddr 100.96.0.0/12 masquerade"));
        assert!(r.contains("oifname \"eth0\" ip6 saddr fd00:564f:4944:1::/64 masquerade"));
        assert!(r.contains("iifname \"vw0\" oifname \"vw0\" drop"));
        assert!(r.contains("ip saddr 100.96.0.0/12 ip daddr 100.96.0.0/12 drop"));
        assert!(r.contains("tcp flags syn tcp option maxseg size set rt mtu"));
        assert!(r.contains("type nat hook postrouting priority srcnat; policy accept;"));
        assert!(r.contains("169.254.0.0/16"), "cloud metadata blocked");
        assert!(r.contains("chain input"));
        // The client-to-client drop precedes the accept rule.
        let drop = r.find("\n    oifname \"vw0\" drop").unwrap();
        let acc = r.find("iifname \"vw0\" oifname \"eth0\" accept").unwrap();
        assert!(r.find("iifname \"vw0\" oifname \"vw0\" drop").unwrap() < acc);
        assert!(acc < drop);
        assert_eq!(r.matches('{').count(), r.matches('}').count());

        let v4only = render_ruleset(&NatPlan {
            tun: "vw0".into(),
            egress: "ens3".into(),
            ipv6: false,
        });
        assert!(!v4only.contains("ip6 saddr fd00:564f:4944:1::/64 masquerade"));
        assert!(v4only.contains("oifname \"ens3\" ip saddr 100.96.0.0/12 masquerade"));
    }

    #[test]
    fn route_get_parsing_and_ifnames() {
        let out = "1.1.1.1 via 10.0.0.1 dev ens3 src 10.0.0.42 uid 0 \n    cache \n";
        assert_eq!(
            parse_route_get(out),
            Some(("ens3".into(), Some("10.0.0.42".into())))
        );
        let v6 = "2606:4700:4700::1111 from :: via fe80::1 dev eth0 proto ra src 2001:db8::5 metric 100 pref medium";
        assert_eq!(parse_route_get(v6).unwrap().0, "eth0");
        assert_eq!(parse_route_get("unreachable"), None);
        assert!(valid_ifname("eth0"));
        assert!(valid_ifname("enp0s31f6"));
        assert!(!valid_ifname("eth0\"; flush ruleset"));
        assert!(!valid_ifname(""));
        assert!(!valid_ifname("averyveryverylongname"));
    }
}
