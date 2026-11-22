//! Pure formatters for daemon data (status block, audit proofs, optimizer
//! decisions, node lists). Every function returns a `String` so it can be
//! unit-tested with a plain theme.

use vw_core::config::{NodeKind, NodeRole, Profile, TransportKind};
use vw_core::ipc::{AuditReport, FirewallMatrix, HopInfo, NodeSummary, StatusReport};
use vw_core::probe::OptimizerDecision;
use vw_core::state::DomeState;
use vw_tui::format;

use crate::output::{Cell, Style, Table, Theme};

pub fn state_name(s: DomeState) -> &'static str {
    match s {
        DomeState::Disarmed => "Disarmed",
        DomeState::ArmingBootLock => "ArmingBootLock",
        DomeState::Handshaking => "Handshaking",
        DomeState::CanaryAuditing => "CanaryAuditing",
        DomeState::TunnelActive => "TunnelActive",
        DomeState::KeyRotating => "KeyRotating",
        DomeState::FailsafeLockdown => "FailsafeLockdown",
        DomeState::Disarming => "Disarming",
    }
}

pub fn state_style(s: DomeState) -> Style {
    match s {
        DomeState::TunnelActive | DomeState::KeyRotating => Style::Ok,
        DomeState::FailsafeLockdown => Style::Bad,
        DomeState::Disarmed | DomeState::Disarming => Style::Warn,
        DomeState::ArmingBootLock | DomeState::Handshaking | DomeState::CanaryAuditing => {
            Style::Accent
        }
    }
}

/// One-line meaning of a state for humans.
pub fn state_meaning(s: DomeState) -> &'static str {
    match s {
        DomeState::Disarmed => "no lockdown: traffic is NOT protected by VoidWire",
        DomeState::ArmingBootLock => "firewall locked, engaging boot lock",
        DomeState::Handshaking => "firewall locked, handshaking with gateways",
        DomeState::CanaryAuditing => "firewall locked, running the canary leak audit",
        DomeState::TunnelActive => "protected: traffic flows only through the tunnel",
        DomeState::KeyRotating => "protected: rotating WireGuard and post-quantum keys",
        DomeState::FailsafeLockdown => "LOCKDOWN: all traffic is blocked",
        DomeState::Disarming => "releasing the lockdown",
    }
}

pub fn profile_label(p: Option<Profile>) -> String {
    p.map(|p| p.label().to_string())
        .unwrap_or_else(|| "-".into())
}

pub fn kind_name(k: NodeKind) -> &'static str {
    match k {
        NodeKind::Voidwire => "voidwire",
        NodeKind::Warp => "warp",
        NodeKind::Generic => "generic",
    }
}

pub fn role_name(r: NodeRole) -> &'static str {
    match r {
        NodeRole::Entry => "entry",
        NodeRole::Exit => "exit",
        NodeRole::Both => "entry+exit",
    }
}

pub fn transport_label(t: TransportKind) -> String {
    if t.is_stealth() {
        format!("{} (stealth)", t.label())
    } else {
        t.label().to_string()
    }
}

fn pq_badge(theme: &Theme, pq: bool) -> String {
    if pq {
        theme.ok("[PQ]")
    } else {
        theme.warn("[classical]")
    }
}

fn check(theme: &Theme, on: bool) -> String {
    if on {
        theme.ok("✓")
    } else {
        theme.bad("✗")
    }
}

fn ms(v: Option<f64>) -> String {
    v.map(|v| format!("{v:.1} ms"))
        .unwrap_or_else(|| "-".into())
}

/// `you → A [PQ] → B [classical] → internet`
pub fn route_line(theme: &Theme, hops: &[HopInfo]) -> String {
    if hops.is_empty() {
        return theme.dim("no route");
    }
    let mut parts = vec!["you".to_string()];
    for h in hops {
        let cc = h
            .country
            .as_deref()
            .map(|c| format!(" {c}"))
            .unwrap_or_default();
        parts.push(format!(
            "{}{cc} {}",
            theme.bold(&h.name),
            pq_badge(theme, h.post_quantum)
        ));
    }
    parts.push("internet".into());
    parts.join(" → ")
}

pub fn firewall_line(theme: &Theme, fw: &FirewallMatrix) -> String {
    let items = [
        ("IPv4", fw.ipv4_locked),
        ("IPv6", fw.ipv6_locked),
        ("DNS vault", fw.dns_vault),
        ("STUN", fw.stun_filter),
        ("CVE-2024-3661", fw.tunnelvision_guard),
        ("boot lock", fw.boot_lock),
    ];
    items
        .iter()
        .map(|(n, on)| format!("{} {n}", check(theme, *on)))
        .collect::<Vec<_>>()
        .join("  ")
}

/// The compact `voidwire status` block.
pub fn status_block(theme: &Theme, s: &StatusReport) -> String {
    let mut o = String::new();
    let key = |k: &str| theme.dim(&format!("  {k:<10}"));
    let state = theme.paint(state_style(s.state), state_name(s.state));
    o.push_str(&format!(
        "{} {state}  {}\n",
        theme.bold("VoidWire"),
        theme.dim(state_meaning(s.state))
    ));
    o.push_str(&format!("{}{}\n", key("profile"), profile_label(s.profile)));
    o.push_str(&format!("{}{}\n", key("route"), route_line(theme, &s.hops)));
    if !s.hops.is_empty() {
        let mut t = Table::new([
            "#",
            "ROLE",
            "NAME",
            "KIND",
            "CC",
            "TRANSPORT",
            "RTT",
            "CRYPTO",
        ])
        .indent(4);
        for (i, h) in s.hops.iter().enumerate() {
            t.row(vec![
                Cell::plain((i + 1).to_string()),
                Cell::plain(role_name(h.role)),
                Cell::new(h.name.clone(), Style::Bold),
                Cell::plain(kind_name(h.kind)),
                Cell::plain(h.country.clone().unwrap_or_else(|| "-".into())),
                Cell::plain(h.transport.label()),
                Cell::plain(ms(h.rtt_ms)),
                if h.post_quantum {
                    Cell::new("PQ hybrid", Style::Ok)
                } else {
                    Cell::new("classical", Style::Warn)
                },
            ]);
        }
        o.push_str(&t.render(theme));
    }
    o.push_str(&format!(
        "{}{}\n",
        key("transport"),
        s.transport
            .map(transport_label)
            .unwrap_or_else(|| "-".into())
    ));
    let suite = if s.crypto_suite.is_empty() {
        "-"
    } else {
        s.crypto_suite.as_str()
    };
    o.push_str(&format!("{}{suite}\n", key("crypto")));
    o.push_str(&format!(
        "{}{}   DAITA {}\n",
        key("mtu"),
        s.mtu.map(|m| m.to_string()).unwrap_or_else(|| "-".into()),
        if s.daita {
            theme.ok("on")
        } else {
            theme.dim("off")
        }
    ));
    let rotation = s
        .last_rotation_secs_ago
        .map(|r| format!("   last key rotation {r}s ago"))
        .unwrap_or_default();
    o.push_str(&format!(
        "{}{}{rotation}\n",
        key("uptime"),
        format::uptime(s.uptime_secs)
    ));
    let t = &s.telemetry;
    o.push_str(&format!(
        "{}↑ {} ({} pkts)   ↓ {} ({} pkts)   chaff {}\n",
        key("traffic"),
        format::bytes(t.tx_bytes),
        format::count(t.tx_packets),
        format::bytes(t.rx_bytes),
        format::count(t.rx_packets),
        format::count(t.chaff_sent),
    ));
    o.push_str(&format!(
        "{}STUN {}  IPv6 {}  DNS intercepted {}  DoT {}  pre-canary {}  shield {}  PQ rotations {}\n",
        key("blocked"),
        format::count(t.stun_blocked),
        format::count(t.ipv6_dropped),
        format::count(t.dns_intercepted),
        format::count(t.dot_blocked),
        format::count(t.pre_canary_dropped),
        format::count(t.shield.total()),
        format::count(t.pq_rotations),
    ));
    o.push_str(&format!(
        "{}{}  {}\n",
        key("firewall"),
        theme.dim(&format!("[{}]", s.firewall.backend)),
        firewall_line(theme, &s.firewall)
    ));
    o.push_str(&format!(
        "{}voidwired {} on {}\n",
        key("daemon"),
        s.daemon_version,
        s.platform
    ));
    o
}

/// The `status --audit` proof table plus a verdict line.
pub fn audit_table(theme: &Theme, a: &AuditReport) -> String {
    let mut t = Table::new(["CHECK", "RESULT", "DETAIL", "PROOF (BLAKE3)"]);
    for c in &a.checks {
        t.row(vec![
            Cell::plain(c.name.clone()),
            if c.passed {
                Cell::new("PASS", Style::Ok)
            } else {
                Cell::new("FAIL", Style::Bad)
            },
            Cell::plain(c.detail.clone()),
            Cell::new(format::short_proof(&c.proof), Style::Dim),
        ]);
    }
    let failed = a.checks.iter().filter(|c| !c.passed).count();
    let mut o = format!(
        "{} {}\n",
        theme.bold("Leak audit"),
        theme.dim(&format!("at {}", format::utc_clock(a.unix_time)))
    );
    if t.is_empty() {
        o.push_str(&theme.warn("  the daemon reported no checks\n"));
    } else {
        o.push_str(&t.render(theme));
    }
    if audit_passed(a) {
        o.push_str(&theme.ok(&format!("all {} checks passed", a.checks.len())));
    } else if failed == 0 {
        o.push_str(&theme.bad("audit FAILED (the daemon marked the report as failed)"));
    } else {
        o.push_str(&theme.bad(&format!("{failed} of {} checks FAILED", a.checks.len())));
    }
    o.push('\n');
    o.push_str(&theme.dim("full proof digests: voidwire status --audit --json"));
    o.push('\n');
    o
}

/// An audit passes only if the daemon says so, every check passed and
/// at least one check ran.
pub fn audit_passed(a: &AuditReport) -> bool {
    a.passed && !a.checks.is_empty() && a.checks.iter().all(|c| c.passed)
}

/// The optimizer's decision: hops, transport, MTU and why.
pub fn decision_block(theme: &Theme, d: &OptimizerDecision) -> String {
    let mut o = String::new();
    let key = |k: &str| theme.dim(&format!("  {k:<10}"));
    o.push_str(&format!("{}\n", theme.bold("Optimizer decision")));
    let hops = if d.hops.is_empty() {
        "-".to_string()
    } else {
        d.hops.join(" → ")
    };
    o.push_str(&format!("{}{hops}\n", key("hops")));
    o.push_str(&format!(
        "{}{}\n",
        key("transport"),
        transport_label(d.transport)
    ));
    o.push_str(&format!(
        "{}{}   MSS {}   DAITA {}\n",
        key("mtu"),
        d.mtu,
        d.mss_v4,
        if d.daita { "on" } else { "off" }
    ));
    let mut net = Vec::new();
    if d.verdict.udp_hostile {
        net.push("UDP hostile");
    }
    if d.verdict.quic_blocked {
        net.push("QUIC blocked");
    }
    if d.verdict.wg_signature_filtered {
        net.push("WireGuard signature filtered");
    }
    let net = if net.is_empty() {
        theme.ok("no interference detected")
    } else {
        theme.warn(&net.join(", "))
    };
    o.push_str(&format!("{}{net}\n", key("network")));
    if !d.reason.is_empty() {
        o.push_str(&format!("{}{}\n", key("why"), d.reason));
    }
    if !d.candidates.is_empty() {
        let mut c = d.candidates.clone();
        c.sort_by(|a, b| b.score.total_cmp(&a.score));
        let mut t = Table::new([
            "CANDIDATE",
            "TRANSPORT",
            "RTT",
            "JITTER",
            "LOSS",
            "MBIT/S",
            "PQ",
            "SCORE",
        ])
        .indent(4);
        for p in c.iter().take(8) {
            let style = if !p.reachable {
                Style::Dim
            } else {
                Style::Plain
            };
            t.row(vec![
                Cell::new(p.node_name.clone(), style),
                Cell::new(p.transport.label(), style),
                Cell::new(ms(p.rtt_ms), style),
                Cell::new(ms(p.jitter_ms), style),
                Cell::new(format!("{:.1}%", p.loss * 100.0), style),
                Cell::new(
                    p.throughput_mbps
                        .map(|v| format!("{v:.1}"))
                        .unwrap_or_else(|| "-".into()),
                    style,
                ),
                Cell::new(if p.post_quantum { "yes" } else { "no" }, style),
                Cell::new(
                    if p.reachable {
                        format!("{:.2}", p.score)
                    } else {
                        "unreachable".into()
                    },
                    style,
                ),
            ]);
        }
        o.push_str(&t.render(theme));
    }
    o
}

pub fn nodes_table(theme: &Theme, nodes: &[NodeSummary]) -> String {
    if nodes.is_empty() {
        return format!(
            "{}\n",
            theme.dim(
                "no nodes imported (try `voidwire warp register` or `voidwire nodes import <uri>`)"
            )
        );
    }
    let mut t = Table::new(["NAME", "KIND", "ROLE", "CC", "TRANSPORTS", "CRYPTO"]);
    for n in nodes {
        t.row(vec![
            Cell::new(n.name.clone(), Style::Bold),
            Cell::plain(kind_name(n.kind)),
            Cell::plain(role_name(n.role)),
            Cell::plain(n.country.clone().unwrap_or_else(|| "-".into())),
            Cell::plain(
                n.transports
                    .iter()
                    .map(|t| t.label())
                    .collect::<Vec<_>>()
                    .join(", "),
            ),
            if n.post_quantum {
                Cell::new("PQ hybrid", Style::Ok)
            } else {
                Cell::new("classical", Style::Warn)
            },
        ]);
    }
    t.render(theme)
}

/// One state transition line printed by `voidwire up`.
pub fn transition_line(theme: &Theme, elapsed_ms: u128, from: DomeState, to: DomeState) -> String {
    format!(
        "{} {} → {}  {}",
        theme.dim(&format!("[{:>6.1}s]", elapsed_ms as f64 / 1000.0)),
        theme.paint(state_style(from), state_name(from)),
        theme.paint(state_style(to), state_name(to)),
        theme.dim(state_meaning(to))
    )
}

/// The exit hop of a route (last hop with an exit role, else the last hop).
pub fn exit_hop(hops: &[HopInfo]) -> Option<&HopInfo> {
    hops.iter()
        .rev()
        .find(|h| matches!(h.role, NodeRole::Exit | NodeRole::Both))
        .or_else(|| hops.last())
}
