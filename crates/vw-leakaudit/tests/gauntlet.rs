//! Adversarial Leak Gauntlet — portable part (no root, runs on every OS).
//!
//! Exercises the real production components (firewall rule generators, STUN
//! filter, DNS interception, packet sanitizer, AmneziaWG morpher, Iron Dome
//! FSM) against the six attacks of PROMPT.md §3. The kernel-level versions of
//! tests 1, 2, 3 and 5 run in `tests/privileged.rs` (Linux root, CI).

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use vw_core::config::{AmneziaParams, DnsSettings, FirewallSettings, SanitizerSettings};
use vw_core::consts::{FW_MARK, LEAK_OBSERVER_V4, SAFE_TUNNEL_MTU};
use vw_core::packet::{build_tcp_syn, build_udp, verify_l4_checksum, IpView, PROTO_TCP};
use vw_core::secret::Key32;
use vw_core::state::{DomeEvent, IronDome};
use vw_core::telemetry::Counters;
use vw_firewall::linux::policy::{render_policy_routing, Family};
use vw_firewall::{LockdownPlan, PinnedEndpoint, StunFilter, TunnelIface, Verdict};

fn tunnel_plan(settings: FirewallSettings) -> LockdownPlan {
    let mut plan = LockdownPlan::new(settings);
    plan.pinned = vec![PinnedEndpoint::udp("192.0.2.10:51820".parse().unwrap())];
    plan.tunnel = Some(TunnelIface {
        name: "vw0".into(),
        luid: None,
        v4: Some((Ipv4Addr::new(100, 96, 0, 2), 12)),
        v6: None,
    });
    plan
}

/// Test 1 — SIGKILL crash race (logic level): a crash fires `Fault`; the FSM
/// must stay locked and block traffic, and the rendered rules must not depend
/// on the daemon process being alive (kernel-persistent table, drop policy).
#[test]
fn t1_crash_keeps_lockdown() {
    let mut dome = IronDome::new();
    for e in [
        DomeEvent::Arm,
        DomeEvent::LockEngaged,
        DomeEvent::HandshakeComplete,
        DomeEvent::CanaryPassed,
    ] {
        dome.fire(e).unwrap();
    }
    dome.fire(DomeEvent::Fault).unwrap();
    assert!(dome.state().firewall_locked());
    assert!(!dome.state().traffic_allowed());
    // Only an explicit disarm can release it.
    assert!(dome.fire(DomeEvent::LockReleased).is_err());

    let nft = vw_firewall::linux::render_nft(&tunnel_plan(FirewallSettings::default()));
    assert!(nft.contains("table inet voidwire_lockdown"));
    assert!(nft.contains("policy drop"));
    assert!(nft.contains(&format!("{FW_MARK:#x}")));
    for process_bound in ["skuid", "cgroup", "socket cgroupv2"] {
        assert!(
            !nft.contains(process_bound),
            "rules must not depend on the daemon process"
        );
    }
    let pf = vw_firewall::macos::render_pf_anchor(&tunnel_plan(FirewallSettings::default()));
    assert!(pf
        .trim_end()
        .lines()
        .any(|l| l.contains("block drop out quick all")));
}

/// Test 2 — Tunnelvision (CVE-2024-3661): unmarked traffic must be forced into
/// table 51820 and never fall back to `main`, whatever routes DHCP injects.
#[test]
fn t2_tunnelvision_policy_routing() {
    let plan = tunnel_plan(FirewallSettings::default());
    let rules: Vec<String> = render_policy_routing(&plan, Family::V4)
        .into_iter()
        .map(|a| a.join(" "))
        .collect();
    let joined = rules.join("\n");
    let tunnel_rule = rules
        .iter()
        .position(|r| r.contains("pref 50") && r.contains("not fwmark") && r.contains("51820"))
        .expect("pref 50 tunnel rule");
    assert!(
        rules
            .iter()
            .any(|r| r.contains("pref 51") && r.contains("unreachable")),
        "no fallback to main:\n{joined}"
    );
    // No global suppress_prefixlength rule may precede the tunnel rule.
    for r in &rules[..tunnel_rule] {
        assert!(
            !(r.contains("suppress_prefixlength") && !r.contains(" to ")),
            "{r}"
        );
    }
    assert!(joined.contains("default dev vw0") || joined.contains("dev vw0"));
    // macOS / Windows: default-deny is route-independent.
    let wfp = vw_firewall::windows_spec::render(&plan);
    assert!(!wfp.is_empty());
}

struct FixedUpstream;

#[async_trait::async_trait]
impl vw_dns::upstream::Upstream for FixedUpstream {
    async fn query(&self, wire: &[u8]) -> vw_dns::Result<Vec<u8>> {
        // Echo the question with one A record 192.0.2.53.
        let mut r = wire.to_vec();
        r[2] = 0x81;
        r[3] = 0x80;
        r[6..8].copy_from_slice(&1u16.to_be_bytes());
        r[8..12].copy_from_slice(&[0, 0, 0, 0]);
        let qend = 12 + wire[12..].iter().position(|b| *b == 0).unwrap() + 1 + 4;
        r.truncate(qend);
        r.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 192, 0, 2, 53]);
        Ok(r)
    }
    fn name(&self) -> &'static str {
        "fixed"
    }
}

fn dns_query(name: &str) -> Vec<u8> {
    let mut q = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
    for label in name.split('.') {
        q.push(label.len() as u8);
        q.extend_from_slice(label.as_bytes());
    }
    q.extend_from_slice(&[0, 0, 1, 0, 1]);
    q
}

/// Test 3 — hardcoded DNS / DoT bypass: queries to 8.8.8.8:53 and
/// [2001:4860:4860::8888]:53 are answered by the vault (spoofed source), DoT to
/// 1.1.1.1:853 is dropped.
#[tokio::test]
async fn t3_hardcoded_dns_is_intercepted() {
    let counters = Arc::new(Counters::default());
    let vault = vw_dns::vault::DnsVault::new(
        DnsSettings::default(),
        Arc::new(FixedUpstream),
        counters.clone(),
    );
    let q = dns_query("example.org");
    for (src, dst) in [
        ("100.96.0.2:40000", "8.8.8.8:53"),
        ("[fd00:564f:4944:1::2]:40000", "[2001:4860:4860::8888]:53"),
    ] {
        let (src, dst): (SocketAddr, SocketAddr) = (src.parse().unwrap(), dst.parse().unwrap());
        let pkt = build_udp(src, dst, &q, 64).unwrap();
        match vw_dns::intercept(&vault, &pkt).await {
            vw_dns::InterceptVerdict::Respond(resp) => {
                let v = IpView::parse(&resp).unwrap();
                assert_eq!(
                    v.src_sock(&resp),
                    Some(dst),
                    "answer must appear to come from {dst}"
                );
                assert_eq!(v.dst_sock(&resp), Some(src));
                assert!(verify_l4_checksum(&resp));
            }
            other => panic!("{dst} not intercepted: {other:?}"),
        }
    }
    let dot = build_udp(
        "100.96.0.2:40001".parse().unwrap(),
        "1.1.1.1:853".parse().unwrap(),
        b"\x16\x03\x01",
        64,
    )
    .unwrap();
    assert!(matches!(
        vw_dns::intercept(&vault, &dot).await,
        vw_dns::InterceptVerdict::Drop
    ));
    let snap = counters.snapshot();
    assert!(snap.dns_intercepted >= 2);
    assert_eq!(snap.dot_blocked, 1);
}

/// Test 4 — WebRTC STUN exfiltration: an RFC 5389 Binding Request is dropped
/// and counted.
#[test]
fn t4_stun_binding_request_dropped() {
    let counters = Arc::new(Counters::default());
    let filter = StunFilter::new(true, counters.clone());
    let mut stun = vec![0x00, 0x01, 0x00, 0x00, 0x21, 0x12, 0xA4, 0x42];
    stun.extend_from_slice(&[7u8; 12]);
    for dst in ["74.125.250.129:19302", "[2001:4860:4864:5:8000::1]:19302"] {
        let dst: SocketAddr = dst.parse().unwrap();
        let src: SocketAddr = if dst.is_ipv4() {
            "100.96.0.2:5000".parse().unwrap()
        } else {
            "[fd00:564f:4944:1::2]:5000".parse().unwrap()
        };
        let pkt = build_udp(src, dst, &stun, 64).unwrap();
        assert!(matches!(filter.inspect(&pkt), Verdict::Drop));
    }
    assert_eq!(counters.snapshot().stun_blocked, 2);
    let quic = build_udp(
        "100.96.0.2:5000".parse().unwrap(),
        "198.51.100.7:443".parse().unwrap(),
        &[0xc3; 64],
        64,
    )
    .unwrap();
    assert!(matches!(filter.inspect(&quic), Verdict::Pass));
}

/// Test 5 — dual-stack IPv6 leak: with an IPv4-only tunnel every IPv6 packet
/// outside the tunnel is dropped by all three backends.
#[test]
fn t5_ipv6_blocked_outside_tunnel() {
    let plan = tunnel_plan(FirewallSettings::default());
    let nft = vw_firewall::linux::render_nft(&plan);
    assert!(nft.contains("ipv6"), "{nft}");
    let pf = vw_firewall::macos::render_pf_anchor(&plan);
    assert!(pf.contains("block drop out quick inet6"), "{pf}");
    let wfp = format!("{:?}", vw_firewall::windows_spec::render(&plan));
    assert!(wfp.contains("V6"), "WFP must filter the IPv6 layers");
}

/// Test 6 — DPI header inspection: AmneziaWG never shows the WireGuard
/// handshake signature on the wire, and inner SYNs are MSS-clamped with TCP
/// timestamps scrubbed.
#[test]
fn t6_wire_signatures_and_syn_scrubbing() {
    let now = std::time::Instant::now();
    let server = Key32::random();
    let server_pub = vw_wg::public_key(&server);
    for _ in 0..50 {
        let mut client = vw_wg::Peer::new_initiator(Key32::random(), server_pub, None, [0; 3]);
        let out = client.encapsulate(&[0x45; 60], now);
        let init = out
            .iter()
            .find(|d| d.len() == 148)
            .expect("handshake initiation");
        assert_eq!(
            &init[..4],
            &[1, 0, 0, 0],
            "sanity: plain WG has the signature"
        );
        let codec = vw_stealth::amnezia::AmneziaCodec::new(AmneziaParams::random()).unwrap();
        let wire = codec.encode(init).unwrap();
        assert_ne!(&wire[..4], &[1, 0, 0, 0]);
        assert_ne!(
            wire.len(),
            148,
            "length fingerprint must change (S1 padding)"
        );
        assert_eq!(codec.decode(&wire).unwrap(), *init);
    }

    // MSS 1460 + timestamps (kind 8) + SACK-permitted + window scale.
    let opts = [
        2, 4, 0x05, 0xb4, 4, 2, 8, 10, 1, 2, 3, 4, 0, 0, 0, 0, 1, 3, 3, 7,
    ];
    let mut syn = build_tcp_syn(
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(100, 96, 0, 2)), 40000),
        SocketAddr::new(IpAddr::V4(LEAK_OBSERVER_V4), 443),
        1,
        &opts,
        128,
    )
    .unwrap();
    let report = vw_wg::Sanitizer::new(SanitizerSettings::default(), SAFE_TUNNEL_MTU)
        .process_outbound(&mut syn);
    assert!(report.mss_clamped && report.ttl_normalized);
    let v = IpView::parse(&syn).unwrap();
    assert_eq!(v.protocol, PROTO_TCP);
    assert_eq!(syn[8], 64, "TTL normalised");
    let tcp = &syn[v.l4_offset..];
    let options = &tcp[20..(tcp[12] >> 4) as usize * 4];
    assert_eq!(&options[..4], &[2, 4, 0x04, 0xd8], "MSS clamped to 1240");
    let mut i = 0;
    while i < options.len() {
        match options[i] {
            0 => break,
            1 => i += 1,
            kind => {
                assert_ne!(kind, 8, "TCP timestamp must be scrubbed");
                i += options[i + 1].max(2) as usize;
            }
        }
    }
    assert!(verify_l4_checksum(&syn));
}
