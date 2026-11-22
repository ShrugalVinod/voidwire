//! Shared fixtures for vw-cli tests (sample daemon data and a buffered sink).
#![allow(dead_code)]

use std::io::Write;
use std::sync::{Arc, Mutex};

use vw_cli::{Out, Theme};
use vw_core::config::{NodeKind, NodeRole, Profile, TransportKind};
use vw_core::ipc::{AuditCheck, AuditReport, FirewallMatrix, HopInfo, NodeSummary, StatusReport};
use vw_core::probe::{NetworkVerdict, OptimizerDecision, ProbeResult};
use vw_core::state::DomeState;
use vw_core::telemetry::TelemetrySnapshot;

#[derive(Clone, Default)]
pub struct Buf(pub Arc<Mutex<Vec<u8>>>);

impl Write for Buf {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Buf {
    pub fn text(&self) -> String {
        String::from_utf8(self.0.lock().unwrap().clone()).unwrap()
    }
}

/// An `Out` writing to two buffers (stdout, stderr), no colors.
pub fn sink(json: bool) -> (Out, Buf, Buf) {
    let o = Buf::default();
    let e = Buf::default();
    (
        Out::new(Box::new(o.clone()), Box::new(e.clone()), Theme::PLAIN, json),
        o,
        e,
    )
}

pub fn hops() -> Vec<HopInfo> {
    vec![
        HopInfo {
            name: "Cloudflare WARP".into(),
            kind: NodeKind::Warp,
            role: NodeRole::Entry,
            country: None,
            transport: TransportKind::NativeUdp,
            post_quantum: false,
            rtt_ms: Some(12.5),
            coords: None,
        },
        HopInfo {
            name: "oracle-fra".into(),
            kind: NodeKind::Voidwire,
            role: NodeRole::Exit,
            country: Some("DE".into()),
            transport: TransportKind::AmneziaWg,
            post_quantum: true,
            rtt_ms: Some(31.0),
            coords: Some((50.1, 8.7)),
        },
    ]
}

pub fn decision() -> OptimizerDecision {
    OptimizerDecision {
        hops: vec!["Cloudflare WARP".into(), "oracle-fra".into()],
        transport: TransportKind::AmneziaWg,
        mtu: 1280,
        mss_v4: 1240,
        daita: true,
        verdict: NetworkVerdict {
            udp_hostile: false,
            quic_blocked: true,
            wg_signature_filtered: true,
        },
        candidates: vec![
            ProbeResult {
                node_name: "oracle-fra".into(),
                transport: TransportKind::AmneziaWg,
                reachable: true,
                handshake_ms: Some(40.0),
                rtt_ms: Some(31.0),
                jitter_ms: Some(2.0),
                loss: 0.0,
                throughput_mbps: Some(220.0),
                post_quantum: true,
                score: 85.4,
            },
            ProbeResult {
                node_name: "gcp-usw".into(),
                transport: TransportKind::NativeUdp,
                reachable: false,
                handshake_ms: None,
                rtt_ms: None,
                jitter_ms: None,
                loss: 1.0,
                throughput_mbps: None,
                post_quantum: true,
                score: 0.0,
            },
        ],
        reason: "plain WireGuard is filtered on this network; AmneziaWG is fastest".into(),
    }
}

pub fn status(state: DomeState) -> StatusReport {
    let active = state.traffic_allowed();
    StatusReport {
        state,
        profile: active.then_some(Profile::Multihop),
        hops: if active { hops() } else { Vec::new() },
        transport: active.then_some(TransportKind::AmneziaWg),
        crypto_suite: if active {
            "X25519+ML-KEM-1024 / ChaCha20-Poly1305".into()
        } else {
            String::new()
        },
        uptime_secs: if active { 3725 } else { 0 },
        mtu: active.then_some(1280),
        daita: active,
        firewall: FirewallMatrix {
            ipv4_locked: state.firewall_locked(),
            ipv6_locked: state.firewall_locked(),
            dns_vault: active,
            stun_filter: true,
            tunnelvision_guard: state.firewall_locked(),
            boot_lock: false,
            backend: "pf".into(),
        },
        last_rotation_secs_ago: active.then_some(42),
        telemetry: TelemetrySnapshot {
            tx_bytes: 1_572_864,
            rx_bytes: 10_485_760,
            tx_packets: 1234,
            rx_packets: 5678,
            stun_blocked: 3,
            ..Default::default()
        },
        decision: active.then(decision),
        platform: "macos".into(),
        daemon_version: "0.1.0".into(),
    }
}

pub fn audit(pass: bool) -> AuditReport {
    AuditReport {
        passed: pass,
        checks: vec![
            AuditCheck {
                name: "dns-leak".into(),
                passed: true,
                detail: "all queries answered by the vault".into(),
                proof: "a".repeat(64),
            },
            AuditCheck {
                name: "ipv6-leak".into(),
                passed: pass,
                detail: if pass {
                    "no IPv6 egress"
                } else {
                    "IPv6 packet escaped"
                }
                .into(),
                proof: "b".repeat(64),
            },
        ],
        unix_time: 3_600 * 13 + 61,
    }
}

pub fn nodes() -> Vec<NodeSummary> {
    vec![NodeSummary {
        name: "oracle-fra".into(),
        kind: NodeKind::Voidwire,
        role: NodeRole::Both,
        country: Some("DE".into()),
        transports: vec![TransportKind::NativeUdp, TransportKind::TlsWebsocket],
        post_quantum: true,
    }]
}
