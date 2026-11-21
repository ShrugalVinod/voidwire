//! Optimizer measurement types and scoring (ARCHITECTURE.md §10).

use serde::{Deserialize, Serialize};

use crate::config::TransportKind;

/// One measured `(gateway, transport)` candidate.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProbeResult {
    pub node_name: String,
    pub transport: TransportKind,
    pub reachable: bool,
    pub handshake_ms: Option<f64>,
    pub rtt_ms: Option<f64>,
    pub jitter_ms: Option<f64>,
    /// 0.0 ..= 1.0
    pub loss: f64,
    pub throughput_mbps: Option<f64>,
    pub post_quantum: bool,
    pub score: f64,
}

/// Network conditions inferred while probing.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkVerdict {
    /// UDP handshakes time out while TCP/QUIC succeed → DPI or UDP block.
    pub udp_hostile: bool,
    /// QUIC (UDP/443) blocked.
    pub quic_blocked: bool,
    /// Plain WireGuard signatures are filtered but AmneziaWG passes.
    pub wg_signature_filtered: bool,
}

/// Score a candidate. Higher is better; unreachable candidates score 0.
pub fn score(
    throughput_mbps: f64,
    rtt_ms: f64,
    loss: f64,
    post_quantum: bool,
    stealth_on_hostile: bool,
) -> f64 {
    if !throughput_mbps.is_finite() || throughput_mbps <= 0.0 {
        return 0.0;
    }
    let loss = loss.clamp(0.0, 1.0);
    let mut s = throughput_mbps / (1.0 + rtt_ms.max(0.0) / 50.0) * (1.0 - loss).powi(2);
    if !post_quantum {
        s *= 0.9;
    }
    if stealth_on_hostile {
        s *= 1.2;
    }
    s
}

/// The optimizer's decision, shown in CLI/TUI/GUI.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OptimizerDecision {
    pub hops: Vec<String>,
    pub transport: TransportKind,
    pub mtu: u16,
    pub mss_v4: u16,
    pub daita: bool,
    pub verdict: NetworkVerdict,
    pub candidates: Vec<ProbeResult>,
    pub reason: String,
}

#[cfg(test)]
mod tests {
    use super::score;

    #[test]
    fn ordering() {
        let fast_far = score(300.0, 150.0, 0.0, true, false);
        let slow_near = score(50.0, 10.0, 0.0, true, false);
        assert!(fast_far > slow_near);
        assert!(score(100.0, 20.0, 0.0, true, false) > score(100.0, 20.0, 0.1, true, false));
        assert!(score(100.0, 20.0, 0.0, true, false) > score(100.0, 20.0, 0.0, false, false));
        assert_eq!(score(0.0, 1.0, 0.0, true, true), 0.0);
        assert_eq!(score(f64::NAN, 1.0, 0.0, true, true), 0.0);
    }
}
