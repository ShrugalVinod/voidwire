//! Privacy-preserving counters (category counts only, RAM only).

use std::sync::atomic::{AtomicU64, Ordering::Relaxed};

use serde::{Deserialize, Serialize};

use crate::config::ShieldCategory;

#[derive(Debug, Default)]
pub struct Counters {
    pub tx_bytes: AtomicU64,
    pub rx_bytes: AtomicU64,
    pub tx_packets: AtomicU64,
    pub rx_packets: AtomicU64,
    pub stun_blocked: AtomicU64,
    pub ipv6_dropped: AtomicU64,
    pub dns_intercepted: AtomicU64,
    pub dot_blocked: AtomicU64,
    pub pre_canary_dropped: AtomicU64,
    pub ts_scrubbed: AtomicU64,
    pub mss_clamped: AtomicU64,
    pub ttl_normalized: AtomicU64,
    pub chaff_sent: AtomicU64,
    pub handshakes: AtomicU64,
    pub pq_rotations: AtomicU64,
    pub shield_ads: AtomicU64,
    pub shield_trackers: AtomicU64,
    pub shield_telemetry: AtomicU64,
    pub shield_malware: AtomicU64,
    pub shield_custom: AtomicU64,
    pub shield_cname_uncloaked: AtomicU64,
}

impl Counters {
    pub fn add(c: &AtomicU64, n: u64) {
        c.fetch_add(n, Relaxed);
    }

    pub fn shield_hit(&self, cat: ShieldCategory) {
        let c = match cat {
            ShieldCategory::Ads => &self.shield_ads,
            ShieldCategory::Trackers => &self.shield_trackers,
            ShieldCategory::Telemetry => &self.shield_telemetry,
            ShieldCategory::Malware => &self.shield_malware,
            ShieldCategory::Custom => &self.shield_custom,
        };
        c.fetch_add(1, Relaxed);
    }

    pub fn snapshot(&self) -> TelemetrySnapshot {
        let g = |c: &AtomicU64| c.load(Relaxed);
        TelemetrySnapshot {
            tx_bytes: g(&self.tx_bytes),
            rx_bytes: g(&self.rx_bytes),
            tx_packets: g(&self.tx_packets),
            rx_packets: g(&self.rx_packets),
            stun_blocked: g(&self.stun_blocked),
            ipv6_dropped: g(&self.ipv6_dropped),
            dns_intercepted: g(&self.dns_intercepted),
            dot_blocked: g(&self.dot_blocked),
            pre_canary_dropped: g(&self.pre_canary_dropped),
            ts_scrubbed: g(&self.ts_scrubbed),
            mss_clamped: g(&self.mss_clamped),
            ttl_normalized: g(&self.ttl_normalized),
            chaff_sent: g(&self.chaff_sent),
            handshakes: g(&self.handshakes),
            pq_rotations: g(&self.pq_rotations),
            shield: ShieldCounts {
                ads: g(&self.shield_ads),
                trackers: g(&self.shield_trackers),
                telemetry: g(&self.shield_telemetry),
                malware: g(&self.shield_malware),
                custom: g(&self.shield_custom),
                cname_uncloaked: g(&self.shield_cname_uncloaked),
            },
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShieldCounts {
    pub ads: u64,
    pub trackers: u64,
    pub telemetry: u64,
    pub malware: u64,
    pub custom: u64,
    pub cname_uncloaked: u64,
}

impl ShieldCounts {
    pub fn total(&self) -> u64 {
        self.ads + self.trackers + self.telemetry + self.malware + self.custom
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TelemetrySnapshot {
    pub tx_bytes: u64,
    pub rx_bytes: u64,
    pub tx_packets: u64,
    pub rx_packets: u64,
    pub stun_blocked: u64,
    pub ipv6_dropped: u64,
    pub dns_intercepted: u64,
    pub dot_blocked: u64,
    pub pre_canary_dropped: u64,
    pub ts_scrubbed: u64,
    pub mss_clamped: u64,
    pub ttl_normalized: u64,
    pub chaff_sent: u64,
    pub handshakes: u64,
    pub pq_rotations: u64,
    pub shield: ShieldCounts,
}
