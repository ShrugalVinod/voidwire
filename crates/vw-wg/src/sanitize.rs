//! Outbound packet sanitizer (pipeline step 1, ARCHITECTURE.md §3):
//! TTL / hop-limit normalisation, TCP MSS clamping and TCP timestamp
//! scrubbing, with checksum repair. Defeats OS fingerprinting and TTL-based
//! tethering / hop-count detection.

use vw_core::config::SanitizerSettings;
use vw_core::consts::{mss_for_mtu, TTL_NORMAL};
use vw_core::packet::{fix_ipv4_header_checksum, fix_l4_checksum, IpView, PROTO_TCP};
use vw_core::telemetry::Counters;

const TCP_OPT_EOL: u8 = 0;
const TCP_OPT_NOP: u8 = 1;
const TCP_OPT_MSS: u8 = 2;
const TCP_OPT_TIMESTAMP: u8 = 8;
const TCP_FLAG_SYN: u8 = 0x02;

/// What [`Sanitizer::process_outbound`] changed.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SanitizeReport {
    pub ttl_normalized: bool,
    /// An existing MSS option was lowered.
    pub mss_clamped: bool,
    /// A missing MSS option was written into existing option padding.
    pub mss_inserted: bool,
    pub timestamps_scrubbed: bool,
}

impl SanitizeReport {
    pub fn modified(&self) -> bool {
        self.ttl_normalized || self.mss_clamped || self.mss_inserted || self.timestamps_scrubbed
    }

    /// Add this report to the telemetry counters.
    pub fn record(&self, c: &Counters) {
        if self.ttl_normalized {
            Counters::add(&c.ttl_normalized, 1);
        }
        if self.mss_clamped || self.mss_inserted {
            Counters::add(&c.mss_clamped, 1);
        }
        if self.timestamps_scrubbed {
            Counters::add(&c.ts_scrubbed, 1);
        }
    }
}

/// Stateless outbound sanitizer for one effective tunnel MTU.
#[derive(Debug, Clone)]
pub struct Sanitizer {
    settings: SanitizerSettings,
    mtu: u16,
}

impl Sanitizer {
    /// `mtu` is the effective inner MTU after all hops and transport overhead.
    pub fn new(settings: SanitizerSettings, mtu: u16) -> Self {
        Self { settings, mtu }
    }

    pub fn set_mtu(&mut self, mtu: u16) {
        self.mtu = mtu;
    }

    pub fn mtu(&self) -> u16 {
        self.mtu
    }

    /// Sanitize one outbound IP packet in place. Never panics and never
    /// changes the packet length; unparseable packets are left untouched.
    pub fn process_outbound(&self, pkt: &mut [u8]) -> SanitizeReport {
        let mut report = SanitizeReport::default();
        let Ok(view) = IpView::parse(pkt) else {
            return report;
        };
        if self.settings.normalize_ttl && pkt[view.ttl_offset] != TTL_NORMAL {
            pkt[view.ttl_offset] = TTL_NORMAL;
            if view.version == 4 {
                fix_ipv4_header_checksum(pkt);
            }
            report.ttl_normalized = true;
        }
        if view.protocol != PROTO_TCP || is_fragment(pkt, &view) {
            return report;
        }
        let o = view.l4_offset;
        let total = view.total_len;
        if o + 20 > total {
            return report;
        }
        let doff = (pkt[o + 12] >> 4) as usize * 4;
        if doff < 20 || o + doff > total {
            return report;
        }
        let syn = pkt[o + 13] & TCP_FLAG_SYN != 0;
        let clamp = mss_for_mtu(self.mtu, view.version == 6);
        let opts = &mut pkt[o + 20..o + doff];
        let walk = self.rewrite_options(opts, syn, clamp, &mut report);
        if syn && self.settings.clamp_mss && !walk.mss_seen && !walk.malformed {
            report.mss_inserted = insert_mss(opts, clamp);
        }
        if report.mss_clamped || report.mss_inserted || report.timestamps_scrubbed {
            // Cannot fail: the packet parsed above and its length is unchanged.
            let _ = fix_l4_checksum(pkt);
        }
        report
    }

    fn rewrite_options(
        &self,
        opts: &mut [u8],
        syn: bool,
        clamp: u16,
        report: &mut SanitizeReport,
    ) -> Walk {
        let mut walk = Walk::default();
        let mut i = 0;
        while i < opts.len() {
            match opts[i] {
                TCP_OPT_EOL => break,
                TCP_OPT_NOP => i += 1,
                kind => {
                    let Some(&len) = opts.get(i + 1) else {
                        walk.malformed = true;
                        break;
                    };
                    let len = len as usize;
                    if len < 2 || i + len > opts.len() {
                        walk.malformed = true;
                        break;
                    }
                    if kind == TCP_OPT_MSS && len == 4 && syn {
                        walk.mss_seen = true;
                        let v = u16::from_be_bytes([opts[i + 2], opts[i + 3]]);
                        if self.settings.clamp_mss && v > clamp {
                            opts[i + 2..i + 4].copy_from_slice(&clamp.to_be_bytes());
                            report.mss_clamped = true;
                        }
                    } else if kind == TCP_OPT_TIMESTAMP
                        && len == 10
                        && self.settings.scrub_tcp_timestamps
                    {
                        opts[i..i + 10].fill(TCP_OPT_NOP);
                        report.timestamps_scrubbed = true;
                    }
                    i += len;
                }
            }
        }
        walk
    }
}

#[derive(Default)]
struct Walk {
    mss_seen: bool,
    malformed: bool,
}

/// Write an MSS option into four existing padding bytes (a run of NOPs, or
/// the space after EOL). Never grows the packet.
fn insert_mss(opts: &mut [u8], mss: u16) -> bool {
    let mss_opt = [TCP_OPT_MSS, 4, (mss >> 8) as u8, mss as u8];
    let mut i = 0;
    let mut nop_run = 0usize;
    while i < opts.len() {
        match opts[i] {
            TCP_OPT_NOP => {
                nop_run += 1;
                i += 1;
                if nop_run == 4 {
                    opts[i - 4..i].copy_from_slice(&mss_opt);
                    return true;
                }
            }
            TCP_OPT_EOL => {
                if opts.len() - i >= 4 {
                    opts[i..i + 4].copy_from_slice(&mss_opt);
                    opts[i + 4..].fill(TCP_OPT_EOL);
                    return true;
                }
                return false;
            }
            _ => {
                nop_run = 0;
                let len = opts.get(i + 1).copied().unwrap_or(0) as usize;
                if len < 2 {
                    return false;
                }
                i += len;
            }
        }
    }
    false
}

/// Any IPv4 fragment (MF set or offset ≠ 0) or IPv6 packet with a Fragment
/// header: the TCP checksum covers bytes we cannot see, so L4 is left alone.
fn is_fragment(pkt: &[u8], view: &IpView) -> bool {
    if view.is_fragment_tail {
        return true;
    }
    if view.version == 4 {
        let frag = u16::from_be_bytes([pkt[6], pkt[7]]);
        return frag & 0x3fff != 0;
    }
    let mut next = pkt[6];
    let mut off = 40usize;
    for _ in 0..8 {
        match next {
            44 => return true,
            0 | 43 | 60 => {
                if off + 2 > pkt.len() {
                    return true;
                }
                next = pkt[off];
                off += (pkt[off + 1] as usize + 1) * 8;
            }
            _ => return false,
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;
    use vw_core::packet::{build_tcp_syn, checksum, verify_l4_checksum};

    fn s4() -> (SocketAddr, SocketAddr) {
        (
            "10.0.0.2:40000".parse().unwrap(),
            "93.184.216.34:443".parse().unwrap(),
        )
    }
    fn s6() -> (SocketAddr, SocketAddr) {
        (
            "[fd00:564f:4944:1::2]:40000".parse().unwrap(),
            "[2001:db8::1]:443".parse().unwrap(),
        )
    }
    fn san(mtu: u16) -> Sanitizer {
        Sanitizer::new(SanitizerSettings::default(), mtu)
    }
    // MSS 1460, SACK-permitted, TS(10), NOP, WS(3) = 20 bytes (Linux SYN layout).
    const LINUX_SYN: [u8; 20] = [
        2, 4, 0x05, 0xb4, 4, 2, 8, 10, 1, 2, 3, 4, 0, 0, 0, 0, 1, 3, 3, 7,
    ];

    fn opts(p: &[u8], l4: usize) -> &[u8] {
        let doff = (p[l4 + 12] >> 4) as usize * 4;
        &p[l4 + 20..l4 + doff]
    }

    #[test]
    fn v4_syn_full_normalisation() {
        let (s, d) = s4();
        let mut p = build_tcp_syn(s, d, 1, &LINUX_SYN, 128).unwrap();
        let len = p.len();
        let r = san(1280).process_outbound(&mut p);
        assert!(r.ttl_normalized && r.mss_clamped && r.timestamps_scrubbed);
        assert_eq!(p.len(), len);
        assert_eq!(p[8], 64);
        assert_eq!(checksum(&p[..20]), 0);
        assert!(verify_l4_checksum(&p));
        let o = opts(&p, 20);
        assert_eq!(&o[..4], &[2, 4, 0x04, 0xd8]); // 1240
        assert_eq!(&o[6..16], &[1u8; 10]);
        assert_eq!(&o[16..], &[1, 3, 3, 7]);
    }

    #[test]
    fn mss_never_raised() {
        let (s, d) = s4();
        let mut p = build_tcp_syn(s, d, 1, &[2, 4, 0x03, 0x00], 64).unwrap();
        let before = p.clone();
        let r = san(1420).process_outbound(&mut p);
        assert!(!r.modified());
        assert_eq!(p, before);
    }

    #[test]
    fn v6_syn() {
        let (s, d) = s6();
        let mut p = build_tcp_syn(s, d, 9, &LINUX_SYN, 255).unwrap();
        let r = san(1280).process_outbound(&mut p);
        assert!(r.ttl_normalized && r.mss_clamped && r.timestamps_scrubbed);
        assert_eq!(p[7], 64);
        assert!(verify_l4_checksum(&p));
        let o = opts(&p, 40);
        assert_eq!(u16::from_be_bytes([o[2], o[3]]), 1220);
    }

    #[test]
    fn syn_without_options_left_alone() {
        let (s, d) = s4();
        let mut p = build_tcp_syn(s, d, 1, &[], 64).unwrap();
        let before = p.clone();
        let r = san(1280).process_outbound(&mut p);
        assert!(!r.modified());
        assert_eq!(p, before);
    }

    #[test]
    fn mss_inserted_into_padding() {
        let (s, d) = s4();
        // TS + 2 NOPs, no MSS: scrubbing yields 12 NOPs, MSS goes there.
        let mut p = build_tcp_syn(s, d, 1, &[1, 1, 8, 10, 1, 2, 3, 4, 5, 6, 7, 8], 64).unwrap();
        let r = san(1280).process_outbound(&mut p);
        assert!(r.timestamps_scrubbed && r.mss_inserted);
        assert!(verify_l4_checksum(&p));
        assert_eq!(&opts(&p, 20)[..4], &[2, 4, 0x04, 0xd8]);
        // EOL padding.
        let mut p = build_tcp_syn(s, d, 1, &[4, 2, 0, 0, 0, 0, 0, 0], 64).unwrap();
        let r = san(1280).process_outbound(&mut p);
        assert!(r.mss_inserted);
        assert_eq!(opts(&p, 20), &[4, 2, 2, 4, 0x04, 0xd8, 0, 0]);
        assert!(verify_l4_checksum(&p));
        // No room: untouched.
        let mut p = build_tcp_syn(s, d, 1, &[4, 2, 3, 3, 7, 1, 1, 1], 64).unwrap();
        assert!(!san(1280).process_outbound(&mut p).mss_inserted);
    }

    #[test]
    fn timestamps_scrubbed_on_non_syn() {
        let (s, d) = s4();
        let mut p = build_tcp_syn(s, d, 1, &[1, 1, 8, 10, 9, 9, 9, 9, 8, 8, 8, 8], 64).unwrap();
        p[33] = 0x10; // ACK only
        vw_core::packet::fix_l4_checksum(&mut p).unwrap();
        let r = san(1280).process_outbound(&mut p);
        assert!(r.timestamps_scrubbed && !r.mss_inserted);
        assert_eq!(opts(&p, 20), &[1u8; 12]);
        assert!(verify_l4_checksum(&p));
    }

    #[test]
    fn malformed_options_do_not_panic() {
        let (s, d) = s4();
        for bad in [
            [2u8, 0, 0, 0],
            [8, 200, 1, 1],
            [2, 4, 5, 0xb4],
            [3, 1, 0, 0],
            [255, 255, 255, 255],
            [1, 1, 1, 2],
        ] {
            let mut p = build_tcp_syn(s, d, 1, &bad, 64).unwrap();
            let _ = san(1280).process_outbound(&mut p);
            assert!(verify_l4_checksum(&p));
        }
        // Data offset pointing past the packet, truncated headers, garbage.
        let mut p = build_tcp_syn(s, d, 1, &[], 64).unwrap();
        p[32] = 0xf0;
        let _ = san(1280).process_outbound(&mut p);
        let mut short = vec![0x45u8, 0, 0, 24, 0, 0, 0, 0, 64, 6, 0, 0];
        short.resize(24, 0);
        let _ = san(1280).process_outbound(&mut short);
        let _ = san(1280).process_outbound(&mut []);
        let _ = san(1280).process_outbound(&mut [0x60; 41]);
    }

    #[test]
    fn fragments_l4_untouched() {
        let (s, d) = s4();
        let mut p = build_tcp_syn(s, d, 1, &LINUX_SYN, 64).unwrap();
        p[6] = 0x20; // MF
        fix_ipv4_header_checksum(&mut p);
        let before = p.clone();
        let r = san(1280).process_outbound(&mut p);
        assert!(!r.modified());
        assert_eq!(p, before);
        // Non-first fragment with a different TTL: only TTL changes.
        p[6] = 0x00;
        p[7] = 0x10;
        p[8] = 100;
        fix_ipv4_header_checksum(&mut p);
        let tcp_before = p[20..].to_vec();
        let r = san(1280).process_outbound(&mut p);
        assert!(r.ttl_normalized && !r.mss_clamped && !r.timestamps_scrubbed);
        assert_eq!(&p[20..], &tcp_before[..]);
        assert_eq!(checksum(&p[..20]), 0);
    }

    #[test]
    fn v6_fragment_header_untouched() {
        let (s, d) = s6();
        let syn = build_tcp_syn(s, d, 1, &LINUX_SYN, 64).unwrap();
        // Insert a Fragment header (offset 0, M=1) between IPv6 and TCP.
        let mut p = syn[..40].to_vec();
        p[6] = 44;
        p.extend_from_slice(&[6, 0, 0, 1, 0, 0, 0, 1]);
        p.extend_from_slice(&syn[40..]);
        let plen = (p.len() - 40) as u16;
        p[4..6].copy_from_slice(&plen.to_be_bytes());
        let before = p.clone();
        let r = san(1280).process_outbound(&mut p);
        assert!(!r.modified());
        assert_eq!(p, before);
    }

    #[test]
    fn settings_respected() {
        let (s, d) = s4();
        let mut p = build_tcp_syn(s, d, 1, &LINUX_SYN, 128).unwrap();
        let off = SanitizerSettings {
            normalize_ttl: false,
            clamp_mss: false,
            scrub_tcp_timestamps: false,
        };
        let before = p.clone();
        assert!(!Sanitizer::new(off, 1280)
            .process_outbound(&mut p)
            .modified());
        assert_eq!(p, before);
        let c = Counters::default();
        san(1280).process_outbound(&mut p).record(&c);
        let snap = c.snapshot();
        assert_eq!(
            (snap.ttl_normalized, snap.mss_clamped, snap.ts_scrubbed),
            (1, 1, 1)
        );
    }
}
