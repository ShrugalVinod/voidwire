//! Userspace WebRTC STUN filter (pipeline step 2, ARCHITECTURE.md §3).
//!
//! Drops UDP datagrams whose payload is an RFC 5389 STUN Binding Request, the
//! message browsers send to discover the host's public/LAN addresses. This is
//! the only STUN guard on macOS (pf cannot match payload bytes) and on Windows;
//! on Linux the nftables `@th,96,32` rule backs it up in the kernel.

use std::sync::atomic::Ordering::Relaxed;
use std::sync::Arc;

use vw_core::consts::STUN_MAGIC;
use vw_core::packet::{IpView, PROTO_UDP};
use vw_core::telemetry::Counters;

/// STUN header length.
pub const STUN_HEADER_LEN: usize = 20;
/// Message type of a Binding Request (method 0x001, class request).
pub const STUN_BINDING_REQUEST: u16 = 0x0001;

/// Verdict for one IP packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Pass,
    Drop,
}

/// True when `payload` (a UDP payload) is a well-formed STUN Binding Request:
/// first two bits zero, message type 0x0001, magic cookie 0x2112A442, and a
/// length field that is a multiple of 4 and exactly matches the payload.
pub fn is_stun(payload: &[u8]) -> bool {
    if payload.len() < STUN_HEADER_LEN {
        return false;
    }
    if payload[0] & 0xC0 != 0 {
        return false;
    }
    let msg_type = u16::from_be_bytes([payload[0], payload[1]]);
    if msg_type != STUN_BINDING_REQUEST {
        return false;
    }
    let len = u16::from_be_bytes([payload[2], payload[3]]) as usize;
    if len % 4 != 0 || STUN_HEADER_LEN + len != payload.len() {
        return false;
    }
    u32::from_be_bytes([payload[4], payload[5], payload[6], payload[7]]) == STUN_MAGIC
}

/// Packet-pipeline STUN filter.
#[derive(Debug, Clone)]
pub struct StunFilter {
    enabled: bool,
    counters: Arc<Counters>,
}

impl StunFilter {
    pub fn new(enabled: bool, counters: Arc<Counters>) -> Self {
        Self { enabled, counters }
    }

    pub fn enabled(&self) -> bool {
        self.enabled
    }

    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }

    /// Inspect one plaintext IPv4/IPv6 packet read from the TUN.
    /// Non-IP, non-UDP, fragment tails and malformed packets pass (other
    /// stages handle them); STUN Binding Requests are dropped and counted.
    pub fn inspect(&self, ip_packet: &[u8]) -> Verdict {
        if !self.enabled {
            return Verdict::Pass;
        }
        let Ok(view) = IpView::parse(ip_packet) else {
            return Verdict::Pass;
        };
        if view.protocol != PROTO_UDP {
            return Verdict::Pass;
        }
        match view.udp_payload(ip_packet) {
            Some(p) if is_stun(p) => {
                self.counters.stun_blocked.fetch_add(1, Relaxed);
                tracing::trace!("dropped STUN binding request");
                Verdict::Drop
            }
            _ => Verdict::Pass,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;
    use vw_core::packet::{build_tcp_syn, build_udp};

    /// Binding Request with a SOFTWARE attribute (8 bytes of value).
    fn binding_request() -> Vec<u8> {
        let mut m = Vec::new();
        m.extend_from_slice(&STUN_BINDING_REQUEST.to_be_bytes());
        m.extend_from_slice(&12u16.to_be_bytes()); // attr header 4 + value 8
        m.extend_from_slice(&STUN_MAGIC.to_be_bytes());
        m.extend_from_slice(&[0x5a; 12]); // transaction id
        m.extend_from_slice(&0x8022u16.to_be_bytes()); // SOFTWARE
        m.extend_from_slice(&8u16.to_be_bytes());
        m.extend_from_slice(b"chromium");
        m
    }

    fn src4() -> SocketAddr {
        "100.96.0.2:50000".parse().unwrap()
    }
    fn dst4() -> SocketAddr {
        "198.51.100.20:3478".parse().unwrap()
    }

    fn filter() -> (StunFilter, Arc<Counters>) {
        let c = Arc::new(Counters::default());
        (StunFilter::new(true, c.clone()), c)
    }

    #[test]
    fn drops_binding_request_v4_and_v6() {
        let (f, c) = filter();
        let msg = binding_request();
        assert!(is_stun(&msg));
        let p4 = build_udp(src4(), dst4(), &msg, 64).unwrap();
        assert_eq!(f.inspect(&p4), Verdict::Drop);
        let p6 = build_udp(
            "[fd00:564f:4944:1::2]:50000".parse().unwrap(),
            "[2001:db8::20]:19302".parse().unwrap(),
            &msg,
            64,
        )
        .unwrap();
        assert_eq!(f.inspect(&p6), Verdict::Drop);
        assert_eq!(c.snapshot().stun_blocked, 2);
    }

    #[test]
    fn bare_header_request_is_stun() {
        let mut m = binding_request();
        m.truncate(20);
        m[2..4].copy_from_slice(&0u16.to_be_bytes());
        assert!(is_stun(&m));
    }

    #[test]
    fn look_alikes_pass() {
        let (f, c) = filter();
        let base = binding_request();
        let mut cases: Vec<Vec<u8>> = Vec::new();
        // Wrong magic cookie (classic RFC 3489 transaction id).
        let mut m = base.clone();
        m[4] ^= 0xff;
        cases.push(m);
        // Binding success response (0x0101).
        let mut m = base.clone();
        m[0..2].copy_from_slice(&0x0101u16.to_be_bytes());
        cases.push(m);
        // First two bits set (e.g. a ChannelData / RTP-like packet).
        let mut m = base.clone();
        m[0] |= 0x40;
        cases.push(m);
        // Length not a multiple of 4.
        let mut m = base.clone();
        m[2..4].copy_from_slice(&13u16.to_be_bytes());
        m.push(0);
        cases.push(m);
        // Length inconsistent with the payload.
        let mut m = base.clone();
        m[2..4].copy_from_slice(&16u16.to_be_bytes());
        cases.push(m);
        // Too short.
        cases.push(base[..19].to_vec());
        // WireGuard handshake initiation-sized random data with the cookie
        // at bytes 4..8 but a non-STUN type.
        let mut m = vec![1u8, 0, 0, 0];
        m.extend_from_slice(&STUN_MAGIC.to_be_bytes());
        m.resize(148, 0x11);
        cases.push(m);
        for (i, payload) in cases.iter().enumerate() {
            assert!(!is_stun(payload), "case {i} misdetected");
            let p = build_udp(src4(), dst4(), payload, 64).unwrap();
            assert_eq!(f.inspect(&p), Verdict::Pass, "case {i}");
        }
        assert_eq!(c.snapshot().stun_blocked, 0);
    }

    #[test]
    fn non_udp_and_garbage_pass() {
        let (f, c) = filter();
        let syn = build_tcp_syn(src4(), "198.51.100.20:443".parse().unwrap(), 1, &[], 64).unwrap();
        assert_eq!(f.inspect(&syn), Verdict::Pass);
        assert_eq!(f.inspect(&[]), Verdict::Pass);
        assert_eq!(f.inspect(&[0x00; 60]), Verdict::Pass);
        assert_eq!(c.snapshot().stun_blocked, 0);
    }

    #[test]
    fn disabled_filter_passes_everything() {
        let c = Arc::new(Counters::default());
        let mut f = StunFilter::new(false, c.clone());
        let p = build_udp(src4(), dst4(), &binding_request(), 64).unwrap();
        assert_eq!(f.inspect(&p), Verdict::Pass);
        f.set_enabled(true);
        assert_eq!(f.inspect(&p), Verdict::Drop);
        assert_eq!(c.snapshot().stun_blocked, 1);
    }
}
