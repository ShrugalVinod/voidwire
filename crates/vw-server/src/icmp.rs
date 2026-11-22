//! ICMP / ICMPv6 echo replies for the in-tunnel node gateway.
//!
//! The client optimizer (ARCHITECTURE.md §10) pings `NODE_GATEWAY_V4/V6`
//! through the tunnel to measure RTT and loss. The node answers in userspace.

use std::net::IpAddr;

use vw_core::consts::{NODE_GATEWAY_V4, NODE_GATEWAY_V6, TTL_NORMAL};
use vw_core::packet::{
    checksum, fix_ipv4_header_checksum, fix_l4_checksum, IpView, PROTO_ICMP, PROTO_ICMPV6,
};

const ICMP_ECHO_REQUEST: u8 = 8;
const ICMP_ECHO_REPLY: u8 = 0;
const ICMPV6_ECHO_REQUEST: u8 = 128;
const ICMPV6_ECHO_REPLY: u8 = 129;

/// True when `addr` is one of the node's in-tunnel gateway addresses.
pub fn is_gateway(addr: IpAddr) -> bool {
    match addr {
        IpAddr::V4(a) => a == NODE_GATEWAY_V4,
        IpAddr::V6(a) => a == NODE_GATEWAY_V6,
    }
}

/// Build the echo reply for an echo request addressed to the gateway, or
/// `None` if `pkt` is anything else (other ICMP types, fragments, bad
/// checksums, other destinations).
pub fn echo_reply(pkt: &[u8]) -> Option<Vec<u8>> {
    let v = IpView::parse(pkt).ok()?;
    if v.is_fragment_tail || !is_gateway(v.dst) {
        return None;
    }
    let l4 = pkt.get(v.l4_offset..v.total_len)?;
    if l4.len() < 8 {
        return None;
    }
    match (v.src, v.dst, v.protocol) {
        (IpAddr::V4(src), IpAddr::V4(dst), PROTO_ICMP) => {
            // First fragments of a fragmented echo are not answered either.
            let frag = u16::from_be_bytes([pkt[6], pkt[7]]);
            if frag & 0x2000 != 0 || l4[0] != ICMP_ECHO_REQUEST || l4[1] != 0 {
                return None;
            }
            if checksum(l4) != 0 {
                return None;
            }
            let total = 20 + l4.len();
            let mut out = vec![0u8; total];
            out[0] = 0x45;
            out[1] = pkt[1];
            out[2..4].copy_from_slice(&(total as u16).to_be_bytes());
            out[4..6].copy_from_slice(&pkt[4..6]);
            out[8] = TTL_NORMAL;
            out[9] = PROTO_ICMP;
            out[12..16].copy_from_slice(&dst.octets());
            out[16..20].copy_from_slice(&src.octets());
            out[20..].copy_from_slice(l4);
            out[20] = ICMP_ECHO_REPLY;
            out[22] = 0;
            out[23] = 0;
            let c = checksum(&out[20..]);
            out[22..24].copy_from_slice(&c.to_be_bytes());
            fix_ipv4_header_checksum(&mut out);
            Some(out)
        }
        (IpAddr::V6(src), IpAddr::V6(dst), PROTO_ICMPV6) => {
            if l4[0] != ICMPV6_ECHO_REQUEST || l4[1] != 0 {
                return None;
            }
            if !vw_core::packet::verify_l4_checksum(pkt) {
                return None;
            }
            let mut out = vec![0u8; 40 + l4.len()];
            out[0] = 0x60;
            out[4..6].copy_from_slice(&(l4.len() as u16).to_be_bytes());
            out[6] = PROTO_ICMPV6;
            out[7] = TTL_NORMAL;
            out[8..24].copy_from_slice(&dst.octets());
            out[24..40].copy_from_slice(&src.octets());
            out[40..].copy_from_slice(l4);
            out[40] = ICMPV6_ECHO_REPLY;
            fix_l4_checksum(&mut out).ok()?;
            Some(out)
        }
        _ => None,
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};
    use vw_core::packet::verify_l4_checksum;

    pub(crate) fn echo_v4(src: Ipv4Addr, dst: Ipv4Addr, id: u16, seq: u16, data: &[u8]) -> Vec<u8> {
        let total = 20 + 8 + data.len();
        let mut p = vec![0u8; total];
        p[0] = 0x45;
        p[2..4].copy_from_slice(&(total as u16).to_be_bytes());
        p[4..6].copy_from_slice(&0x1234u16.to_be_bytes());
        p[8] = 64;
        p[9] = PROTO_ICMP;
        p[12..16].copy_from_slice(&src.octets());
        p[16..20].copy_from_slice(&dst.octets());
        p[20] = ICMP_ECHO_REQUEST;
        p[24..26].copy_from_slice(&id.to_be_bytes());
        p[26..28].copy_from_slice(&seq.to_be_bytes());
        p[28..].copy_from_slice(data);
        let c = checksum(&p[20..]);
        p[22..24].copy_from_slice(&c.to_be_bytes());
        fix_ipv4_header_checksum(&mut p);
        p
    }

    pub(crate) fn echo_v6(src: Ipv6Addr, dst: Ipv6Addr, id: u16, seq: u16, data: &[u8]) -> Vec<u8> {
        let plen = 8 + data.len();
        let mut p = vec![0u8; 40 + plen];
        p[0] = 0x60;
        p[4..6].copy_from_slice(&(plen as u16).to_be_bytes());
        p[6] = PROTO_ICMPV6;
        p[7] = 64;
        p[8..24].copy_from_slice(&src.octets());
        p[24..40].copy_from_slice(&dst.octets());
        p[40] = ICMPV6_ECHO_REQUEST;
        p[44..46].copy_from_slice(&id.to_be_bytes());
        p[46..48].copy_from_slice(&seq.to_be_bytes());
        p[48..].copy_from_slice(data);
        fix_l4_checksum(&mut p).unwrap();
        p
    }

    #[test]
    fn v4_echo_reply_is_correct() {
        let client = Ipv4Addr::new(100, 96, 0, 9);
        let req = echo_v4(client, NODE_GATEWAY_V4, 0xBEEF, 7, b"voidwire-probe!");
        let rep = echo_reply(&req).expect("reply");
        let v = IpView::parse(&rep).unwrap();
        assert_eq!(v.src, IpAddr::V4(NODE_GATEWAY_V4));
        assert_eq!(v.dst, IpAddr::V4(client));
        assert_eq!(v.protocol, PROTO_ICMP);
        assert_eq!(rep[8], TTL_NORMAL);
        assert_eq!(checksum(&rep[..20]), 0, "ipv4 header checksum");
        assert_eq!(checksum(&rep[20..]), 0, "icmp checksum");
        assert_eq!(rep[20], ICMP_ECHO_REPLY);
        assert_eq!(&rep[24..26], &0xBEEFu16.to_be_bytes());
        assert_eq!(&rep[26..28], &7u16.to_be_bytes());
        assert_eq!(&rep[28..], b"voidwire-probe!");
        assert_eq!(rep.len(), req.len());
    }

    #[test]
    fn v4_rejects_non_echo_bad_checksum_and_other_targets() {
        let c = Ipv4Addr::new(100, 96, 0, 9);
        let mut bad = echo_v4(c, NODE_GATEWAY_V4, 1, 1, b"x");
        bad[30 - 2] ^= 0xff;
        assert!(echo_reply(&bad).is_none());
        let other = echo_v4(c, Ipv4Addr::new(1, 1, 1, 1), 1, 1, b"x");
        assert!(echo_reply(&other).is_none());
        let mut reply = echo_v4(c, NODE_GATEWAY_V4, 1, 1, b"x");
        reply[20] = ICMP_ECHO_REPLY;
        let ck = {
            reply[22] = 0;
            reply[23] = 0;
            checksum(&reply[20..])
        };
        reply[22..24].copy_from_slice(&ck.to_be_bytes());
        assert!(echo_reply(&reply).is_none(), "never answer replies");
        let mut frag = echo_v4(c, NODE_GATEWAY_V4, 1, 1, b"x");
        frag[6] = 0x20; // MF
        fix_ipv4_header_checksum(&mut frag);
        assert!(echo_reply(&frag).is_none());
    }

    #[test]
    fn v6_echo_reply_is_correct() {
        let client: Ipv6Addr = "fd00:564f:4944:1::9".parse().unwrap();
        let req = echo_v6(client, NODE_GATEWAY_V6, 42, 3, &[0xAA; 56]);
        assert!(verify_l4_checksum(&req));
        let rep = echo_reply(&req).expect("reply");
        let v = IpView::parse(&rep).unwrap();
        assert_eq!(v.src, IpAddr::V6(NODE_GATEWAY_V6));
        assert_eq!(v.dst, IpAddr::V6(client));
        assert_eq!(rep[7], TTL_NORMAL);
        assert_eq!(rep[40], ICMPV6_ECHO_REPLY);
        assert!(verify_l4_checksum(&rep), "icmpv6 checksum");
        assert_eq!(&rep[44..48], &req[44..48]);
        assert_eq!(&rep[48..], &[0xAA; 56][..]);
        let mut bad = req.clone();
        bad[50] ^= 1;
        assert!(echo_reply(&bad).is_none());
    }
}
