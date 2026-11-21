//! In-pipeline DNS interception (ARCHITECTURE.md §3, step 3).
//!
//! * UDP to port 53 on **any** address (v4 or v6) is answered by the vault.
//!   The reply's source is the original destination (`8.8.8.8:53`), so apps
//!   with hard-coded resolvers transparently receive vault answers.
//! * TCP to port 53 gets an immediate RST so clients fall back to UDP.
//! * UDP/TCP to port 853 (DoT) on anything but the vault is dropped.

use std::net::{IpAddr, SocketAddr};

use vw_core::consts::{DNS_PORT, DNS_VAULT_V4, DNS_VAULT_V6, DOT_PORT, TTL_NORMAL};
use vw_core::packet::{
    build_udp, fix_ipv4_header_checksum, fix_l4_checksum, IpView, PROTO_TCP, PROTO_UDP,
};
use vw_core::telemetry::Counters;

use crate::message::EDNS_UDP_SIZE;
use crate::vault::DnsVault;

/// What the pipeline should do with a packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InterceptVerdict {
    /// Not DNS: continue down the pipeline.
    NotDns,
    /// Write this IP packet back to the TUN (towards the local client).
    Respond(Vec<u8>),
    /// Discard silently.
    Drop,
}

const TCP_FIN: u8 = 0x01;
const TCP_SYN: u8 = 0x02;
const TCP_RST: u8 = 0x04;
const TCP_ACK: u8 = 0x10;

fn is_vault(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(a) => *a == DNS_VAULT_V4,
        IpAddr::V6(a) => *a == DNS_VAULT_V6,
    }
}

/// Classify and, for DNS, answer an outbound plaintext IP packet.
pub async fn intercept(vault: &DnsVault, pkt: &[u8]) -> InterceptVerdict {
    let Ok(v) = IpView::parse(pkt) else {
        return InterceptVerdict::NotDns;
    };
    if v.is_fragment_tail {
        return InterceptVerdict::NotDns;
    }
    let Some((sport, dport)) = v.ports(pkt) else {
        return InterceptVerdict::NotDns;
    };
    let counters: &Counters = vault.counters();
    match (v.protocol, dport) {
        (PROTO_UDP, DNS_PORT) => {
            Counters::add(&counters.dns_intercepted, 1);
            let o = v.l4_offset;
            if o + 8 > v.total_len {
                return InterceptVerdict::Drop;
            }
            let ulen = u16::from_be_bytes([pkt[o + 4], pkt[o + 5]]) as usize;
            // A first fragment (or truncated datagram) cannot be answered.
            if ulen < 8 || o + ulen != v.total_len || is_v4_more_fragments(pkt, &v) {
                return InterceptVerdict::Drop;
            }
            let Some(payload) = v.udp_payload(pkt) else {
                return InterceptVerdict::Drop;
            };
            // Fit the answer to the tunnel-safe MTU (1280 incl. IPv6+UDP headers).
            let resp = vault.resolve_udp(payload, EDNS_UDP_SIZE as usize).await;
            let src = SocketAddr::new(v.dst, DNS_PORT);
            let dst = SocketAddr::new(v.src, sport);
            match build_udp(src, dst, &resp, TTL_NORMAL) {
                Ok(p) => InterceptVerdict::Respond(p),
                Err(_) => InterceptVerdict::Drop,
            }
        }
        (PROTO_TCP, DNS_PORT) => {
            Counters::add(&counters.dns_intercepted, 1);
            match build_rst_reply(pkt, &v) {
                Some(rst) => InterceptVerdict::Respond(rst),
                None => InterceptVerdict::Drop,
            }
        }
        (PROTO_UDP | PROTO_TCP, DOT_PORT) if !is_vault(&v.dst) => {
            Counters::add(&counters.dot_blocked, 1);
            InterceptVerdict::Drop
        }
        _ => InterceptVerdict::NotDns,
    }
}

fn is_v4_more_fragments(pkt: &[u8], v: &IpView) -> bool {
    v.version == 4 && pkt[6] & 0x20 != 0
}

/// RFC 9293 §3.10.7.1 reset for a segment to a closed port. Returns `None`
/// for RST segments (never answer a reset) and malformed headers.
pub fn build_rst_reply(pkt: &[u8], v: &IpView) -> Option<Vec<u8>> {
    let o = v.l4_offset;
    if o + 20 > v.total_len {
        return None;
    }
    let tcp = &pkt[o..v.total_len];
    let flags = tcp[13];
    if flags & TCP_RST != 0 {
        return None;
    }
    let data_off = ((tcp[12] >> 4) as usize) * 4;
    if data_off < 20 || data_off > tcp.len() {
        return None;
    }
    let seq = u32::from_be_bytes([tcp[4], tcp[5], tcp[6], tcp[7]]);
    let ack = u32::from_be_bytes([tcp[8], tcp[9], tcp[10], tcp[11]]);
    let payload_len = (tcp.len() - data_off) as u32;
    let seg_len = payload_len + u32::from(flags & TCP_SYN != 0) + u32::from(flags & TCP_FIN != 0);
    let sport = u16::from_be_bytes([tcp[0], tcp[1]]);
    let dport = u16::from_be_bytes([tcp[2], tcp[3]]);
    let (r_seq, r_ack, r_flags) = if flags & TCP_ACK != 0 {
        // <SEQ=SEG.ACK><CTL=RST>
        (ack, 0, TCP_RST)
    } else {
        // <SEQ=0><ACK=SEG.SEQ+SEG.LEN><CTL=RST,ACK>
        (0, seq.wrapping_add(seg_len), TCP_RST | TCP_ACK)
    };
    build_tcp_segment(
        SocketAddr::new(v.dst, dport),
        SocketAddr::new(v.src, sport),
        r_seq,
        r_ack,
        r_flags,
    )
}

/// Build a bare 20-byte-header TCP segment (window 0) with valid checksums.
fn build_tcp_segment(
    src: SocketAddr,
    dst: SocketAddr,
    seq: u32,
    ack: u32,
    flags: u8,
) -> Option<Vec<u8>> {
    let mut tcp = [0u8; 20];
    tcp[0..2].copy_from_slice(&src.port().to_be_bytes());
    tcp[2..4].copy_from_slice(&dst.port().to_be_bytes());
    tcp[4..8].copy_from_slice(&seq.to_be_bytes());
    tcp[8..12].copy_from_slice(&ack.to_be_bytes());
    tcp[12] = 5 << 4;
    tcp[13] = flags;
    let mut p = match (src.ip(), dst.ip()) {
        (IpAddr::V4(s), IpAddr::V4(d)) => {
            let mut p = vec![0u8; 40];
            p[0] = 0x45;
            p[2..4].copy_from_slice(&40u16.to_be_bytes());
            p[6] = 0x40; // DF
            p[8] = TTL_NORMAL;
            p[9] = PROTO_TCP;
            p[12..16].copy_from_slice(&s.octets());
            p[16..20].copy_from_slice(&d.octets());
            p[20..].copy_from_slice(&tcp);
            fix_ipv4_header_checksum(&mut p);
            p
        }
        (IpAddr::V6(s), IpAddr::V6(d)) => {
            let mut p = vec![0u8; 60];
            p[0] = 0x60;
            p[4..6].copy_from_slice(&20u16.to_be_bytes());
            p[6] = PROTO_TCP;
            p[7] = TTL_NORMAL;
            p[8..24].copy_from_slice(&s.octets());
            p[24..40].copy_from_slice(&d.octets());
            p[40..].copy_from_slice(&tcp);
            p
        }
        _ => return None,
    };
    fix_l4_checksum(&mut p).ok()?;
    Some(p)
}
