//! Zero-copy IPv4/IPv6/TCP/UDP parsing, checksums and packet builders.
//!
//! Used by the sanitizer (vw-wg), STUN filter (vw-firewall), DNS interception
//! (vw-dns), the node NAT (vw-server) and the leak gauntlet.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use crate::error::{Result, VwError};

pub const PROTO_ICMP: u8 = 1;
pub const PROTO_TCP: u8 = 6;
pub const PROTO_UDP: u8 = 17;
pub const PROTO_ICMPV6: u8 = 58;

const V6_HOP_BY_HOP: u8 = 0;
const V6_ROUTING: u8 = 43;
const V6_FRAGMENT: u8 = 44;
const V6_DEST_OPTS: u8 = 60;

/// Parsed view of an IP packet's headers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IpView {
    pub version: u8,
    /// Upper-layer protocol (after IPv6 extension headers).
    pub protocol: u8,
    pub src: IpAddr,
    pub dst: IpAddr,
    /// Offset of the upper-layer header.
    pub l4_offset: usize,
    /// Packet length declared by the IP header (≤ buffer length).
    pub total_len: usize,
    /// Offset of the TTL / hop-limit byte.
    pub ttl_offset: usize,
    /// True for non-first fragments (no L4 header present).
    pub is_fragment_tail: bool,
}

impl IpView {
    pub fn parse(buf: &[u8]) -> Result<Self> {
        let first = *buf.first().ok_or(VwError::Packet("empty"))?;
        match first >> 4 {
            4 => Self::parse_v4(buf),
            6 => Self::parse_v6(buf),
            _ => Err(VwError::Packet("not an IP packet")),
        }
    }

    fn parse_v4(buf: &[u8]) -> Result<Self> {
        if buf.len() < 20 {
            return Err(VwError::Packet("short ipv4"));
        }
        let ihl = ((buf[0] & 0x0f) as usize) * 4;
        let total = u16::from_be_bytes([buf[2], buf[3]]) as usize;
        if ihl < 20 || total < ihl || total > buf.len() {
            return Err(VwError::Packet("bad ipv4 lengths"));
        }
        let frag = u16::from_be_bytes([buf[6], buf[7]]);
        let offset = frag & 0x1fff;
        Ok(Self {
            version: 4,
            protocol: buf[9],
            src: IpAddr::V4(Ipv4Addr::new(buf[12], buf[13], buf[14], buf[15])),
            dst: IpAddr::V4(Ipv4Addr::new(buf[16], buf[17], buf[18], buf[19])),
            l4_offset: ihl,
            total_len: total,
            ttl_offset: 8,
            is_fragment_tail: offset != 0,
        })
    }

    fn parse_v6(buf: &[u8]) -> Result<Self> {
        if buf.len() < 40 {
            return Err(VwError::Packet("short ipv6"));
        }
        let payload = u16::from_be_bytes([buf[4], buf[5]]) as usize;
        let total = 40 + payload;
        if total > buf.len() {
            return Err(VwError::Packet("bad ipv6 length"));
        }
        let mut next = buf[6];
        let mut off = 40usize;
        let mut frag_tail = false;
        // Walk at most 8 extension headers.
        for _ in 0..8 {
            match next {
                V6_HOP_BY_HOP | V6_ROUTING | V6_DEST_OPTS => {
                    if off + 8 > total {
                        return Err(VwError::Packet("truncated ipv6 ext header"));
                    }
                    next = buf[off];
                    off += (buf[off + 1] as usize + 1) * 8;
                }
                V6_FRAGMENT => {
                    if off + 8 > total {
                        return Err(VwError::Packet("truncated ipv6 fragment header"));
                    }
                    next = buf[off];
                    let fo = u16::from_be_bytes([buf[off + 2], buf[off + 3]]) >> 3;
                    frag_tail = fo != 0;
                    off += 8;
                }
                _ => break,
            }
        }
        if off > total {
            return Err(VwError::Packet("ipv6 ext headers exceed packet"));
        }
        let mut s = [0u8; 16];
        let mut d = [0u8; 16];
        s.copy_from_slice(&buf[8..24]);
        d.copy_from_slice(&buf[24..40]);
        Ok(Self {
            version: 6,
            protocol: next,
            src: IpAddr::V6(Ipv6Addr::from(s)),
            dst: IpAddr::V6(Ipv6Addr::from(d)),
            l4_offset: off,
            total_len: total,
            ttl_offset: 7,
            is_fragment_tail: frag_tail,
        })
    }

    /// Source and destination ports for TCP/UDP packets with an L4 header.
    pub fn ports(&self, buf: &[u8]) -> Option<(u16, u16)> {
        if self.is_fragment_tail || !matches!(self.protocol, PROTO_TCP | PROTO_UDP) {
            return None;
        }
        let o = self.l4_offset;
        if o + 4 > self.total_len {
            return None;
        }
        Some((
            u16::from_be_bytes([buf[o], buf[o + 1]]),
            u16::from_be_bytes([buf[o + 2], buf[o + 3]]),
        ))
    }

    /// UDP payload slice (after the 8-byte UDP header).
    pub fn udp_payload<'a>(&self, buf: &'a [u8]) -> Option<&'a [u8]> {
        if self.protocol != PROTO_UDP || self.is_fragment_tail {
            return None;
        }
        let o = self.l4_offset;
        if o + 8 > self.total_len {
            return None;
        }
        let ulen = u16::from_be_bytes([buf[o + 4], buf[o + 5]]) as usize;
        let end = if ulen >= 8 && o + ulen <= self.total_len {
            o + ulen
        } else {
            self.total_len
        };
        Some(&buf[o + 8..end])
    }

    pub fn src_sock(&self, buf: &[u8]) -> Option<SocketAddr> {
        self.ports(buf).map(|(s, _)| SocketAddr::new(self.src, s))
    }

    pub fn dst_sock(&self, buf: &[u8]) -> Option<SocketAddr> {
        self.ports(buf).map(|(_, d)| SocketAddr::new(self.dst, d))
    }
}

/// One's-complement sum of 16-bit words (unfolded).
pub fn sum16(data: &[u8], mut acc: u32) -> u32 {
    let mut chunks = data.chunks_exact(2);
    for c in &mut chunks {
        acc = acc.wrapping_add(u16::from_be_bytes([c[0], c[1]]) as u32);
    }
    if let [last] = chunks.remainder() {
        acc = acc.wrapping_add((*last as u32) << 8);
    }
    acc
}

pub fn fold(mut acc: u32) -> u16 {
    while acc >> 16 != 0 {
        acc = (acc & 0xffff) + (acc >> 16);
    }
    !(acc as u16)
}

/// RFC 1071 internet checksum.
pub fn checksum(data: &[u8]) -> u16 {
    fold(sum16(data, 0))
}

fn pseudo_header_sum(src: IpAddr, dst: IpAddr, proto: u8, len: usize) -> u32 {
    let mut acc = 0u32;
    match (src, dst) {
        (IpAddr::V4(s), IpAddr::V4(d)) => {
            acc = sum16(&s.octets(), acc);
            acc = sum16(&d.octets(), acc);
            acc = acc.wrapping_add(proto as u32);
            acc = acc.wrapping_add(len as u32);
        }
        (IpAddr::V6(s), IpAddr::V6(d)) => {
            acc = sum16(&s.octets(), acc);
            acc = sum16(&d.octets(), acc);
            acc = acc.wrapping_add((len as u32) >> 16);
            acc = acc.wrapping_add((len as u32) & 0xffff);
            acc = acc.wrapping_add(proto as u32);
        }
        _ => {}
    }
    acc
}

/// Recompute the IPv4 header checksum in place.
pub fn fix_ipv4_header_checksum(buf: &mut [u8]) {
    if buf.len() < 20 || buf[0] >> 4 != 4 {
        return;
    }
    let ihl = ((buf[0] & 0x0f) as usize) * 4;
    if ihl > buf.len() {
        return;
    }
    buf[10] = 0;
    buf[11] = 0;
    let c = checksum(&buf[..ihl]);
    buf[10..12].copy_from_slice(&c.to_be_bytes());
}

/// Recompute the TCP or UDP checksum in place (IPv4 or IPv6).
pub fn fix_l4_checksum(buf: &mut [u8]) -> Result<()> {
    let v = IpView::parse(buf)?;
    if v.is_fragment_tail {
        return Ok(());
    }
    let o = v.l4_offset;
    let seg_len = v.total_len - o;
    let ck_off = match v.protocol {
        PROTO_TCP if seg_len >= 20 => o + 16,
        PROTO_UDP if seg_len >= 8 => o + 6,
        PROTO_ICMPV6 if seg_len >= 4 => o + 2,
        _ => return Ok(()),
    };
    buf[ck_off] = 0;
    buf[ck_off + 1] = 0;
    let acc = pseudo_header_sum(v.src, v.dst, v.protocol, seg_len);
    let mut c = fold(sum16(&buf[o..v.total_len], acc));
    if v.protocol == PROTO_UDP && c == 0 {
        c = 0xffff;
    }
    buf[ck_off..ck_off + 2].copy_from_slice(&c.to_be_bytes());
    Ok(())
}

/// Verify a TCP/UDP checksum (true when valid).
pub fn verify_l4_checksum(buf: &[u8]) -> bool {
    let Ok(v) = IpView::parse(buf) else {
        return false;
    };
    let o = v.l4_offset;
    let seg_len = v.total_len - o;
    if v.protocol == PROTO_UDP
        && v.version == 4
        && seg_len >= 8
        && buf[o + 6] == 0
        && buf[o + 7] == 0
    {
        return true; // checksum disabled (IPv4 only)
    }
    let acc = pseudo_header_sum(v.src, v.dst, v.protocol, seg_len);
    fold(sum16(&buf[o..v.total_len], acc)) == 0
}

/// Build a complete IPv4 or IPv6 UDP packet with valid checksums.
pub fn build_udp(src: SocketAddr, dst: SocketAddr, payload: &[u8], ttl: u8) -> Result<Vec<u8>> {
    let udp_len = 8 + payload.len();
    match (src.ip(), dst.ip()) {
        (IpAddr::V4(s), IpAddr::V4(d)) => {
            let total = 20 + udp_len;
            if total > u16::MAX as usize {
                return Err(VwError::Packet("udp payload too large"));
            }
            let mut p = vec![0u8; total];
            p[0] = 0x45;
            p[2..4].copy_from_slice(&(total as u16).to_be_bytes());
            p[6] = 0x40; // DF
            p[8] = ttl;
            p[9] = PROTO_UDP;
            p[12..16].copy_from_slice(&s.octets());
            p[16..20].copy_from_slice(&d.octets());
            write_udp(&mut p[20..], src.port(), dst.port(), payload);
            fix_ipv4_header_checksum(&mut p);
            fix_l4_checksum(&mut p)?;
            Ok(p)
        }
        (IpAddr::V6(s), IpAddr::V6(d)) => {
            if udp_len > u16::MAX as usize {
                return Err(VwError::Packet("udp payload too large"));
            }
            let mut p = vec![0u8; 40 + udp_len];
            p[0] = 0x60;
            p[4..6].copy_from_slice(&(udp_len as u16).to_be_bytes());
            p[6] = PROTO_UDP;
            p[7] = ttl;
            p[8..24].copy_from_slice(&s.octets());
            p[24..40].copy_from_slice(&d.octets());
            write_udp(&mut p[40..], src.port(), dst.port(), payload);
            fix_l4_checksum(&mut p)?;
            Ok(p)
        }
        _ => Err(VwError::Packet("address family mismatch")),
    }
}

fn write_udp(seg: &mut [u8], sport: u16, dport: u16, payload: &[u8]) {
    let len = seg.len() as u16;
    seg[0..2].copy_from_slice(&sport.to_be_bytes());
    seg[2..4].copy_from_slice(&dport.to_be_bytes());
    seg[4..6].copy_from_slice(&len.to_be_bytes());
    seg[8..].copy_from_slice(payload);
}

/// Minimal TCP SYN builder (used by tests and canary probes).
pub fn build_tcp_syn(
    src: SocketAddr,
    dst: SocketAddr,
    seq: u32,
    options: &[u8],
    ttl: u8,
) -> Result<Vec<u8>> {
    if options.len() % 4 != 0 || options.len() > 40 {
        return Err(VwError::Packet(
            "tcp options must be 4-byte aligned and <= 40",
        ));
    }
    let tcp_len = 20 + options.len();
    let mut tcp = vec![0u8; tcp_len];
    tcp[0..2].copy_from_slice(&src.port().to_be_bytes());
    tcp[2..4].copy_from_slice(&dst.port().to_be_bytes());
    tcp[4..8].copy_from_slice(&seq.to_be_bytes());
    tcp[12] = ((tcp_len / 4) as u8) << 4;
    tcp[13] = 0x02; // SYN
    tcp[14..16].copy_from_slice(&64240u16.to_be_bytes());
    tcp[20..].copy_from_slice(options);
    let mut p = match (src.ip(), dst.ip()) {
        (IpAddr::V4(s), IpAddr::V4(d)) => {
            let total = 20 + tcp_len;
            let mut p = vec![0u8; total];
            p[0] = 0x45;
            p[2..4].copy_from_slice(&(total as u16).to_be_bytes());
            p[6] = 0x40;
            p[8] = ttl;
            p[9] = PROTO_TCP;
            p[12..16].copy_from_slice(&s.octets());
            p[16..20].copy_from_slice(&d.octets());
            p[20..].copy_from_slice(&tcp);
            fix_ipv4_header_checksum(&mut p);
            p
        }
        (IpAddr::V6(s), IpAddr::V6(d)) => {
            let mut p = vec![0u8; 40 + tcp_len];
            p[0] = 0x60;
            p[4..6].copy_from_slice(&(tcp_len as u16).to_be_bytes());
            p[6] = PROTO_TCP;
            p[7] = ttl;
            p[8..24].copy_from_slice(&s.octets());
            p[24..40].copy_from_slice(&d.octets());
            p[40..].copy_from_slice(&tcp);
            p
        }
        _ => return Err(VwError::Packet("address family mismatch")),
    };
    fix_l4_checksum(&mut p)?;
    Ok(p)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc1071_example() {
        let data = [0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7];
        assert_eq!(checksum(&data), !0xddf2u16);
    }

    #[test]
    fn udp_v4_roundtrip() {
        let s: SocketAddr = "100.96.0.2:5000".parse().unwrap();
        let d: SocketAddr = "203.0.113.99:53".parse().unwrap();
        let p = build_udp(s, d, b"hello", 64).unwrap();
        let v = IpView::parse(&p).unwrap();
        assert_eq!(v.protocol, PROTO_UDP);
        assert_eq!(v.src_sock(&p), Some(s));
        assert_eq!(v.dst_sock(&p), Some(d));
        assert_eq!(v.udp_payload(&p), Some(&b"hello"[..]));
        assert_eq!(checksum(&p[..20]), 0);
        assert!(verify_l4_checksum(&p));
    }

    #[test]
    fn udp_v6_roundtrip() {
        let s: SocketAddr = "[fd00:564f:4944:1::2]:5000".parse().unwrap();
        let d: SocketAddr = "[2001:db8::1]:443".parse().unwrap();
        let p = build_udp(s, d, &[0xAB; 33], 64).unwrap();
        let v = IpView::parse(&p).unwrap();
        assert_eq!(v.version, 6);
        assert_eq!(v.udp_payload(&p).unwrap().len(), 33);
        assert!(verify_l4_checksum(&p));
    }

    #[test]
    fn tcp_syn_checksum() {
        let s: SocketAddr = "10.0.0.2:40000".parse().unwrap();
        let d: SocketAddr = "93.184.216.34:443".parse().unwrap();
        let opts = [2, 4, 0x05, 0xb4, 1, 1, 1, 0];
        let p = build_tcp_syn(s, d, 1, &opts, 128).unwrap();
        assert!(verify_l4_checksum(&p));
        let mut bad = p.clone();
        bad[30] ^= 0xff;
        assert!(!verify_l4_checksum(&bad));
    }

    #[test]
    fn rejects_garbage() {
        assert!(IpView::parse(&[]).is_err());
        assert!(IpView::parse(&[0x45; 10]).is_err());
        assert!(IpView::parse(&[0x00; 40]).is_err());
    }
}
