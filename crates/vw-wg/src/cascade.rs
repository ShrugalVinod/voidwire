//! Userspace multi-hop ("cascade"): each inner hop's WireGuard datagrams are
//! wrapped in IPv4/IPv6 UDP packets addressed to that hop's endpoint and sent
//! as plaintext through the hop outside it (ARCHITECTURE.md §7).
//!
//! With hops `[H1, H2]`, H1 only ever sees UDP packets to H2's endpoint
//! (never the real destination), and H2 sees the destination but only H1's
//! address as the source (never the client's).

use std::net::SocketAddr;
use std::time::Instant;

use vw_core::consts::TTL_NORMAL;
use vw_core::packet::{build_udp, IpView};

use crate::error::WgError;
use crate::peer::{Decapsulated, Peer};

/// One hop of a cascade.
#[derive(Debug)]
pub struct CascadeHop {
    pub peer: Peer,
    /// UDP endpoint of this hop as reachable from the previous hop's exit
    /// (informational for hop 0, whose endpoint is the transport's remote).
    pub endpoint: SocketAddr,
    /// Our source address inside the previous hop's tunnel (the tunnel address
    /// assigned by that hop, plus a local port). Unused for hop 0.
    pub via_src: SocketAddr,
}

impl CascadeHop {
    pub fn new(peer: Peer, endpoint: SocketAddr, via_src: SocketAddr) -> Self {
        Self {
            peer,
            endpoint,
            via_src,
        }
    }
}

/// Result of [`Cascade::decapsulate`].
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct CascadeOutput {
    /// Datagrams for the wire (already wrapped by every outer hop).
    pub network: Vec<Vec<u8>>,
    /// Plaintext packets with the hop index they were decrypted at. Packets
    /// from the innermost hop are user traffic; others are hop-local control
    /// traffic (e.g. VWCP with that hop's gateway).
    pub delivered: Vec<(usize, Vec<u8>)>,
    pub chaff: usize,
    pub errors: usize,
}

/// An ordered list of hops: `hops[0]` is the outermost (entry) session.
#[derive(Debug)]
pub struct Cascade {
    hops: Vec<CascadeHop>,
}

impl Cascade {
    pub fn new(hops: Vec<CascadeHop>) -> Result<Self, WgError> {
        if hops.is_empty() {
            return Err(WgError::EmptyCascade);
        }
        Ok(Self { hops })
    }

    pub fn hops(&self) -> &[CascadeHop] {
        &self.hops
    }

    pub fn hop_mut(&mut self, i: usize) -> Option<&mut CascadeHop> {
        self.hops.get_mut(i)
    }

    pub fn len(&self) -> usize {
        self.hops.len()
    }

    pub fn is_empty(&self) -> bool {
        self.hops.is_empty()
    }

    fn last(&self) -> usize {
        self.hops.len() - 1
    }

    /// True when every hop has a session.
    pub fn established(&self) -> bool {
        self.hops.iter().all(|h| h.peer.session_established())
    }

    /// Encrypt user traffic through every hop (innermost first).
    pub fn encapsulate(&mut self, plaintext: &[u8], now: Instant) -> Vec<Vec<u8>> {
        self.encapsulate_at(self.last(), plaintext, now)
    }

    /// Encrypt a packet for hop `hop`'s own network (control traffic to that
    /// hop's gateway), then wrap it through the hops outside it.
    pub fn encapsulate_at(&mut self, hop: usize, plaintext: &[u8], now: Instant) -> Vec<Vec<u8>> {
        let hop = hop.min(self.last());
        let d = self.hops[hop].peer.encapsulate(plaintext, now);
        self.descend(hop, d, now)
    }

    /// Wrap datagrams produced by hop `from` through hops `from-1 .. 0`.
    fn descend(&mut self, from: usize, mut datagrams: Vec<Vec<u8>>, now: Instant) -> Vec<Vec<u8>> {
        for i in (0..from).rev() {
            let (src, dst) = (self.hops[i + 1].via_src, self.hops[i + 1].endpoint);
            let mut out = Vec::with_capacity(datagrams.len());
            for d in datagrams {
                match build_udp(src, dst, &d, TTL_NORMAL) {
                    Ok(wrapped) => out.extend(self.hops[i].peer.encapsulate(&wrapped, now)),
                    Err(e) => {
                        tracing::debug!(error = %e, hop = i + 1, "cannot wrap cascade datagram")
                    }
                }
            }
            datagrams = out;
        }
        datagrams
    }

    fn unwrap_for(&self, hop: usize, pkt: &[u8]) -> Option<Vec<u8>> {
        let next = self.hops.get(hop + 1)?;
        let v = IpView::parse(pkt).ok()?;
        if v.src_sock(pkt)? != next.endpoint || v.dst != next.via_src.ip() {
            return None;
        }
        v.udp_payload(pkt).map(<[u8]>::to_vec)
    }

    /// Process one datagram from the wire, peeling hops outermost first.
    pub fn decapsulate(&mut self, datagram: &[u8], now: Instant) -> CascadeOutput {
        let mut out = CascadeOutput::default();
        let mut current = datagram.to_vec();
        let mut hop = 0;
        loop {
            match self.hops[hop].peer.decapsulate(&current, now) {
                Ok(Decapsulated::Network(d)) => {
                    out.network.extend(self.descend(hop, d, now));
                }
                Ok(Decapsulated::Tunnel(pkt)) => {
                    if let Some(inner) = self.unwrap_for(hop, &pkt) {
                        current = inner;
                        hop += 1;
                        continue;
                    }
                    out.delivered.push((hop, pkt));
                }
                Ok(Decapsulated::Chaff) => out.chaff += 1,
                Ok(Decapsulated::Keepalive | Decapsulated::None) => {}
                Err(e) => {
                    tracing::trace!(error = %e, hop, "cascade datagram rejected");
                    out.errors += 1;
                }
            }
            break;
        }
        for i in 0..self.hops.len() {
            let d = self.hops[i].peer.drain_outbox();
            if !d.is_empty() {
                out.network.extend(self.descend(i, d, now));
            }
        }
        out
    }

    /// Run every hop's timers (innermost first) and wrap their output.
    pub fn tick(&mut self, now: Instant) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        for i in (0..self.hops.len()).rev() {
            let d = self.hops[i].peer.tick(now);
            if !d.is_empty() {
                out.extend(self.descend(i, d, now));
            }
        }
        out
    }

    /// DAITA chaff on the outermost session.
    pub fn make_chaff(&mut self, size: usize, now: Instant) -> Option<Vec<u8>> {
        self.hops[0].peer.make_chaff(size, now)
    }

    pub fn handshakes_completed(&self) -> u64 {
        self.hops
            .iter()
            .map(|h| h.peer.handshakes_completed())
            .sum()
    }
}
