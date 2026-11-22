//! IP-level links to a hop's network and the protocols spoken over them:
//! VWCP (PQ handshake, F2F redemption, attestation) and ICMP echo probes.
//!
//! * [`DirectSession`]: a standalone sans-IO WireGuard peer over its own
//!   transport (optimizer probes, invite redemption).
//! * [`TunnelLink`]: hop `n` of the live cascade; replies arrive through the
//!   pipeline's [`ControlBus`].

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant as StdInstant};

use async_trait::async_trait;
use tokio::sync::broadcast;
use tokio::time::Instant;
use vw_core::config::Bytes32;
use vw_core::consts::{NODE_GATEWAY_V4, TTL_NORMAL, VWCP_PORT};
use vw_core::packet::{build_udp, IpView, PROTO_UDP};
use vw_core::secret::SecretVec;
use vw_core::transport::StealthTransport;
use vw_core::{Result, VwError};
use vw_crypto::blind::{finalize, prepare_token, TokenPublicKey};
use vw_crypto::vwcp::{
    AttestRequest, AttestResponse, ClientHandshake, ErrorMsg, MsgType, PqSession, Reassembler,
    RedeemRequest, RedeemResponse,
};
use vw_wg::{Cascade, Decapsulated, Engine, Peer};

use crate::pipeline::ControlBus;
use crate::util::{icmp_echo, icmp_echo_fields};

/// Something that carries plaintext IP packets to a hop's network.
#[async_trait]
pub trait IpLink: Send {
    async fn send(&mut self, pkt: &[u8]) -> Result<()>;
    /// Next packet from the hop network, or `None` at the deadline.
    async fn recv(&mut self, deadline: Instant) -> Option<Vec<u8>>;
}

async fn send_wire(t: &dyn StealthTransport, datagrams: Vec<Vec<u8>>) -> Result<()> {
    for d in datagrams {
        if vw_wg::noise::is_handshake_initiation(&d) {
            t.before_handshake().await?;
        }
        t.send(&d).await?;
    }
    Ok(())
}

// ───────────────────────────── DirectSession ─────────────────────────────

/// One WireGuard peer over a dedicated transport, driven inline.
pub struct DirectSession {
    pub peer: Peer,
    pub transport: Box<dyn StealthTransport>,
    buf: Vec<u8>,
}

impl DirectSession {
    pub fn new(peer: Peer, transport: Box<dyn StealthTransport>) -> Self {
        Self {
            peer: peer.with_auto_connect(false),
            transport,
            buf: vec![0u8; 65_535],
        }
    }

    /// Complete a WireGuard handshake: up to `attempts` initiations, each
    /// waiting `per_attempt`. Returns the latency of the successful attempt.
    pub async fn handshake(&mut self, attempts: u32, per_attempt: Duration) -> Result<Duration> {
        for _ in 0..attempts.max(1) {
            let start = Instant::now();
            let Some(init) = self.peer.initiate_handshake(StdInstant::now()) else {
                return Err(VwError::Transport(
                    "cannot create handshake initiation".into(),
                ));
            };
            send_wire(self.transport.as_ref(), vec![init]).await?;
            let deadline = start + per_attempt;
            while Instant::now() < deadline {
                if self.pump(deadline).await.is_none() && Instant::now() >= deadline {
                    break;
                }
                if self.peer.session_established() && !self.peer.handshake_in_progress() {
                    return Ok(start.elapsed());
                }
            }
        }
        Err(VwError::Timeout)
    }

    /// Receive and process one datagram; returns a tunnel packet if any.
    async fn pump(&mut self, deadline: Instant) -> Option<Option<Vec<u8>>> {
        let n = match tokio::time::timeout_at(deadline, self.transport.recv(&mut self.buf)).await {
            Ok(Ok(n)) => n,
            _ => return None,
        };
        let now = StdInstant::now();
        let r = self.peer.decapsulate(&self.buf[..n], now);
        let mut out = self.peer.drain_outbox();
        let pkt = match r {
            Ok(Decapsulated::Network(d)) => {
                out.extend(d);
                None
            }
            Ok(Decapsulated::Tunnel(p)) => Some(p),
            _ => None,
        };
        if let Err(e) = send_wire(self.transport.as_ref(), out).await {
            tracing::debug!(error = %e, "probe send failed");
        }
        Some(pkt)
    }

    pub async fn close(self) {
        let _ = self.transport.close().await;
    }
}

#[async_trait]
impl IpLink for DirectSession {
    async fn send(&mut self, pkt: &[u8]) -> Result<()> {
        let d = self.peer.encapsulate(pkt, StdInstant::now());
        send_wire(self.transport.as_ref(), d).await
    }

    async fn recv(&mut self, deadline: Instant) -> Option<Vec<u8>> {
        loop {
            match self.pump(deadline).await {
                None => return None,
                Some(Some(p)) => return Some(p),
                Some(None) => continue,
            }
        }
    }
}

// ───────────────────────────── TunnelLink ─────────────────────────────

/// Hop `hop` of the live cascade.
pub struct TunnelLink {
    pub engine: Arc<Mutex<Cascade>>,
    pub transport: Arc<dyn StealthTransport>,
    pub hop: usize,
    rx: broadcast::Receiver<(usize, Vec<u8>)>,
    bus: ControlBus,
    claimed: Vec<u16>,
}

impl TunnelLink {
    pub fn new(
        engine: Arc<Mutex<Cascade>>,
        transport: Arc<dyn StealthTransport>,
        hop: usize,
        bus: &ControlBus,
    ) -> Self {
        Self {
            engine,
            transport,
            hop,
            rx: bus.subscribe(),
            bus: bus.clone(),
            claimed: Vec::new(),
        }
    }

    /// Divert ICMP echo replies with `id` to this link.
    pub fn claim_icmp(&mut self, id: u16) {
        self.bus.claim_icmp(id);
        self.claimed.push(id);
    }
}

impl Drop for TunnelLink {
    fn drop(&mut self) {
        for id in &self.claimed {
            self.bus.release_icmp(*id);
        }
    }
}

#[async_trait]
impl IpLink for TunnelLink {
    async fn send(&mut self, pkt: &[u8]) -> Result<()> {
        let d = {
            let mut e = self.engine.lock().unwrap_or_else(|p| p.into_inner());
            e.outbound_at(self.hop, pkt, StdInstant::now())
        };
        send_wire(self.transport.as_ref(), d).await
    }

    async fn recv(&mut self, deadline: Instant) -> Option<Vec<u8>> {
        loop {
            match tokio::time::timeout_at(deadline, self.rx.recv()).await {
                Ok(Ok((hop, p))) if hop == self.hop => return Some(p),
                Ok(Ok(_)) | Ok(Err(broadcast::error::RecvError::Lagged(_))) => continue,
                _ => return None,
            }
        }
    }
}

// ───────────────────────────── VWCP ─────────────────────────────

fn gateway() -> SocketAddr {
    SocketAddr::new(IpAddr::V4(NODE_GATEWAY_V4), VWCP_PORT)
}

/// Send VWCP datagrams from `src` and wait for one complete message of `want`.
async fn vwcp_exchange(
    link: &mut dyn IpLink,
    src: SocketAddr,
    datagrams: &[Vec<u8>],
    want: MsgType,
    timeout: Duration,
) -> Result<Vec<u8>> {
    let deadline = Instant::now() + timeout;
    let mut reasm = Reassembler::new();
    let resend_every = Duration::from_millis(1500);
    'outer: loop {
        for d in datagrams {
            link.send(&build_udp(src, gateway(), d, TTL_NORMAL)?)
                .await?;
        }
        let round_end = (Instant::now() + resend_every).min(deadline);
        while let Some(pkt) = link.recv(round_end).await {
            let Ok(v) = IpView::parse(&pkt) else { continue };
            if v.protocol != PROTO_UDP
                || v.src_sock(&pkt) != Some(gateway())
                || v.dst_sock(&pkt) != Some(src)
            {
                continue;
            }
            let Some(payload) = v.udp_payload(&pkt) else {
                continue;
            };
            match reasm.push(payload, StdInstant::now()) {
                Ok(Some(m)) if m.ty == want => return Ok(m.body),
                Ok(Some(m)) if m.ty == MsgType::Error => {
                    let e = ErrorMsg::decode(&m.body)
                        .map(|e| format!("node error {}: {}", e.code, e.reason))
                        .unwrap_or_else(|_| "malformed node error".into());
                    return Err(VwError::Transport(e));
                }
                _ => {}
            }
        }
        if Instant::now() >= deadline {
            break 'outer;
        }
    }
    Err(VwError::Timeout)
}

/// Run one VWCP exchange (ARCHITECTURE.md §6) and return the PQ session.
pub async fn vwcp_handshake(
    link: &mut dyn IpLink,
    src: SocketAddr,
    identity: Bytes32,
    epoch: u32,
    token: Vec<u8>,
    timeout: Duration,
) -> Result<PqSession> {
    let token = zeroize::Zeroizing::new(token);
    let (mut hs, hello) = ClientHandshake::start(identity, epoch, token.to_vec())
        .map_err(|e| VwError::Crypto(crypto_msg(&e)))?;
    let sh = vwcp_exchange(link, src, &hello, MsgType::ServerHello, timeout).await?;
    let kem = hs
        .on_server_hello(&sh)
        .map_err(|e| VwError::Crypto(crypto_msg(&e)))?;
    let ack = vwcp_exchange(link, src, &kem, MsgType::ServerAck, timeout).await?;
    hs.on_server_ack(&ack)
        .map_err(|e| VwError::Crypto(crypto_msg(&e)))
}

fn crypto_msg(e: &vw_crypto::CryptoError) -> &'static str {
    use vw_crypto::CryptoError as C;
    match e {
        C::BadSignature => "VWCP: node signature invalid",
        C::BadConfirm => "VWCP: key confirmation failed",
        C::SessionMismatch => "VWCP: session mismatch",
        C::Epoch { .. } => "VWCP: epoch rejected",
        C::TokenRejected(_) => "VWCP: token rejected",
        _ => "VWCP: protocol error",
    }
}

/// AttestRequest → encoded `SignedAttestation`.
pub async fn vwcp_attest(
    link: &mut dyn IpLink,
    src: SocketAddr,
    nonce: [u8; 32],
    timeout: Duration,
) -> Result<Vec<u8>> {
    let d = AttestRequest { nonce }
        .datagrams()
        .map_err(|e| VwError::Crypto(crypto_msg(&e)))?;
    let body = vwcp_exchange(link, src, &d, MsgType::AttestResponse, timeout).await?;
    let r = AttestResponse::decode(&body).map_err(|e| VwError::Crypto(crypto_msg(&e)))?;
    r.attestation
        .encode()
        .map_err(|e| VwError::Crypto(crypto_msg(&e)))
}

/// Redeem an invite-admitted session for `count` blind session tokens
/// (ARCHITECTURE.md §8.1). Returns encoded `0x01 || SessionToken` blobs.
pub async fn vwcp_redeem(
    link: &mut dyn IpLink,
    src: SocketAddr,
    pk: &TokenPublicKey,
    count: u8,
    timeout: Duration,
) -> Result<Vec<SecretVec>> {
    let count = count.clamp(1, 32);
    let mut reqs = Vec::new();
    let mut pending = Vec::new();
    for _ in 0..count {
        let (r, p) = prepare_token(pk).map_err(|e| VwError::Crypto(crypto_msg(&e)))?;
        reqs.push(r);
        pending.push(p);
    }
    let d = RedeemRequest { blinded: reqs }
        .datagrams()
        .map_err(|e| VwError::Crypto(crypto_msg(&e)))?;
    let body = vwcp_exchange(link, src, &d, MsgType::RedeemResponse, timeout).await?;
    let resp = RedeemResponse::decode(&body).map_err(|e| VwError::Crypto(crypto_msg(&e)))?;
    if resp.blind_sigs.len() != pending.len() || resp.tier != pk.tier() {
        return Err(VwError::Crypto("redeem response does not match request"));
    }
    let mut out = Vec::new();
    for (p, sig) in pending.into_iter().zip(resp.blind_sigs.iter()) {
        let tok = finalize(p, sig).map_err(|e| VwError::Crypto(crypto_msg(&e)))?;
        let mut blob = vec![0x01];
        blob.extend_from_slice(&tok.encode());
        out.push(SecretVec::new(blob));
    }
    Ok(out)
}

// ───────────────────────────── ICMP probes ─────────────────────────────

/// Results of an echo series.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct EchoStats {
    pub sent: u32,
    pub rtts_ms: Vec<f64>,
}

impl EchoStats {
    pub fn loss(&self) -> f64 {
        if self.sent == 0 {
            return 1.0;
        }
        1.0 - self.rtts_ms.len() as f64 / self.sent as f64
    }

    pub fn mean_rtt(&self) -> Option<f64> {
        (!self.rtts_ms.is_empty())
            .then(|| self.rtts_ms.iter().sum::<f64>() / self.rtts_ms.len() as f64)
    }

    /// Mean absolute difference of consecutive RTTs (RFC 3550 style).
    pub fn jitter(&self) -> Option<f64> {
        (self.rtts_ms.len() >= 2).then(|| {
            let d: f64 = self.rtts_ms.windows(2).map(|w| (w[1] - w[0]).abs()).sum();
            d / (self.rtts_ms.len() - 1) as f64
        })
    }
}

/// `count` sequential echo requests, each waiting up to `per_probe`.
pub async fn echo_series(
    link: &mut dyn IpLink,
    src: Ipv4Addr,
    dst: Ipv4Addr,
    id: u16,
    count: u16,
    per_probe: Duration,
) -> Result<EchoStats> {
    let mut st = EchoStats::default();
    for seq in 0..count {
        let start = Instant::now();
        link.send(&icmp_echo(src, dst, id, seq, 56)).await?;
        st.sent += 1;
        let deadline = start + per_probe;
        while let Some(p) = link.recv(deadline).await {
            if icmp_echo_fields(&p) == Some((0, id, seq)) {
                st.rtts_ms.push(start.elapsed().as_secs_f64() * 1000.0);
                break;
            }
        }
    }
    Ok(st)
}

/// Packet-train dispersion estimate: `n` back-to-back echoes of `ip_len`
/// bytes; throughput = bits between first and last reply / their spacing.
pub async fn packet_train(
    link: &mut dyn IpLink,
    src: Ipv4Addr,
    dst: Ipv4Addr,
    id: u16,
    n: u16,
    ip_len: usize,
    wait: Duration,
) -> Result<Option<f64>> {
    let payload = ip_len.saturating_sub(28).max(8);
    for seq in 0..n {
        link.send(&icmp_echo(src, dst, id, 1000 + seq, payload))
            .await?;
    }
    let deadline = Instant::now() + wait;
    let mut arrivals = Vec::new();
    while let Some(p) = link.recv(deadline).await {
        if let Some((0, pid, seq)) = icmp_echo_fields(&p) {
            if pid == id && (1000..1000 + n).contains(&seq) {
                arrivals.push(Instant::now());
                if arrivals.len() == n as usize {
                    break;
                }
            }
        }
    }
    Ok(dispersion_mbps(&arrivals, payload + 28))
}

/// Throughput from reply arrival times of equal-size packets.
pub fn dispersion_mbps(arrivals: &[Instant], pkt_len: usize) -> Option<f64> {
    if arrivals.len() < 2 {
        return None;
    }
    let span = arrivals[arrivals.len() - 1]
        .duration_since(arrivals[0])
        .as_secs_f64()
        // Below timer resolution: bound by 1 µs per packet.
        .max(1e-6 * (arrivals.len() - 1) as f64);
    let bits = (arrivals.len() - 1) as f64 * pkt_len as f64 * 8.0;
    Some(bits / span / 1e6)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn echo_stats() {
        let s = EchoStats {
            sent: 4,
            rtts_ms: vec![10.0, 12.0, 11.0],
        };
        assert!((s.loss() - 0.25).abs() < 1e-9);
        assert_eq!(s.mean_rtt(), Some(11.0));
        assert_eq!(s.jitter(), Some(1.5));
        assert_eq!(EchoStats::default().loss(), 1.0);
    }

    #[test]
    fn dispersion() {
        let t0 = Instant::now();
        let a = [
            t0,
            t0 + Duration::from_millis(1),
            t0 + Duration::from_millis(2),
        ];
        // 2 × 1250 B × 8 bit over 2 ms = 10 Mbit/s
        let m = dispersion_mbps(&a, 1250).unwrap();
        assert!((m - 10.0).abs() < 1e-6);
        assert!(dispersion_mbps(&a[..1], 1250).is_none());
    }
}
