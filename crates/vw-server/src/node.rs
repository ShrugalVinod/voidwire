//! The sans-IO node core: WireGuard responder + VWCP admission + forwarding
//! decisions (ARCHITECTURE.md §6, §8.1).
//!
//! [`NodeCore`] is generic over the remote handle type `R` (the runtime uses
//! [`crate::listeners::Remote`], tests use plain integers). Every input
//! returns a list of [`Action`]s for the I/O layer to perform; time is passed
//! in explicitly.
//!
//! Per WireGuard peer (keyed by its static key) the admission state machine is:
//!
//! ```text
//! Unadmitted ──ClientHello(token ok)──► Handshaking ──ClientKem(confirm ok)──► Admitted
//!     ▲  only UDP to NODE_GATEWAY:VWCP_PORT                    │ ClientHello(epoch+1): rotation
//!     └───────── WireGuard peer evicted by the responder ◄─────┘
//! ```
//!
//! Unadmitted peers may only talk VWCP to the gateway; nothing is forwarded.
//! Admitted peers' packets go to the TUN after anti-spoofing (source must be
//! the assigned address), the no-client-to-client rule and the token bucket.

use std::collections::{HashMap, HashSet, VecDeque};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::{Duration, Instant};

use vw_core::consts::{
    CLIENT_POOL_V4, CLIENT_POOL_V6, NODE_GATEWAY_V4, NODE_GATEWAY_V6, PQ_ROTATE_SECS, TTL_NORMAL,
    VWCP_PORT,
};
use vw_core::packet::{build_udp, IpView, PROTO_UDP};
use vw_core::secret::Key32;
use vw_core::{Result, VwError};
use vw_crypto::attest::{AttestationReport, SignedAttestation};
use vw_crypto::blind::{blind_sign, SessionToken};
use vw_crypto::identity::NodeIdentity;
use vw_crypto::invite::Invite;
use vw_crypto::vwcp::{
    error_code, Assignment, AttestRequest, AttestResponse, ErrorMsg, MsgType, Reassembler,
    RedeemRequest, RedeemResponse, ServerHandshake, TokenGrant,
};
use vw_crypto::CryptoError;
use vw_wg::{Admission, Decapsulated, Responder};

use crate::admission::{
    invite_hash, parse_token, tier, tier_for_bandwidth, AddressPool, InviteEntry, InviteTable,
    Issuers, SpentLedger, Tier, TokenClaim, OWNER_TIER,
};
use crate::attestation::Facts;
use crate::bandwidth::TokenBucket;
use crate::icmp;

/// ClientHellos accepted per peer per [`HELLO_WINDOW`].
pub const MAX_HELLOS_PER_WINDOW: usize = 8;
pub const HELLO_WINDOW: Duration = Duration::from_secs(60);
/// A VWCP exchange must finish within this time after the ClientHello.
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// Default cap on auto-created (non-owner) WireGuard peers.
pub const DEFAULT_MAX_PEERS: usize = 1024;

/// Work for the I/O layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action<R> {
    /// Send a WireGuard datagram to a remote.
    Send { to: R, datagram: Vec<u8> },
    /// Write a plaintext IP packet to the node TUN (towards the Internet).
    Tun(Vec<u8>),
}

/// Drop / event counters (no identifying data).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Stats {
    pub wg_rejected: u64,
    pub unadmitted_dropped: u64,
    pub spoofed_dropped: u64,
    pub client_to_client_dropped: u64,
    pub rate_limited_dropped: u64,
    pub no_route_dropped: u64,
    pub admissions: u64,
    pub rotations: u64,
    pub vwcp_errors: u64,
    pub echo_replies: u64,
    pub forwarded_up: u64,
    pub forwarded_down: u64,
}

/// How a peer was admitted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdmitKind {
    Owner,
    SessionToken,
    Invite,
}

enum Claim {
    Owner,
    Session(SessionToken),
    Invite([u8; 32]),
    Rotation,
}

struct Pending {
    hs: ServerHandshake,
    claim: Claim,
    started: Instant,
}

enum Redeem {
    NotAllowed,
    Available,
    Done {
        request_hash: [u8; 32],
        response: Vec<Vec<u8>>,
    },
}

struct Admitted {
    kind: AdmitKind,
    tier: u8,
    bandwidth_bps: u64,
    addr_idx: u32,
    v4: Ipv4Addr,
    v6: Ipv6Addr,
    epoch: u32,
    handshakes_at_install: u64,
    up: TokenBucket,
    down: TokenBucket,
    redeem: Redeem,
}

struct PeerState<R> {
    remote: Option<R>,
    reasm: Reassembler,
    pending: Option<Pending>,
    session: Option<Admitted>,
    hellos: VecDeque<Instant>,
}

impl<R> PeerState<R> {
    fn new() -> Self {
        Self {
            remote: None,
            reasm: Reassembler::new(),
            pending: None,
            session: None,
            hellos: VecDeque::new(),
        }
    }
}

/// Static configuration of the core.
pub struct CoreConfig {
    /// WireGuard static private key.
    pub wg_key: Key32,
    /// Ed25519 node identity.
    pub identity: NodeIdentity,
    /// Owner WireGuard public keys (`--authorize`).
    pub owners: Vec<[u8; 32]>,
    /// Blind-token issuer keys.
    pub issuers: Issuers,
    /// Spent-token ledger.
    pub ledger: SpentLedger,
    /// Cap on auto-created WireGuard peers.
    pub max_peers: usize,
}

type FactsFn = Box<dyn Fn() -> Facts + Send>;
type ClockFn = Box<dyn Fn() -> u64 + Send>;

/// The node's protocol state.
pub struct NodeCore<R> {
    identity: NodeIdentity,
    responder: Responder,
    owners: HashSet<[u8; 32]>,
    issuers: Issuers,
    ledger: SpentLedger,
    invites: InviteTable,
    pool: AddressPool,
    peers: HashMap<[u8; 32], PeerState<R>>,
    by_v4: HashMap<Ipv4Addr, [u8; 32]>,
    by_v6: HashMap<Ipv6Addr, [u8; 32]>,
    facts: FactsFn,
    unix_now: ClockFn,
    stats: Stats,
}

/// Current Unix time in seconds.
pub fn system_unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn in_pool_v4(a: Ipv4Addr) -> bool {
    let mask = u32::MAX << (32 - CLIENT_POOL_V4.1);
    u32::from(a) & mask == u32::from(CLIENT_POOL_V4.0)
}

fn in_pool_v6(a: Ipv6Addr) -> bool {
    let mask = u128::MAX << (128 - CLIENT_POOL_V6.1);
    u128::from(a) & mask == u128::from(CLIENT_POOL_V6.0)
}

/// True if `a` is inside the client pools (used for the no-client-to-client rule).
pub fn in_client_pool(a: IpAddr) -> bool {
    match a {
        IpAddr::V4(a) => in_pool_v4(a),
        IpAddr::V6(a) => in_pool_v6(a),
    }
}

impl<R: Clone> NodeCore<R> {
    pub fn new(cfg: CoreConfig, facts: FactsFn) -> Self {
        let mut responder = Responder::new(
            cfg.wg_key,
            Admission::AcceptUnknown {
                max_unknown: cfg.max_peers.max(1),
            },
        );
        for k in &cfg.owners {
            responder.add_peer(*k, None, [0; 3]);
        }
        Self {
            identity: cfg.identity,
            responder,
            owners: cfg.owners.into_iter().collect(),
            issuers: cfg.issuers,
            ledger: cfg.ledger,
            invites: InviteTable::default(),
            pool: AddressPool::new(),
            peers: HashMap::new(),
            by_v4: HashMap::new(),
            by_v6: HashMap::new(),
            facts,
            unix_now: Box::new(system_unix_now),
            stats: Stats::default(),
        }
    }

    /// Replace the wall clock (tests).
    pub fn set_clock(&mut self, f: impl Fn() -> u64 + Send + 'static) {
        self.unix_now = Box::new(f);
    }

    pub fn stats(&self) -> &Stats {
        &self.stats
    }

    pub fn identity(&self) -> &NodeIdentity {
        &self.identity
    }

    pub fn wg_public(&self) -> [u8; 32] {
        *self.responder.public_key()
    }

    pub fn issuers(&self) -> &Issuers {
        &self.issuers
    }

    pub fn responder(&self) -> &Responder {
        &self.responder
    }

    pub fn outstanding_invites(&self) -> usize {
        self.invites.len()
    }

    pub fn admitted_count(&self) -> usize {
        self.peers.values().filter(|p| p.session.is_some()).count()
    }

    /// How a peer was admitted, if it is.
    pub fn admission_of(&self, key: &[u8; 32]) -> Option<AdmitKind> {
        self.peers.get(key)?.session.as_ref().map(|s| s.kind)
    }

    /// Assigned tunnel addresses of an admitted peer.
    pub fn assigned(&self, key: &[u8; 32]) -> Option<(Ipv4Addr, Ipv6Addr)> {
        let s = self.peers.get(key)?.session.as_ref()?;
        Some((s.v4, s.v6))
    }

    /// Bandwidth tier and limit of an admitted peer.
    pub fn grant_of(&self, key: &[u8; 32]) -> Option<(u8, u64)> {
        let s = self.peers.get(key)?.session.as_ref()?;
        Some((s.tier, s.bandwidth_bps))
    }

    /// Process one WireGuard datagram from `from` (`src` = outer address,
    /// used only for cookie replies under load).
    pub fn on_datagram(
        &mut self,
        from: R,
        src: Option<SocketAddr>,
        datagram: &[u8],
        now: Instant,
    ) -> Vec<Action<R>> {
        let routed = match self.responder.decapsulate(src, datagram, now) {
            Ok(r) => r,
            Err(e) => {
                self.stats.wg_rejected += 1;
                tracing::trace!("wireguard datagram rejected: {}", e.as_str());
                return Vec::new();
            }
        };
        let mut out = Vec::new();
        let Some(key) = routed.peer else {
            if let Decapsulated::Network(ds) = routed.result {
                out.extend(ds.into_iter().map(|d| Action::Send {
                    to: from.clone(),
                    datagram: d,
                }));
            }
            return out;
        };
        let st = self.peers.entry(key).or_insert_with(PeerState::new);
        // Roaming: replies go to wherever the peer last sent an authenticated
        // datagram from.
        st.remote = Some(from.clone());
        match routed.result {
            Decapsulated::Network(ds) => {
                out.extend(ds.into_iter().map(|d| Action::Send {
                    to: from.clone(),
                    datagram: d,
                }));
            }
            Decapsulated::Tunnel(pkt) => self.on_inner(key, &pkt, now, &mut out),
            Decapsulated::Keepalive | Decapsulated::Chaff | Decapsulated::None => {}
        }
        if let Some(p) = self.responder.peer_mut(&key) {
            let extra = p.drain_outbox();
            out.extend(extra.into_iter().map(|d| Action::Send {
                to: from.clone(),
                datagram: d,
            }));
        }
        out
    }

    /// Route one packet read from the node TUN to the peer owning its destination.
    pub fn on_tun_packet(&mut self, pkt: &[u8], now: Instant) -> Vec<Action<R>> {
        let Ok(v) = IpView::parse(pkt) else {
            return Vec::new();
        };
        let key = match v.dst {
            IpAddr::V4(a) => self.by_v4.get(&a).copied(),
            IpAddr::V6(a) => self.by_v6.get(&a).copied(),
        };
        let Some(key) = key else {
            self.stats.no_route_dropped += 1;
            return Vec::new();
        };
        let Some(st) = self.peers.get_mut(&key) else {
            return Vec::new();
        };
        let (Some(sess), Some(remote)) = (st.session.as_mut(), st.remote.clone()) else {
            return Vec::new();
        };
        if !sess.down.try_consume(pkt.len(), now) {
            self.stats.rate_limited_dropped += 1;
            return Vec::new();
        }
        self.stats.forwarded_down += 1;
        self.encapsulate_to(&key, remote, pkt, now)
    }

    fn encapsulate_to(
        &mut self,
        key: &[u8; 32],
        to: R,
        pkt: &[u8],
        now: Instant,
    ) -> Vec<Action<R>> {
        match self.responder.encapsulate(key, pkt, now) {
            Ok(ds) => ds
                .into_iter()
                .map(|d| Action::Send {
                    to: to.clone(),
                    datagram: d,
                })
                .collect(),
            Err(_) => Vec::new(),
        }
    }

    /// Run timers: WireGuard retransmits/keepalives, evictions, timeouts.
    pub fn tick(&mut self, now: Instant) -> Vec<Action<R>> {
        let mut out = Vec::new();
        for (key, ds) in self.responder.tick(now) {
            if let Some(remote) = self.peers.get(&key).and_then(|p| p.remote.clone()) {
                out.extend(ds.into_iter().map(|d| Action::Send {
                    to: remote.clone(),
                    datagram: d,
                }));
            }
        }
        // Peers the responder evicted lose their admission and addresses.
        let gone: Vec<[u8; 32]> = self
            .peers
            .keys()
            .filter(|k| self.responder.peer(k).is_none())
            .copied()
            .collect();
        for k in gone {
            self.drop_peer(&k);
        }
        for st in self.peers.values_mut() {
            if st
                .pending
                .as_ref()
                .is_some_and(|p| now.saturating_duration_since(p.started) >= HANDSHAKE_TIMEOUT)
            {
                st.pending = None;
            }
            st.reasm.expire(now);
        }
        let unix = (self.unix_now)();
        self.invites.expire(unix);
        out
    }

    fn drop_peer(&mut self, key: &[u8; 32]) {
        if let Some(st) = self.peers.remove(key) {
            if let Some(s) = st.session {
                self.by_v4.remove(&s.v4);
                self.by_v6.remove(&s.v6);
                self.pool.release(s.addr_idx);
            }
        }
    }

    fn on_inner(&mut self, key: [u8; 32], pkt: &[u8], now: Instant, out: &mut Vec<Action<R>>) {
        let Ok(v) = IpView::parse(pkt) else {
            return;
        };
        let admitted = self.peers.get(&key).is_some_and(|p| p.session.is_some());

        if icmp::is_gateway(v.dst) {
            if v.protocol == PROTO_UDP {
                if let (Some(src), Some(dst)) = (v.src_sock(pkt), v.dst_sock(pkt)) {
                    if dst.port() == VWCP_PORT {
                        if let Some(payload) = v.udp_payload(pkt) {
                            let payload = payload.to_vec();
                            self.on_vwcp(key, src, dst, &payload, now, out);
                        }
                        return;
                    }
                }
            }
            if admitted {
                if let Some(reply) = icmp::echo_reply(pkt) {
                    self.stats.echo_replies += 1;
                    if let Some(remote) = self.peers.get(&key).and_then(|p| p.remote.clone()) {
                        out.extend(self.encapsulate_to(&key, remote, &reply, now));
                    }
                    return;
                }
            }
            self.stats.unadmitted_dropped += u64::from(!admitted);
            return;
        }

        let Some(sess) = self.peers.get_mut(&key).and_then(|p| p.session.as_mut()) else {
            self.stats.unadmitted_dropped += 1;
            return;
        };
        let src_ok = match v.src {
            IpAddr::V4(a) => a == sess.v4,
            IpAddr::V6(a) => a == sess.v6,
        };
        if !src_ok {
            self.stats.spoofed_dropped += 1;
            return;
        }
        if in_client_pool(v.dst) {
            self.stats.client_to_client_dropped += 1;
            return;
        }
        if !sess.up.try_consume(pkt.len(), now) {
            self.stats.rate_limited_dropped += 1;
            return;
        }
        self.stats.forwarded_up += 1;
        out.push(Action::Tun(pkt.to_vec()));
    }

    fn on_vwcp(
        &mut self,
        key: [u8; 32],
        client: SocketAddr,
        gateway: SocketAddr,
        datagram: &[u8],
        now: Instant,
        out: &mut Vec<Action<R>>,
    ) {
        let msg = {
            let Some(st) = self.peers.get_mut(&key) else {
                return;
            };
            match st.reasm.push(datagram, now) {
                Ok(Some(m)) => m,
                Ok(None) => return,
                Err(e) => {
                    self.stats.vwcp_errors += 1;
                    let reply = ErrorMsg::from_error(&e).datagrams();
                    self.reply_vwcp(key, client, gateway, reply, now, out);
                    return;
                }
            }
        };
        let result = match msg.ty {
            MsgType::ClientHello => self.handle_hello(key, &msg.body, now),
            MsgType::ClientKem => self.handle_kem(key, &msg.body, now),
            MsgType::RedeemRequest => self.handle_redeem(key, &msg.body),
            MsgType::AttestRequest => self.handle_attest(&msg.body),
            MsgType::Error => {
                if let Some(st) = self.peers.get_mut(&key) {
                    st.pending = None;
                }
                Ok(Vec::new())
            }
            other => Err(CryptoError::UnexpectedType(other as u8)),
        };
        let reply = match result {
            Ok(d) => d,
            Err(e) => {
                self.stats.vwcp_errors += 1;
                tracing::debug!("vwcp request refused: {}", e.kind());
                let m = match e {
                    CryptoError::State("rate limited") => {
                        ErrorMsg::new(error_code::RATE_LIMITED, "rate limited")
                    }
                    ref other => ErrorMsg::from_error(other),
                };
                m.datagrams()
            }
        };
        self.reply_vwcp(key, client, gateway, reply, now, out);
    }

    fn reply_vwcp(
        &mut self,
        key: [u8; 32],
        client: SocketAddr,
        gateway: SocketAddr,
        datagrams: Vec<Vec<u8>>,
        now: Instant,
        out: &mut Vec<Action<R>>,
    ) {
        let Some(remote) = self.peers.get(&key).and_then(|p| p.remote.clone()) else {
            return;
        };
        for d in datagrams {
            if let Ok(pkt) = build_udp(gateway, client, &d, TTL_NORMAL) {
                out.extend(self.encapsulate_to(&key, remote.clone(), &pkt, now));
            }
        }
    }

    fn handle_hello(
        &mut self,
        key: [u8; 32],
        body: &[u8],
        now: Instant,
    ) -> std::result::Result<Vec<Vec<u8>>, CryptoError> {
        let handshakes = self
            .responder
            .peer(&key)
            .map(|p| p.handshakes_completed())
            .unwrap_or(0);
        let st = self
            .peers
            .get_mut(&key)
            .ok_or(CryptoError::State("no peer"))?;
        while st
            .hellos
            .front()
            .is_some_and(|t| now.saturating_duration_since(*t) >= HELLO_WINDOW)
        {
            st.hellos.pop_front();
        }
        if st.hellos.len() >= MAX_HELLOS_PER_WINDOW {
            return Err(CryptoError::State("rate limited"));
        }
        st.hellos.push_back(now);
        let existing = st.session.as_ref().map(|s| {
            let confirmed = handshakes > s.handshakes_at_install;
            let min = if confirmed {
                s.epoch.saturating_add(1)
            } else {
                s.epoch
            };
            (
                min,
                TokenGrant {
                    tier: s.tier,
                    bandwidth_bps: s.bandwidth_bps,
                },
            )
        });

        let unix = (self.unix_now)();
        let mut claim = None;
        let (hs, datagrams) = match existing {
            // Already admitted by this static key: rotation needs no new token.
            Some((min, grant)) => {
                let r =
                    ServerHandshake::on_client_hello_min_epoch(&self.identity, body, min, |_| {
                        Ok(grant)
                    })?;
                claim = Some(Claim::Rotation);
                r
            }
            None => {
                let owners = &self.owners;
                let issuers = &self.issuers;
                let ledger = &self.ledger;
                let invites = &self.invites;
                let claim_ref = &mut claim;
                ServerHandshake::on_client_hello(&self.identity, body, |token| match parse_token(
                    token,
                )? {
                    TokenClaim::Owner => {
                        if !owners.contains(&key) {
                            return Err(CryptoError::TokenRejected("device not authorised"));
                        }
                        *claim_ref = Some(Claim::Owner);
                        Ok(TokenGrant {
                            tier: OWNER_TIER,
                            bandwidth_bps: 0,
                        })
                    }
                    TokenClaim::Session(t) => {
                        let pk = issuers
                            .public(t.tier)
                            .ok_or(CryptoError::TokenRejected("unknown token tier"))?;
                        ledger.check(pk, &t)?;
                        let tr =
                            tier(t.tier).ok_or(CryptoError::TokenRejected("unknown token tier"))?;
                        *claim_ref = Some(Claim::Session(t));
                        Ok(TokenGrant {
                            tier: tr.id,
                            bandwidth_bps: tr.bandwidth_bps,
                        })
                    }
                    TokenClaim::Invite(h) => {
                        let e = invites.check(&h, unix)?;
                        *claim_ref = Some(Claim::Invite(h));
                        Ok(TokenGrant {
                            tier: e.tier,
                            bandwidth_bps: e.bandwidth_bps,
                        })
                    }
                })?
            }
        };
        let claim = claim.ok_or(CryptoError::State("token not evaluated"))?;
        let st = self
            .peers
            .get_mut(&key)
            .ok_or(CryptoError::State("no peer"))?;
        st.pending = Some(Pending {
            hs,
            claim,
            started: now,
        });
        Ok(datagrams)
    }

    fn handle_kem(
        &mut self,
        key: [u8; 32],
        body: &[u8],
        now: Instant,
    ) -> std::result::Result<Vec<Vec<u8>>, CryptoError> {
        let st = self
            .peers
            .get_mut(&key)
            .ok_or(CryptoError::SessionMismatch)?;
        let pending = st.pending.take().ok_or(CryptoError::SessionMismatch)?;
        if now.saturating_duration_since(pending.started) >= HANDSHAKE_TIMEOUT {
            return Err(CryptoError::SessionMismatch);
        }
        let (idx, fresh) = match st.session.as_ref() {
            Some(s) => (s.addr_idx, false),
            None => (
                self.pool
                    .allocate()
                    .ok_or(CryptoError::Backend("address pool exhausted"))?,
                true,
            ),
        };
        let v4 = AddressPool::v4_of(idx);
        let v6 = AddressPool::v6_of(idx);
        let mut assignment = Assignment::host(v4, v6);
        assignment.rotate_secs = PQ_ROTATE_SECS.min(u64::from(u16::MAX)) as u16;
        let grant = pending.hs.grant();
        let completed = pending.hs.on_client_kem(body, assignment);
        let (session, ack) = match completed {
            Ok(x) => x,
            Err(e) => {
                if fresh {
                    self.pool.release(idx);
                }
                return Err(e);
            }
        };
        // Consume the capability only once the client proved key possession.
        let unix = (self.unix_now)();
        let consumed: std::result::Result<(AdmitKind, Option<InviteEntry>), CryptoError> =
            match &pending.claim {
                Claim::Owner => Ok((AdmitKind::Owner, None)),
                Claim::Session(t) => self
                    .ledger
                    .spend(t)
                    .map(|_| (AdmitKind::SessionToken, None)),
                Claim::Invite(h) => self
                    .invites
                    .consume(h, unix)
                    .map(|e| (AdmitKind::Invite, Some(e))),
                Claim::Rotation => Ok((AdmitKind::Owner, None)),
            };
        let (kind, _invite) = match consumed {
            Ok(x) => x,
            Err(e) => {
                if fresh {
                    self.pool.release(idx);
                }
                return Err(e);
            }
        };

        let handshakes = match self.responder.peer_mut(&key) {
            Some(p) => {
                p.set_psk(session.psk.clone());
                p.handshakes_completed()
            }
            None => {
                if fresh {
                    self.pool.release(idx);
                }
                return Err(CryptoError::State("peer vanished"));
            }
        };
        let st = self
            .peers
            .get_mut(&key)
            .ok_or(CryptoError::State("no peer"))?;
        match st.session.as_mut() {
            Some(s) => {
                s.epoch = session.epoch;
                s.handshakes_at_install = handshakes;
                self.stats.rotations += 1;
            }
            None => {
                st.session = Some(Admitted {
                    kind,
                    tier: grant.tier,
                    bandwidth_bps: grant.bandwidth_bps,
                    addr_idx: idx,
                    v4,
                    v6,
                    epoch: session.epoch,
                    handshakes_at_install: handshakes,
                    up: TokenBucket::new(grant.bandwidth_bps, now),
                    down: TokenBucket::new(grant.bandwidth_bps, now),
                    redeem: if kind == AdmitKind::Invite {
                        Redeem::Available
                    } else {
                        Redeem::NotAllowed
                    },
                });
                self.by_v4.insert(v4, key);
                self.by_v6.insert(v6, key);
                self.stats.admissions += 1;
            }
        }
        Ok(ack)
    }

    fn handle_redeem(
        &mut self,
        key: [u8; 32],
        body: &[u8],
    ) -> std::result::Result<Vec<Vec<u8>>, CryptoError> {
        let request_hash = *blake3::hash(body).as_bytes();
        let sess = self
            .peers
            .get_mut(&key)
            .and_then(|p| p.session.as_mut())
            .ok_or(CryptoError::TokenRejected("session not admitted"))?;
        match &sess.redeem {
            Redeem::NotAllowed => {
                return Err(CryptoError::TokenRejected("redemption not permitted"))
            }
            Redeem::Done {
                request_hash: h,
                response,
            } => {
                // An identical retry (lost response) gets the same answer.
                if *h == request_hash {
                    return Ok(response.clone());
                }
                return Err(CryptoError::TokenRejected("invite already redeemed"));
            }
            Redeem::Available => {}
        }
        let req = RedeemRequest::decode(body)?;
        let issuer = self
            .issuers
            .key(sess.tier)
            .ok_or(CryptoError::TokenRejected("no issuer key for tier"))?;
        let blind_sigs = req
            .blinded
            .iter()
            .map(|b| blind_sign(issuer, b))
            .collect::<std::result::Result<Vec<_>, _>>()?;
        let response = RedeemResponse {
            tier: sess.tier,
            blind_sigs,
        }
        .datagrams()?;
        sess.redeem = Redeem::Done {
            request_hash,
            response: response.clone(),
        };
        Ok(response)
    }

    fn handle_attest(&self, body: &[u8]) -> std::result::Result<Vec<Vec<u8>>, CryptoError> {
        let req = AttestRequest::decode(body)?;
        let attestation = self
            .attestation(req.nonce)
            .map_err(|_| CryptoError::Backend("attestation unavailable"))?;
        AttestResponse { attestation }.datagrams()
    }

    /// A fresh signed attestation echoing `nonce`.
    pub fn attestation(&self, nonce: [u8; 32]) -> Result<SignedAttestation> {
        let f = (self.facts)();
        let report = AttestationReport {
            binary_blake3: f.binary_blake3,
            swap_disabled: f.swap_disabled,
            logging_off: f.logging_off,
            ram_only: f.ram_only,
            uptime_secs: f.uptime_secs,
            unix_time: (self.unix_now)(),
            nonce,
            node_identity: self.identity.public(),
        };
        Ok(report.sign(&self.identity)?)
    }

    /// Create a single-use F2F invite. Returns the `voidwire://f2f/...` URI
    /// and the tier actually granted.
    pub fn create_invite(
        &mut self,
        bandwidth_bps: u64,
        expires_unix: u64,
        node_uri: &str,
    ) -> Result<(String, Tier)> {
        let t = tier_for_bandwidth(bandwidth_bps);
        if self.issuers.key(t.id).is_none() {
            return Err(VwError::Config(
                "no issuer key for the requested tier".into(),
            ));
        }
        if expires_unix <= (self.unix_now)() {
            return Err(VwError::Config("invite expiry is in the past".into()));
        }
        let invite = Invite::new(
            &self.identity,
            t.bandwidth_bps,
            expires_unix,
            node_uri.to_string(),
        );
        let uri = invite.to_uri(&self.identity)?;
        self.invites.insert(
            invite_hash(invite.invite_secret.expose()),
            InviteEntry {
                tier: t.id,
                bandwidth_bps: t.bandwidth_bps,
                expires_unix,
            },
        );
        Ok((uri, t))
    }
}

/// Gateway VWCP socket for a client address family.
pub fn gateway_sock(v6: bool) -> SocketAddr {
    if v6 {
        SocketAddr::new(IpAddr::V6(NODE_GATEWAY_V6), VWCP_PORT)
    } else {
        SocketAddr::new(IpAddr::V4(NODE_GATEWAY_V4), VWCP_PORT)
    }
}
