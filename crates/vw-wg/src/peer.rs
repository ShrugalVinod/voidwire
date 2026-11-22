//! A single WireGuard peer: handshake state, keypair rotation, timers, cookie
//! handling, packet queueing and PSK rotation. Fully sans-IO: callers pass
//! datagrams and `Instant`s in and get datagrams / plaintext out.

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use rand::rngs::OsRng;
use rand::{Rng, RngCore};
use vw_core::consts::BASE_TUNNEL_MTU;
use vw_core::secret::Key32;

use crate::daita;
use crate::error::WgError;
use crate::noise::{
    self, consume_cookie_reply, consume_initiation, consume_response, create_initiation,
    create_response, static_secret, write_macs, Cookie, CookieChecker, InitiatorState, LoadMeter,
    MacCheck, MessageType, ReceivedInitiation, Tai64nClock, COOKIE_REFRESH_TIME, INITIATION_LEN,
    RESPONSE_LEN, TIMESTAMP_LEN,
};
use crate::session::Session;
use crate::timers::{
    KEEPALIVE_TIMEOUT, MAX_QUEUED_PACKETS, MIN_INITIATION_SPACING, REJECT_AFTER_TIME,
    REKEY_ATTEMPT_TIME, REKEY_TIMEOUT, REKEY_TIMEOUT_JITTER_MS, ZERO_KEYS_AFTER,
};

/// Whether this side proactively starts handshakes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// Client side: initiates handshakes, rekeys, retransmits.
    Initiator,
    /// Server side: only answers initiations. VoidWire nodes cannot reach
    /// clients behind NAT or stream transports, so they never initiate;
    /// packets for a peer without a usable session are queued until the
    /// client handshakes again.
    Responder,
}

/// Result of feeding one datagram to [`Peer::decapsulate`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decapsulated {
    /// Nothing to do (e.g. a cookie reply was stored).
    None,
    /// Datagrams to send to the remote (handshake responses, cookie replies,
    /// queued data flushed after a handshake, confirmation keepalives).
    Network(Vec<Vec<u8>>),
    /// A decrypted IP packet (WireGuard padding stripped) for the TUN device.
    Tunnel(Vec<u8>),
    /// An authenticated keepalive.
    Keepalive,
    /// An authenticated DAITA chaff packet (silently dropped).
    Chaff,
}

struct PendingHandshake {
    state: InitiatorState,
}

/// One WireGuard peer.
pub struct Peer {
    role: Role,
    local_static: Key32,
    local_public: [u8; 32],
    remote_static: [u8; 32],
    mac1_key_remote: [u8; 32],
    cookie_key_remote: [u8; 32],
    psk: Key32,
    previous_psk: Option<Key32>,
    /// Responder: our last response used `psk` and is not yet confirmed.
    unconfirmed_current_response: bool,
    /// Responder: the `next` session was built with the fallback PSK.
    next_used_fallback: bool,
    reserved: [u8; 3],
    mtu: u16,
    persistent_keepalive: Option<Duration>,
    auto_connect: bool,

    index_prefix: u32,
    index_counter: u8,

    pending: Option<PendingHandshake>,
    attempt_started: Option<Instant>,
    retransmit_at: Option<Instant>,
    rehandshake_requested: bool,
    rehandshake_at: Option<Instant>,

    previous: Option<Session>,
    current: Option<Session>,
    next: Option<Session>,

    greatest_timestamp: Option<[u8; TIMESTAMP_LEN]>,
    last_initiation_consumed: Option<Instant>,
    tai: Tai64nClock,

    cookie: Option<(Cookie, Instant)>,
    last_mac1: Option<(u32, [u8; 16])>,
    checker: CookieChecker,
    load: LoadMeter,

    queue: VecDeque<Vec<u8>>,
    outbox: Vec<Vec<u8>>,

    last_sent: Option<Instant>,
    last_received: Option<Instant>,
    keepalive_due: Option<Instant>,
    new_handshake_due: Option<Instant>,
    last_handshake: Option<Instant>,
    handshakes_completed: u64,
}

impl std::fmt::Debug for Peer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Peer")
            .field("role", &self.role)
            .field("established", &self.current.is_some())
            .field("handshake_pending", &self.pending.is_some())
            .field("queued", &self.queue.len())
            .field("handshakes", &self.handshakes_completed)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Slot {
    Previous,
    Current,
    Next,
}

impl Peer {
    /// A client-side peer that initiates handshakes.
    pub fn new_initiator(
        local_static: Key32,
        remote_static: [u8; 32],
        psk: Option<Key32>,
        reserved: [u8; 3],
    ) -> Self {
        Self::new(Role::Initiator, local_static, remote_static, psk, reserved)
    }

    /// A server-side peer that only answers handshakes (see [`Role::Responder`]).
    pub fn new_responder(
        local_static: Key32,
        remote_static: [u8; 32],
        psk: Option<Key32>,
        reserved: [u8; 3],
    ) -> Self {
        Self::new(Role::Responder, local_static, remote_static, psk, reserved)
    }

    fn new(
        role: Role,
        local_static: Key32,
        remote_static: [u8; 32],
        psk: Option<Key32>,
        reserved: [u8; 3],
    ) -> Self {
        let local_public = noise::public_key(&local_static);
        Self {
            role,
            local_static,
            local_public,
            remote_static,
            mac1_key_remote: noise::mac1_key(&remote_static),
            cookie_key_remote: noise::cookie_key(&remote_static),
            psk: psk.unwrap_or_else(Key32::zero),
            previous_psk: None,
            unconfirmed_current_response: false,
            next_used_fallback: false,
            reserved,
            mtu: BASE_TUNNEL_MTU,
            persistent_keepalive: None,
            auto_connect: role == Role::Initiator,
            index_prefix: OsRng.next_u32() & 0x00ff_ffff,
            index_counter: 0,
            pending: None,
            attempt_started: None,
            retransmit_at: None,
            rehandshake_requested: false,
            rehandshake_at: None,
            previous: None,
            current: None,
            next: None,
            greatest_timestamp: None,
            last_initiation_consumed: None,
            tai: Tai64nClock::new(Instant::now()),
            cookie: None,
            last_mac1: None,
            checker: CookieChecker::new(&local_public),
            load: LoadMeter::default(),
            queue: VecDeque::new(),
            outbox: Vec::new(),
            last_sent: None,
            last_received: None,
            keepalive_due: None,
            new_handshake_due: None,
            last_handshake: None,
            handshakes_completed: 0,
        }
    }

    /// Send a keepalive whenever nothing was sent for `interval` (NAT upkeep).
    pub fn with_persistent_keepalive(mut self, interval: Option<Duration>) -> Self {
        self.persistent_keepalive = interval.filter(|d| !d.is_zero());
        self
    }

    /// Tunnel MTU: WireGuard's 16-byte padding never grows packets past it.
    pub fn with_mtu(mut self, mtu: u16) -> Self {
        self.mtu = mtu;
        self
    }

    /// Initiators connect from the first `tick` (default) or only when data is
    /// sent (`false`, classic WireGuard behaviour).
    pub fn with_auto_connect(mut self, auto: bool) -> Self {
        self.auto_connect = auto && self.role == Role::Initiator;
        self
    }

    pub(crate) fn set_index_prefix(&mut self, prefix: u32) {
        self.index_prefix = prefix & 0x00ff_ffff;
    }

    pub(crate) fn index_prefix(&self) -> u32 {
        self.index_prefix
    }

    pub fn role(&self) -> Role {
        self.role
    }

    /// The remote's static public key.
    pub fn remote_static(&self) -> &[u8; 32] {
        &self.remote_static
    }

    /// Our static public key.
    pub fn local_public(&self) -> &[u8; 32] {
        &self.local_public
    }

    /// Bytes written into positions 1..4 of every outgoing message.
    pub fn reserved(&self) -> [u8; 3] {
        self.reserved
    }

    pub fn set_reserved(&mut self, reserved: [u8; 3]) {
        self.reserved = reserved;
    }

    /// Force (or release, with `None`) cookie mode for incoming handshakes.
    pub fn set_under_load(&mut self, forced: Option<bool>) {
        self.load.force(forced);
    }

    /// Replace the preshared key. The old key is kept as a fallback for one
    /// handshake attempt (ARCHITECTURE.md §6); initiators immediately start a
    /// new handshake on the next [`tick`](Self::tick).
    pub fn set_psk(&mut self, psk: Key32) {
        let old = std::mem::replace(&mut self.psk, psk);
        if old != self.psk {
            self.previous_psk = Some(old);
        }
        self.unconfirmed_current_response = false;
        if self.role == Role::Initiator {
            self.rehandshake_requested = true;
        }
    }

    /// True while a sending session is installed.
    pub fn session_established(&self) -> bool {
        self.current.is_some()
    }

    /// When the most recent handshake completed.
    pub fn last_handshake(&self) -> Option<Instant> {
        self.last_handshake
    }

    /// Number of handshakes completed over the peer's lifetime.
    pub fn handshakes_completed(&self) -> u64 {
        self.handshakes_completed
    }

    /// Whether an initiation is awaiting its response.
    pub fn handshake_in_progress(&self) -> bool {
        self.pending.is_some()
    }

    /// Plaintext packets waiting for a session.
    pub fn queued_packets(&self) -> usize {
        self.queue.len()
    }

    /// When an authenticated packet was last received.
    pub fn last_received(&self) -> Option<Instant> {
        self.last_received
    }

    fn jitter() -> Duration {
        Duration::from_millis(rand::thread_rng().gen_range(0..=REKEY_TIMEOUT_JITTER_MS))
    }

    fn live(&self, idx: u32) -> bool {
        [&self.previous, &self.current, &self.next]
            .iter()
            .any(|s| s.as_ref().is_some_and(|s| s.local_index == idx))
            || self
                .pending
                .as_ref()
                .is_some_and(|p| p.state.local_index == idx)
    }

    fn next_index(&mut self) -> u32 {
        loop {
            self.index_counter = self.index_counter.wrapping_add(1);
            let idx = (self.index_prefix << 8) | self.index_counter as u32;
            if !self.live(idx) {
                return idx;
            }
        }
    }

    /// Whether `idx` names one of this peer's sessions or pending handshake.
    pub(crate) fn owns_index(&self, idx: u32) -> bool {
        self.live(idx)
            || self.last_mac1.is_some_and(|(i, _)| i == idx)
            || idx >> 8 == self.index_prefix
    }

    fn padded_len(&self, len: usize) -> usize {
        let mtu = self.mtu as usize;
        if len >= mtu {
            return len;
        }
        ((len + 15) & !15).min(mtu)
    }

    fn fresh_cookie(&self, now: Instant) -> Option<[u8; 16]> {
        self.cookie
            .as_ref()
            .filter(|(_, at)| now.saturating_duration_since(*at) < COOKIE_REFRESH_TIME)
            .map(|(c, _)| *c.expose())
    }

    fn encrypt_current(&mut self, plaintext: &[u8], now: Instant) -> Option<Vec<u8>> {
        let padded = self.padded_len(plaintext.len());
        let reserved = self.reserved;
        let s = self.current.as_mut()?;
        match s.encrypt(plaintext, padded, reserved, now) {
            Ok(m) => {
                self.last_sent = Some(now);
                Some(m)
            }
            Err(e) => {
                tracing::trace!(error = %e, "cannot encrypt on current session");
                None
            }
        }
    }

    fn send_data(&mut self, plaintext: &[u8], now: Instant) -> Option<Vec<u8>> {
        let m = self.encrypt_current(plaintext, now)?;
        self.keepalive_due = None;
        if !plaintext.is_empty() && self.new_handshake_due.is_none() {
            self.new_handshake_due = Some(now + KEEPALIVE_TIMEOUT + REKEY_TIMEOUT);
        }
        Some(m)
    }

    /// Encrypt an empty keepalive on the current session.
    pub fn keepalive(&mut self, now: Instant) -> Option<Vec<u8>> {
        let m = self.encrypt_current(&[], now)?;
        self.keepalive_due = None;
        Some(m)
    }

    /// Encrypt a DAITA chaff packet of `size` plaintext bytes, or `None`
    /// without a session. Chaff never triggers handshakes or keepalives.
    pub fn make_chaff(&mut self, size: usize, now: Instant) -> Option<Vec<u8>> {
        let pt = daita::chaff_plaintext(size);
        self.encrypt_current(&pt, now)
    }

    fn enqueue(&mut self, plaintext: &[u8]) {
        if self.queue.len() >= MAX_QUEUED_PACKETS {
            self.queue.pop_front();
        }
        self.queue.push_back(plaintext.to_vec());
    }

    fn flush_queue(&mut self, now: Instant) -> Vec<Vec<u8>> {
        let mut out = Vec::with_capacity(self.queue.len());
        while let Some(p) = self.queue.pop_front() {
            match self.send_data(&p, now) {
                Some(m) => out.push(m),
                None => {
                    self.queue.push_front(p);
                    break;
                }
            }
        }
        out
    }

    fn current_usable(&self, now: Instant) -> bool {
        self.current.as_ref().is_some_and(|s| !s.expired(now))
    }

    /// Encrypt one plaintext IP packet. Without a session the packet is queued
    /// and (for initiators) a handshake initiation is returned instead.
    pub fn encapsulate(&mut self, plaintext: &[u8], now: Instant) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        if self.current_usable(now) {
            if !self.queue.is_empty() {
                out.extend(self.flush_queue(now));
            }
            match self.send_data(plaintext, now) {
                Some(m) => out.push(m),
                None => self.enqueue(plaintext),
            }
            let rekey = self.current.as_ref().is_some_and(|s| s.needs_rekey(now));
            if rekey && self.pending.is_none() {
                out.extend(self.initiate(now));
            }
        } else {
            self.enqueue(plaintext);
            if self.pending.is_none() {
                out.extend(self.initiate(now));
            }
        }
        out
    }

    /// Start a new handshake now (initiators only). Returns the initiation.
    pub fn initiate_handshake(&mut self, now: Instant) -> Option<Vec<u8>> {
        self.attempt_started = None;
        self.initiate(now)
    }

    fn initiate(&mut self, now: Instant) -> Option<Vec<u8>> {
        if self.role != Role::Initiator {
            return None;
        }
        let local_index = self.next_index();
        let ts = self.tai.stamp(now);
        let mut msg = [0u8; INITIATION_LEN];
        let state = match create_initiation(
            &static_secret(&self.local_static),
            &self.local_public,
            &self.remote_static,
            local_index,
            &ts,
            self.reserved,
            &mut msg,
        ) {
            Ok(s) => s,
            Err(e) => {
                tracing::debug!(error = %e, "cannot create handshake initiation");
                return None;
            }
        };
        let cookie = self.fresh_cookie(now);
        let m1 = write_macs(&mut msg, &self.mac1_key_remote, cookie.as_ref());
        self.last_mac1 = Some((local_index, m1));
        self.pending = Some(PendingHandshake { state });
        if self.attempt_started.is_none() {
            self.attempt_started = Some(now);
        }
        self.retransmit_at = Some(now + REKEY_TIMEOUT + Self::jitter());
        self.last_sent = Some(now);
        Some(msg.to_vec())
    }

    /// Feed one datagram received from the remote (no source address, so
    /// cookie mode is never engaged).
    pub fn decapsulate(&mut self, datagram: &[u8], now: Instant) -> Result<Decapsulated, WgError> {
        self.decapsulate_from(None, datagram, now)
    }

    /// Feed one datagram received from `src`. The source address is only used
    /// for cookies when this peer is under load.
    pub fn decapsulate_from(
        &mut self,
        src: Option<SocketAddr>,
        datagram: &[u8],
        now: Instant,
    ) -> Result<Decapsulated, WgError> {
        match noise::message_type(datagram).ok_or(WgError::Malformed)? {
            MessageType::Initiation => {
                let under_load = self.load.record(now);
                if let MacCheck::SendCookie(c) =
                    self.checker
                        .check(datagram, src.as_ref(), under_load, self.reserved, now)?
                {
                    return Ok(Decapsulated::Network(vec![c]));
                }
                let ri = consume_initiation(
                    &static_secret(&self.local_static),
                    &self.local_public,
                    datagram,
                )?;
                self.handle_initiation(ri, now)
            }
            MessageType::Response => {
                let under_load = self.load.record(now);
                if let MacCheck::SendCookie(c) =
                    self.checker
                        .check(datagram, src.as_ref(), under_load, self.reserved, now)?
                {
                    return Ok(Decapsulated::Network(vec![c]));
                }
                self.handle_response(datagram, now)
            }
            MessageType::CookieReply => self.handle_cookie_reply(datagram, now),
            MessageType::Data => self.handle_data(datagram, now),
        }
    }

    /// Answer an authenticated initiation addressed to us.
    pub(crate) fn handle_initiation(
        &mut self,
        ri: ReceivedInitiation,
        now: Instant,
    ) -> Result<Decapsulated, WgError> {
        if ri.remote_static != self.remote_static {
            return Err(WgError::WrongPeer);
        }
        if self.greatest_timestamp.is_some_and(|g| ri.timestamp <= g) {
            return Err(WgError::StaleTimestamp);
        }
        if self
            .last_initiation_consumed
            .is_some_and(|t| now.saturating_duration_since(t) < MIN_INITIATION_SPACING)
        {
            return Err(WgError::Flood);
        }
        // Fallback order when our last response was never confirmed: the
        // previous PSK, else no PSK at all. The latter recovers a VoidWire
        // client whose daemon restarted and lost its PQ PSK; only the holder of
        // this peer's static key can trigger it, and the client re-runs VWCP
        // before any user traffic, so no unprotected traffic results.
        let use_fallback = self.unconfirmed_current_response
            && (self.previous_psk.is_some() || !self.psk.is_zero());
        let psk = if use_fallback {
            self.previous_psk.take().unwrap_or_else(Key32::zero)
        } else {
            self.psk.clone()
        };
        let local_index = self.next_index();
        let mut resp = [0u8; RESPONSE_LEN];
        let keys = create_response(&ri, &psk, local_index, self.reserved, &mut resp)?;
        let cookie = self.fresh_cookie(now);
        let m1 = write_macs(&mut resp, &self.mac1_key_remote, cookie.as_ref());
        self.last_mac1 = Some((local_index, m1));
        self.greatest_timestamp = Some(ri.timestamp);
        self.last_initiation_consumed = Some(now);
        self.unconfirmed_current_response = !use_fallback;
        self.next_used_fallback = use_fallback;

        self.next = Some(Session::new(
            local_index,
            ri.sender_index,
            keys.send,
            keys.recv,
            now,
            false,
        ));
        self.previous = None;
        self.last_handshake = Some(now);
        self.handshakes_completed += 1;
        self.last_received = Some(now);
        self.last_sent = Some(now);
        Ok(Decapsulated::Network(vec![resp.to_vec()]))
    }

    /// Complete our pending handshake with a response.
    pub(crate) fn handle_response(
        &mut self,
        msg: &[u8],
        now: Instant,
    ) -> Result<Decapsulated, WgError> {
        let receiver = u32::from_le_bytes([msg[8], msg[9], msg[10], msg[11]]);
        let pending = self
            .pending
            .as_ref()
            .filter(|p| p.state.local_index == receiver)
            .ok_or(WgError::UnknownIndex)?;
        let ls = static_secret(&self.local_static);
        let (keys, remote_index, used_fallback) =
            match consume_response(&pending.state, &ls, &self.psk, msg) {
                Ok((k, r)) => (k, r, false),
                Err(WgError::Decrypt) => match &self.previous_psk {
                    Some(prev) => {
                        let (k, r) = consume_response(&pending.state, &ls, prev, msg)?;
                        (k, r, true)
                    }
                    None => return Err(WgError::Decrypt),
                },
                Err(e) => return Err(e),
            };
        let local_index = pending.state.local_index;
        self.pending = None;
        self.previous_psk = None;
        if used_fallback {
            // The remote has not installed the new PSK yet: retry with it soon.
            self.rehandshake_at = Some(now + REKEY_TIMEOUT);
        }
        self.attempt_started = None;
        self.retransmit_at = None;

        let session = Session::new(local_index, remote_index, keys.send, keys.recv, now, true);
        match self.next.take() {
            Some(next) => self.previous = Some(next),
            None => self.previous = self.current.take(),
        }
        self.current = Some(session);
        self.last_handshake = Some(now);
        self.handshakes_completed += 1;
        self.last_received = Some(now);
        self.new_handshake_due = None;

        let mut out = self.flush_queue(now);
        if out.is_empty() {
            // Immediate key confirmation for the responder.
            out.extend(self.keepalive(now));
        }
        Ok(Decapsulated::Network(out))
    }

    /// Store a cookie answering one of our handshake messages.
    pub(crate) fn handle_cookie_reply(
        &mut self,
        msg: &[u8],
        now: Instant,
    ) -> Result<Decapsulated, WgError> {
        let receiver = u32::from_le_bytes([msg[4], msg[5], msg[6], msg[7]]);
        let (idx, m1) = self.last_mac1.ok_or(WgError::UnknownIndex)?;
        if idx != receiver {
            return Err(WgError::UnknownIndex);
        }
        let c = consume_cookie_reply(&self.cookie_key_remote, msg, &m1)?;
        self.cookie = Some((Cookie::new(c), now));
        Ok(Decapsulated::None)
    }

    fn slot_for(&self, idx: u32) -> Option<Slot> {
        let m = |s: &Option<Session>| s.as_ref().is_some_and(|s| s.local_index == idx);
        if m(&self.current) {
            Some(Slot::Current)
        } else if m(&self.next) {
            Some(Slot::Next)
        } else if m(&self.previous) {
            Some(Slot::Previous)
        } else {
            None
        }
    }

    fn session_mut(&mut self, slot: Slot) -> Option<&mut Session> {
        match slot {
            Slot::Previous => self.previous.as_mut(),
            Slot::Current => self.current.as_mut(),
            Slot::Next => self.next.as_mut(),
        }
    }

    /// Decrypt a transport data message.
    pub(crate) fn handle_data(
        &mut self,
        msg: &[u8],
        now: Instant,
    ) -> Result<Decapsulated, WgError> {
        let idx = u32::from_le_bytes([msg[4], msg[5], msg[6], msg[7]]);
        let slot = self.slot_for(idx).ok_or(WgError::UnknownIndex)?;
        let pt = self
            .session_mut(slot)
            .ok_or(WgError::UnknownIndex)?
            .decrypt(msg, now)?;
        if slot == Slot::Next {
            // Key confirmation: the initiator is now using the new session.
            self.previous = self.current.take();
            self.current = self.next.take();
            self.unconfirmed_current_response = false;
            if !self.next_used_fallback {
                self.previous_psk = None;
            }
            self.next_used_fallback = false;
            let flushed = self.flush_queue(now);
            self.outbox.extend(flushed);
        }
        self.last_received = Some(now);
        self.new_handshake_due = None;

        // Whitepaper §6.2: an initiator receiving on an old session rekeys.
        let aging = self.current.as_ref().is_some_and(|s| {
            s.we_initiated
                && now.saturating_duration_since(s.created)
                    >= REJECT_AFTER_TIME - KEEPALIVE_TIMEOUT - REKEY_TIMEOUT
        });
        if aging && self.pending.is_none() {
            if let Some(i) = self.initiate(now) {
                self.outbox.push(i);
            }
        }

        if pt.is_empty() {
            return Ok(Decapsulated::Keepalive);
        }
        if daita::is_chaff(&pt) {
            return Ok(Decapsulated::Chaff);
        }
        let n = daita::strip_padding(&pt)?;
        if self.keepalive_due.is_none() {
            self.keepalive_due = Some(now + KEEPALIVE_TIMEOUT);
        }
        let mut pt = pt;
        pt.truncate(n);
        Ok(Decapsulated::Tunnel(pt))
    }

    /// Datagrams produced outside a direct call (queued data flushed on key
    /// confirmation, receive-side rekeys). Also drained by [`tick`](Self::tick).
    pub fn drain_outbox(&mut self) -> Vec<Vec<u8>> {
        std::mem::take(&mut self.outbox)
    }

    /// Run all timers. Call at least every few hundred milliseconds.
    pub fn tick(&mut self, now: Instant) -> Vec<Vec<u8>> {
        let mut out = std::mem::take(&mut self.outbox);

        for s in [&mut self.previous, &mut self.current, &mut self.next] {
            if s.as_ref().is_some_and(|x| x.expired(now)) {
                *s = None;
            }
        }
        if self
            .last_handshake
            .is_some_and(|h| now.saturating_duration_since(h) >= ZERO_KEYS_AFTER)
        {
            self.previous = None;
            self.current = None;
            self.next = None;
            self.pending = None;
            self.cookie = None;
        }

        if self.retransmit_at.is_some_and(|at| now >= at) {
            let gave_up = self
                .attempt_started
                .is_some_and(|s| now.saturating_duration_since(s) >= REKEY_ATTEMPT_TIME);
            if gave_up {
                tracing::debug!("handshake attempt timed out; dropping queued packets");
                self.pending = None;
                self.retransmit_at = None;
                self.attempt_started = None;
                self.queue.clear();
            } else if self.pending.is_some() {
                out.extend(self.initiate(now));
            } else {
                self.retransmit_at = None;
            }
        }

        if self.role == Role::Initiator {
            let scheduled = self.rehandshake_at.is_some_and(|t| now >= t);
            if self.rehandshake_requested || scheduled {
                self.rehandshake_requested = false;
                self.rehandshake_at = None;
                self.attempt_started = None;
                out.extend(self.initiate(now));
            } else if self.pending.is_none() {
                let need = match &self.current {
                    Some(s) => s.needs_rekey(now),
                    None => self.auto_connect || !self.queue.is_empty(),
                } || self.new_handshake_due.is_some_and(|d| now >= d);
                if need {
                    self.new_handshake_due = None;
                    out.extend(self.initiate(now));
                }
            }
        }

        if self.keepalive_due.is_some_and(|d| now >= d) {
            self.keepalive_due = None;
            out.extend(self.keepalive(now));
        }
        if let Some(iv) = self.persistent_keepalive {
            let idle = self
                .last_sent
                .is_none_or(|t| now.saturating_duration_since(t) >= iv);
            if idle && self.current.is_some() {
                out.extend(self.keepalive(now));
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::noise::generate_private_key;

    fn pair(psk: Option<Key32>) -> (Peer, Peer) {
        let a = generate_private_key();
        let b = generate_private_key();
        let pa = noise::public_key(&a);
        let pb = noise::public_key(&b);
        (
            Peer::new_initiator(a, pb, psk.clone(), [0; 3]),
            Peer::new_responder(b, pa, psk, [0; 3]),
        )
    }

    fn ip(payload: &[u8]) -> Vec<u8> {
        vw_core::packet::build_udp(
            "10.0.0.1:1000".parse().unwrap(),
            "10.0.0.2:2000".parse().unwrap(),
            payload,
            64,
        )
        .unwrap()
    }

    /// Deliver datagrams back and forth until both sides are quiet.
    fn pump(a: &mut Peer, b: &mut Peer, mut to_b: Vec<Vec<u8>>, now: Instant) -> Vec<Vec<u8>> {
        let mut tunnel_b = Vec::new();
        let mut guard = 0;
        while !to_b.is_empty() && guard < 16 {
            guard += 1;
            let mut to_a = Vec::new();
            for d in to_b.drain(..) {
                match b.decapsulate(&d, now) {
                    Ok(Decapsulated::Network(v)) => to_a.extend(v),
                    Ok(Decapsulated::Tunnel(p)) => tunnel_b.push(p),
                    _ => {}
                }
            }
            to_a.extend(b.drain_outbox());
            for d in to_a {
                if let Ok(Decapsulated::Network(v)) = a.decapsulate(&d, now) {
                    to_b.extend(v);
                }
            }
            to_b.extend(a.drain_outbox());
        }
        tunnel_b
    }

    #[test]
    fn handshake_and_data() {
        let (mut a, mut b) = pair(None);
        let now = Instant::now();
        let pkt = ip(b"hello");
        let out = a.encapsulate(&pkt, now);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].len(), INITIATION_LEN);
        let got = pump(&mut a, &mut b, out, now);
        assert_eq!(got, vec![pkt.clone()]);
        assert!(a.session_established());
        assert!(b.session_established());
        // Reverse direction.
        let reply = ip(b"world");
        let d = b.encapsulate(&reply, now);
        assert_eq!(d.len(), 1);
        assert_eq!(
            a.decapsulate(&d[0], now).unwrap(),
            Decapsulated::Tunnel(reply)
        );
    }

    #[test]
    fn responder_never_initiates() {
        let (_a, mut b) = pair(None);
        let now = Instant::now();
        assert!(b.encapsulate(&ip(b"x"), now).is_empty());
        assert!(b.tick(now + Duration::from_secs(30)).is_empty());
        assert_eq!(b.queued_packets(), 1);
    }

    #[test]
    fn handshake_retransmit_and_give_up() {
        let (mut a, _b) = pair(None);
        let t0 = Instant::now();
        let first = a.tick(t0);
        assert_eq!(first.len(), 1);
        assert!(a.tick(t0 + Duration::from_secs(1)).is_empty());
        let re = a.tick(t0 + Duration::from_millis(5400));
        assert_eq!(re.len(), 1);
        assert_ne!(re[0], first[0]);
        a.encapsulate(&ip(b"q"), t0 + Duration::from_secs(6));
        assert_eq!(a.queued_packets(), 1);
        let mut t = t0 + Duration::from_secs(6);
        while t < t0 + Duration::from_secs(100) {
            t += Duration::from_secs(1);
            a.tick(t);
        }
        assert_eq!(a.queued_packets(), 0);
    }

    #[test]
    fn passive_keepalive_after_receive() {
        let (mut a, mut b) = pair(None);
        let now = Instant::now();
        let out = a.encapsulate(&ip(b"hello"), now);
        pump(&mut a, &mut b, out, now);
        // b received data and has sent nothing: keepalive after 10 s.
        assert!(b.tick(now + Duration::from_secs(5)).is_empty());
        let k = b.tick(now + Duration::from_secs(11));
        assert_eq!(k.len(), 1);
        assert_eq!(a.decapsulate(&k[0], now).unwrap(), Decapsulated::Keepalive);
    }

    #[test]
    fn persistent_keepalive() {
        let (a, mut b) = pair(None);
        let mut a = a.with_persistent_keepalive(Some(Duration::from_secs(25)));
        let now = Instant::now();
        let out = a.tick(now);
        pump(&mut a, &mut b, out, now);
        assert!(a.tick(now + Duration::from_secs(10)).is_empty());
        let k = a.tick(now + Duration::from_secs(26));
        assert_eq!(k.len(), 1);
        assert_eq!(b.decapsulate(&k[0], now).unwrap(), Decapsulated::Keepalive);
    }

    #[test]
    fn wrong_static_key_rejected() {
        let (mut a, _) = pair(None);
        let other = generate_private_key();
        let mut c = Peer::new_responder(
            noise::generate_private_key(),
            noise::public_key(&other),
            None,
            [0; 3],
        );
        let init = a.tick(Instant::now());
        // Not addressed to c: mac1 fails first.
        assert_eq!(
            c.decapsulate(&init[0], Instant::now()),
            Err(WgError::InvalidMac)
        );
    }

    #[test]
    fn padding_respects_mtu() {
        let (a, _) = pair(None);
        let a = a.with_mtu(1280);
        assert_eq!(a.padded_len(1), 16);
        assert_eq!(a.padded_len(16), 16);
        assert_eq!(a.padded_len(1279), 1280);
        assert_eq!(a.padded_len(1280), 1280);
        assert_eq!(a.padded_len(1300), 1300);
    }
}
