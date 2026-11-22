//! Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s primitives and WireGuard message
//! construction, exactly as specified in the WireGuard whitepaper (§5.4).
//!
//! This module is sans-IO and stateless: it builds and consumes the four
//! WireGuard message types. Per-peer state (timers, sessions, cookies) lives in
//! [`crate::peer::Peer`]; the multi-peer server view in [`crate::responder`].

use std::net::SocketAddr;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use blake2::digest::consts::U16;
use blake2::digest::{Digest, KeyInit, Mac};
use blake2::{Blake2s256, Blake2sMac};
use chacha20poly1305::aead::AeadInPlace;
use chacha20poly1305::{ChaCha20Poly1305, Nonce, Tag, XChaCha20Poly1305, XNonce};
use rand::rngs::OsRng;
use rand::RngCore;
use vw_core::secret::{Key32, Secret};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, Zeroizing};

use crate::error::WgError;

/// Noise protocol name mixed into the initial chaining key.
pub const CONSTRUCTION: &[u8] = b"Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s";
/// WireGuard protocol identifier mixed into the initial hash.
pub const IDENTIFIER: &[u8] = b"WireGuard v1 zx2c4 Jason@zx2c4.com";
/// Label for the mac1 key derivation.
pub const LABEL_MAC1: &[u8] = b"mac1----";
/// Label for the cookie encryption key derivation.
pub const LABEL_COOKIE: &[u8] = b"cookie--";

/// Message type: handshake initiation.
pub const TYPE_INITIATION: u8 = 1;
/// Message type: handshake response.
pub const TYPE_RESPONSE: u8 = 2;
/// Message type: cookie reply.
pub const TYPE_COOKIE_REPLY: u8 = 3;
/// Message type: transport data.
pub const TYPE_DATA: u8 = 4;

/// Size of a handshake initiation.
pub const INITIATION_LEN: usize = 148;
/// Size of a handshake response.
pub const RESPONSE_LEN: usize = 92;
/// Size of a cookie reply.
pub const COOKIE_REPLY_LEN: usize = 64;
/// Transport data header (type, reserved, receiver, counter).
pub const DATA_HEADER_LEN: usize = 16;
/// Poly1305 tag length.
pub const TAG_LEN: usize = 16;
/// Smallest valid transport data message (an empty keepalive).
pub const DATA_MIN_LEN: usize = DATA_HEADER_LEN + TAG_LEN;
/// TAI64N timestamp length.
pub const TIMESTAMP_LEN: usize = 12;

/// Cookie secrets rotate (and received cookies expire) after this long.
pub const COOKIE_REFRESH_TIME: Duration = Duration::from_secs(120);

/// The four WireGuard message kinds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageType {
    Initiation,
    Response,
    CookieReply,
    Data,
}

/// Classify a datagram by its type byte and length. Bytes 1..4 (reserved /
/// WARP client id) are deliberately ignored.
pub fn message_type(datagram: &[u8]) -> Option<MessageType> {
    match (datagram.first()?, datagram.len()) {
        (&TYPE_INITIATION, INITIATION_LEN) => Some(MessageType::Initiation),
        (&TYPE_RESPONSE, RESPONSE_LEN) => Some(MessageType::Response),
        (&TYPE_COOKIE_REPLY, COOKIE_REPLY_LEN) => Some(MessageType::CookieReply),
        (&TYPE_DATA, n) if n >= DATA_MIN_LEN => Some(MessageType::Data),
        _ => None,
    }
}

/// True when `datagram` is a handshake initiation (the driver calls
/// `StealthTransport::before_handshake` before sending these).
pub fn is_handshake_initiation(datagram: &[u8]) -> bool {
    message_type(datagram) == Some(MessageType::Initiation)
}

// ---------------------------------------------------------------------------
// Primitives
// ---------------------------------------------------------------------------

/// `HASH(input)` = BLAKE2s-256 over the concatenation of `parts`.
pub fn hash(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Blake2s256::new();
    for p in parts {
        Digest::update(&mut h, p);
    }
    h.finalize().into()
}

/// `MAC(key, input)` = keyed BLAKE2s with a 16-byte output. `key` ≤ 32 bytes.
pub fn mac(key: &[u8], parts: &[&[u8]]) -> [u8; 16] {
    // Keys passed here are always 16 or 32 bytes, within BLAKE2s' 32-byte limit.
    let mut m = <Blake2sMac<U16> as KeyInit>::new_from_slice(key)
        .expect("BLAKE2s MAC keys are at most 32 bytes");
    for p in parts {
        Mac::update(&mut m, p);
    }
    m.finalize().into_bytes().into()
}

/// `HMAC(key, input)` = RFC 2104 HMAC over BLAKE2s-256 (64-byte block).
pub fn hmac(key: &[u8; 32], parts: &[&[u8]]) -> [u8; 32] {
    let mut ipad = Zeroizing::new([0x36u8; 64]);
    let mut opad = Zeroizing::new([0x5cu8; 64]);
    for i in 0..32 {
        ipad[i] ^= key[i];
        opad[i] ^= key[i];
    }
    let mut inner = Blake2s256::new();
    Digest::update(&mut inner, ipad.as_slice());
    for p in parts {
        Digest::update(&mut inner, p);
    }
    let mut inner_out: [u8; 32] = inner.finalize().into();
    let out = hash(&[opad.as_slice(), &inner_out]);
    inner_out.zeroize();
    out
}

/// `KDF1(key, input)`.
pub fn kdf1(key: &[u8; 32], input: &[u8]) -> Zeroizing<[u8; 32]> {
    let t0 = Zeroizing::new(hmac(key, &[input]));
    Zeroizing::new(hmac(&t0, &[&[1u8]]))
}

/// `KDF2(key, input)`.
pub fn kdf2(key: &[u8; 32], input: &[u8]) -> (Zeroizing<[u8; 32]>, Zeroizing<[u8; 32]>) {
    let t0 = Zeroizing::new(hmac(key, &[input]));
    let t1 = Zeroizing::new(hmac(&t0, &[&[1u8]]));
    let t2 = Zeroizing::new(hmac(&t0, &[t1.as_slice(), &[2u8]]));
    (t1, t2)
}

/// `KDF3(key, input)`.
#[allow(clippy::type_complexity)]
pub fn kdf3(
    key: &[u8; 32],
    input: &[u8],
) -> (
    Zeroizing<[u8; 32]>,
    Zeroizing<[u8; 32]>,
    Zeroizing<[u8; 32]>,
) {
    let t0 = Zeroizing::new(hmac(key, &[input]));
    let t1 = Zeroizing::new(hmac(&t0, &[&[1u8]]));
    let t2 = Zeroizing::new(hmac(&t0, &[t1.as_slice(), &[2u8]]));
    let t3 = Zeroizing::new(hmac(&t0, &[t2.as_slice(), &[3u8]]));
    (t1, t2, t3)
}

fn nonce_for(counter: u64) -> Nonce {
    let mut n = [0u8; 12];
    n[4..].copy_from_slice(&counter.to_le_bytes());
    Nonce::from(n)
}

/// `AEAD(key, counter, plain, auth)`: ChaCha20-Poly1305 with a
/// `0^32 || LE64(counter)` nonce. Encrypts `buf` in place and appends the tag.
pub fn aead_seal(key: &[u8; 32], counter: u64, buf: &mut Vec<u8>, aad: &[u8]) {
    let cipher = ChaCha20Poly1305::new(key.into());
    // Encryption cannot fail for messages below the 256 GiB ChaCha20 limit.
    let tag = cipher
        .encrypt_in_place_detached(&nonce_for(counter), aad, buf)
        .expect("chacha20poly1305 encryption of a bounded buffer");
    buf.extend_from_slice(&tag);
}

/// Encrypt `plain` into `out` (`out.len() == plain.len() + 16`).
pub fn aead_seal_into(key: &[u8; 32], counter: u64, plain: &[u8], aad: &[u8], out: &mut [u8]) {
    debug_assert_eq!(out.len(), plain.len() + TAG_LEN);
    let (body, tag_out) = out.split_at_mut(plain.len());
    body.copy_from_slice(plain);
    let cipher = ChaCha20Poly1305::new(key.into());
    let tag = cipher
        .encrypt_in_place_detached(&nonce_for(counter), aad, body)
        .expect("chacha20poly1305 encryption of a bounded buffer");
    tag_out.copy_from_slice(&tag);
}

/// Decrypt `ct` (ciphertext || tag) in place into `buf`, returning the plaintext length.
pub fn aead_open_in_place(
    key: &[u8; 32],
    counter: u64,
    buf: &mut [u8],
    aad: &[u8],
) -> Result<usize, WgError> {
    if buf.len() < TAG_LEN {
        return Err(WgError::Malformed);
    }
    let n = buf.len() - TAG_LEN;
    let (body, tag) = buf.split_at_mut(n);
    let tag = Tag::clone_from_slice(tag);
    let cipher = ChaCha20Poly1305::new(key.into());
    cipher
        .decrypt_in_place_detached(&nonce_for(counter), aad, body, &tag)
        .map_err(|_| WgError::Decrypt)?;
    Ok(n)
}

/// Decrypt a fixed-size field, returning the plaintext in a zeroizing buffer.
fn aead_open_field<const N: usize>(
    key: &[u8; 32],
    ct: &[u8],
    aad: &[u8],
) -> Result<Zeroizing<[u8; N]>, WgError> {
    if ct.len() != N + TAG_LEN {
        return Err(WgError::Malformed);
    }
    let mut buf = Zeroizing::new(ct.to_vec());
    aead_open_in_place(key, 0, &mut buf, aad)?;
    let mut out = Zeroizing::new([0u8; N]);
    out.copy_from_slice(&buf[..N]);
    Ok(out)
}

/// `XAEAD(key, nonce, plain, auth)`: XChaCha20-Poly1305.
fn xaead_seal(key: &[u8; 32], nonce: &[u8; 24], plain: &[u8], aad: &[u8], out: &mut [u8]) {
    let (body, tag_out) = out.split_at_mut(plain.len());
    body.copy_from_slice(plain);
    let cipher = XChaCha20Poly1305::new(key.into());
    let tag = cipher
        .encrypt_in_place_detached(XNonce::from_slice(nonce), aad, body)
        .expect("xchacha20poly1305 encryption of a bounded buffer");
    tag_out.copy_from_slice(&tag);
}

fn xaead_open(key: &[u8; 32], nonce: &[u8], ct: &[u8], aad: &[u8]) -> Result<[u8; 16], WgError> {
    if ct.len() != 16 + TAG_LEN || nonce.len() != 24 {
        return Err(WgError::Malformed);
    }
    let mut body = [0u8; 16];
    body.copy_from_slice(&ct[..16]);
    let tag = Tag::clone_from_slice(&ct[16..]);
    let cipher = XChaCha20Poly1305::new(key.into());
    cipher
        .decrypt_in_place_detached(XNonce::from_slice(nonce), aad, &mut body, &tag)
        .map_err(|_| WgError::Decrypt)?;
    Ok(body)
}

/// X25519 with the all-zero (non-contributory) output rejected.
fn dh(private: &StaticSecret, public: &[u8; 32]) -> Result<Zeroizing<[u8; 32]>, WgError> {
    let shared = private.diffie_hellman(&PublicKey::from(*public));
    if !shared.was_contributory() {
        return Err(WgError::WeakKey);
    }
    Ok(Zeroizing::new(shared.to_bytes()))
}

/// Derive the X25519 public key for a WireGuard private key.
pub fn public_key(private: &Key32) -> [u8; 32] {
    let s = StaticSecret::from(*private.expose());
    PublicKey::from(&s).to_bytes()
}

/// Generate a fresh WireGuard private key from the OS CSPRNG.
pub fn generate_private_key() -> Key32 {
    let s = StaticSecret::random_from_rng(OsRng);
    Key32::new(s.to_bytes())
}

pub(crate) fn static_secret(k: &Key32) -> StaticSecret {
    StaticSecret::from(*k.expose())
}

fn initial_chain_key() -> [u8; 32] {
    hash(&[CONSTRUCTION])
}

fn initial_hash(responder_static: &[u8; 32]) -> [u8; 32] {
    let ck = initial_chain_key();
    let h = hash(&[&ck, IDENTIFIER]);
    hash(&[&h, responder_static])
}

/// mac1 key for messages addressed to the holder of `static_public`.
pub fn mac1_key(static_public: &[u8; 32]) -> [u8; 32] {
    hash(&[LABEL_MAC1, static_public])
}

/// Cookie encryption key for cookie replies sent by the holder of `static_public`.
pub fn cookie_key(static_public: &[u8; 32]) -> [u8; 32] {
    hash(&[LABEL_COOKIE, static_public])
}

/// Write mac1 (and mac2 when a cookie is held) into the last 32 bytes of a
/// handshake message. Returns the mac1 value (needed to decrypt cookie replies).
///
/// The MACs are computed with the three reserved header bytes (1..4) treated as
/// zero. Cloudflare WARP carries its client id there and validates MACs over the
/// zeroed header, as do WARP-capable clients (they stamp the bytes after the
/// MACs); with zero reserved bytes this is identical to standard WireGuard.
pub fn write_macs(msg: &mut [u8], mac1_key: &[u8; 32], cookie: Option<&[u8; 16]>) -> [u8; 16] {
    let n = msg.len();
    let m1 = mac_zero_reserved(mac1_key, msg, n - 32);
    msg[n - 32..n - 16].copy_from_slice(&m1);
    let m2 = match cookie {
        Some(c) => mac_zero_reserved(c, msg, n - 16),
        None => [0u8; 16],
    };
    msg[n - 16..].copy_from_slice(&m2);
    m1
}

/// MAC over `msg[..end]` with the reserved bytes 1..4 read as zero.
fn mac_zero_reserved(key: &[u8], msg: &[u8], end: usize) -> [u8; 16] {
    if end < 4 {
        return mac(key, &[&msg[..end]]);
    }
    mac(key, &[&msg[..1], &[0u8; 3], &msg[4..end]])
}

// ---------------------------------------------------------------------------
// TAI64N
// ---------------------------------------------------------------------------

/// TAI64N label offset used by WireGuard (`2^62 + 10`).
const TAI64_BASE: u64 = 0x4000_0000_0000_000a;
/// Timestamps are rounded down to 2^24 ns (~16.8 ms) like the Linux kernel,
/// so they do not leak precise timer values.
const TAI64N_QUANTUM_NS: u128 = 1 << 24;

/// Monotonic TAI64N source. The wall clock is sampled once at creation and
/// advanced with the caller-supplied `Instant`, so timestamps never go
/// backwards when the system clock is adjusted, and tests stay deterministic.
#[derive(Debug, Clone)]
pub struct Tai64nClock {
    wall_base_ns: u128,
    mono_base: Instant,
    last_ns: u128,
}

impl Tai64nClock {
    pub fn new(now: Instant) -> Self {
        let wall = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        Self {
            wall_base_ns: wall,
            mono_base: now,
            last_ns: 0,
        }
    }

    /// A strictly increasing TAI64N timestamp for `now`.
    pub fn stamp(&mut self, now: Instant) -> [u8; TIMESTAMP_LEN] {
        let elapsed = now.saturating_duration_since(self.mono_base).as_nanos();
        let mut t = (self.wall_base_ns + elapsed) / TAI64N_QUANTUM_NS * TAI64N_QUANTUM_NS;
        if t <= self.last_ns {
            t = self.last_ns + TAI64N_QUANTUM_NS;
        }
        self.last_ns = t;
        encode_tai64n(t)
    }
}

fn encode_tai64n(total_ns: u128) -> [u8; TIMESTAMP_LEN] {
    let secs = (total_ns / 1_000_000_000) as u64;
    let nanos = (total_ns % 1_000_000_000) as u32;
    let mut out = [0u8; TIMESTAMP_LEN];
    out[..8].copy_from_slice(&TAI64_BASE.wrapping_add(secs).to_be_bytes());
    out[8..].copy_from_slice(&nanos.to_be_bytes());
    out
}

// ---------------------------------------------------------------------------
// Handshake messages
// ---------------------------------------------------------------------------

/// Initiator state kept between sending message 1 and receiving message 2.
pub(crate) struct InitiatorState {
    pub local_index: u32,
    chaining_key: Key32,
    hash: [u8; 32],
    ephemeral: StaticSecret,
}

impl std::fmt::Debug for InitiatorState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InitiatorState")
            .field("local_index", &self.local_index)
            .finish_non_exhaustive()
    }
}

/// Symmetric transport keys derived at the end of a handshake.
pub(crate) struct TransportKeys {
    pub send: Key32,
    pub recv: Key32,
}

/// Build handshake initiation (message 1) into `out` (without macs).
pub(crate) fn create_initiation(
    local_static: &StaticSecret,
    local_public: &[u8; 32],
    remote_static: &[u8; 32],
    local_index: u32,
    timestamp: &[u8; TIMESTAMP_LEN],
    reserved: [u8; 3],
    out: &mut [u8; INITIATION_LEN],
) -> Result<InitiatorState, WgError> {
    out.fill(0);
    out[0] = TYPE_INITIATION;
    out[1..4].copy_from_slice(&reserved);
    out[4..8].copy_from_slice(&local_index.to_le_bytes());

    let mut ck = Zeroizing::new(initial_chain_key());
    let mut h = initial_hash(remote_static);

    let eph = StaticSecret::random_from_rng(OsRng);
    let eph_pub = PublicKey::from(&eph).to_bytes();
    ck = kdf1(&ck, &eph_pub);
    out[8..40].copy_from_slice(&eph_pub);
    h = hash(&[&h, &eph_pub]);

    let ss = dh(&eph, remote_static)?;
    let (c, k) = kdf2(&ck, ss.as_slice());
    ck = c;
    aead_seal_into(&k, 0, local_public, &h, &mut out[40..88]);
    h = hash(&[&h, &out[40..88]]);

    let ss = dh(local_static, remote_static)?;
    let (c, k) = kdf2(&ck, ss.as_slice());
    ck = c;
    aead_seal_into(&k, 0, timestamp, &h, &mut out[88..116]);
    h = hash(&[&h, &out[88..116]]);

    Ok(InitiatorState {
        local_index,
        chaining_key: Key32::new(*ck),
        hash: h,
        ephemeral: eph,
    })
}

/// A decrypted, authenticated (but not yet replay-checked) initiation.
pub(crate) struct ReceivedInitiation {
    pub remote_static: [u8; 32],
    pub sender_index: u32,
    pub remote_ephemeral: [u8; 32],
    pub timestamp: [u8; TIMESTAMP_LEN],
    chaining_key: Key32,
    hash: [u8; 32],
}

/// Consume message 1 with the local static key (responder side).
pub(crate) fn consume_initiation(
    local_static: &StaticSecret,
    local_public: &[u8; 32],
    msg: &[u8],
) -> Result<ReceivedInitiation, WgError> {
    if msg.len() != INITIATION_LEN || msg[0] != TYPE_INITIATION {
        return Err(WgError::Malformed);
    }
    let sender_index = u32::from_le_bytes([msg[4], msg[5], msg[6], msg[7]]);
    let mut e_i = [0u8; 32];
    e_i.copy_from_slice(&msg[8..40]);

    let mut ck = Zeroizing::new(initial_chain_key());
    let mut h = initial_hash(local_public);
    ck = kdf1(&ck, &e_i);
    h = hash(&[&h, &e_i]);

    let ss = dh(local_static, &e_i)?;
    let (c, k) = kdf2(&ck, ss.as_slice());
    ck = c;
    let s_i = aead_open_field::<32>(&k, &msg[40..88], &h)?;
    h = hash(&[&h, &msg[40..88]]);

    let ss = dh(local_static, &s_i)?;
    let (c, k) = kdf2(&ck, ss.as_slice());
    ck = c;
    let ts = aead_open_field::<TIMESTAMP_LEN>(&k, &msg[88..116], &h)?;
    h = hash(&[&h, &msg[88..116]]);

    Ok(ReceivedInitiation {
        remote_static: *s_i,
        sender_index,
        remote_ephemeral: e_i,
        timestamp: *ts,
        chaining_key: Key32::new(*ck),
        hash: h,
    })
}

/// Build handshake response (message 2, without macs) and derive transport keys.
pub(crate) fn create_response(
    init: &ReceivedInitiation,
    psk: &Key32,
    local_index: u32,
    reserved: [u8; 3],
    out: &mut [u8; RESPONSE_LEN],
) -> Result<TransportKeys, WgError> {
    out.fill(0);
    out[0] = TYPE_RESPONSE;
    out[1..4].copy_from_slice(&reserved);
    out[4..8].copy_from_slice(&local_index.to_le_bytes());
    out[8..12].copy_from_slice(&init.sender_index.to_le_bytes());

    let mut ck = Zeroizing::new(*init.chaining_key.expose());
    let mut h = init.hash;

    let eph = StaticSecret::random_from_rng(OsRng);
    let eph_pub = PublicKey::from(&eph).to_bytes();
    ck = kdf1(&ck, &eph_pub);
    out[12..44].copy_from_slice(&eph_pub);
    h = hash(&[&h, &eph_pub]);

    let ss = dh(&eph, &init.remote_ephemeral)?;
    ck = kdf1(&ck, ss.as_slice());
    let ss = dh(&eph, &init.remote_static)?;
    ck = kdf1(&ck, ss.as_slice());

    let (c, tau, k) = kdf3(&ck, psk.expose());
    ck = c;
    h = hash(&[&h, tau.as_slice()]);
    aead_seal_into(&k, 0, &[], &h, &mut out[44..60]);

    let (recv, send) = kdf2(&ck, &[]);
    Ok(TransportKeys {
        send: Key32::new(*send),
        recv: Key32::new(*recv),
    })
}

/// Consume message 2 on the initiator side and derive transport keys.
pub(crate) fn consume_response(
    state: &InitiatorState,
    local_static: &StaticSecret,
    psk: &Key32,
    msg: &[u8],
) -> Result<(TransportKeys, u32), WgError> {
    if msg.len() != RESPONSE_LEN || msg[0] != TYPE_RESPONSE {
        return Err(WgError::Malformed);
    }
    let sender_index = u32::from_le_bytes([msg[4], msg[5], msg[6], msg[7]]);
    let receiver_index = u32::from_le_bytes([msg[8], msg[9], msg[10], msg[11]]);
    if receiver_index != state.local_index {
        return Err(WgError::UnknownIndex);
    }
    let mut e_r = [0u8; 32];
    e_r.copy_from_slice(&msg[12..44]);

    let mut ck = Zeroizing::new(*state.chaining_key.expose());
    let mut h = state.hash;
    ck = kdf1(&ck, &e_r);
    h = hash(&[&h, &e_r]);
    let ss = dh(&state.ephemeral, &e_r)?;
    ck = kdf1(&ck, ss.as_slice());
    let ss = dh(local_static, &e_r)?;
    ck = kdf1(&ck, ss.as_slice());

    let (c, tau, k) = kdf3(&ck, psk.expose());
    ck = c;
    h = hash(&[&h, tau.as_slice()]);
    aead_open_field::<0>(&k, &msg[44..60], &h)?;

    let (send, recv) = kdf2(&ck, &[]);
    Ok((
        TransportKeys {
            send: Key32::new(*send),
            recv: Key32::new(*recv),
        },
        sender_index,
    ))
}

/// Build a cookie reply (message 3) answering a handshake message whose
/// sender index is `receiver_index` and whose mac1 was `mac1`.
pub(crate) fn create_cookie_reply(
    cookie_key: &[u8; 32],
    receiver_index: u32,
    cookie: &[u8; 16],
    mac1: &[u8],
    reserved: [u8; 3],
) -> Vec<u8> {
    let mut out = vec![0u8; COOKIE_REPLY_LEN];
    out[0] = TYPE_COOKIE_REPLY;
    out[1..4].copy_from_slice(&reserved);
    out[4..8].copy_from_slice(&receiver_index.to_le_bytes());
    let mut nonce = [0u8; 24];
    OsRng.fill_bytes(&mut nonce);
    out[8..32].copy_from_slice(&nonce);
    xaead_seal(cookie_key, &nonce, cookie, mac1, &mut out[32..64]);
    out
}

/// Decrypt a cookie reply with the remote's cookie key and our last mac1.
pub(crate) fn consume_cookie_reply(
    cookie_key: &[u8; 32],
    msg: &[u8],
    last_mac1: &[u8; 16],
) -> Result<[u8; 16], WgError> {
    if msg.len() != COOKIE_REPLY_LEN || msg[0] != TYPE_COOKIE_REPLY {
        return Err(WgError::Malformed);
    }
    xaead_open(cookie_key, &msg[8..32], &msg[32..64], last_mac1)
}

// ---------------------------------------------------------------------------
// Cookie checker (responder side of the DoS mitigation)
// ---------------------------------------------------------------------------

/// Result of checking the macs of an incoming handshake message.
#[derive(Debug, PartialEq, Eq)]
pub enum MacCheck {
    /// mac1 valid and (if under load) mac2 valid: process the message.
    Accept,
    /// Under load without a valid mac2: send this cookie reply instead.
    SendCookie(Vec<u8>),
}

/// Validates mac1/mac2 and issues cookies. The cookie secret rotates every
/// [`COOKIE_REFRESH_TIME`].
pub struct CookieChecker {
    mac1_key: [u8; 32],
    cookie_key: [u8; 32],
    secret: Key32,
    secret_born: Option<Instant>,
}

impl std::fmt::Debug for CookieChecker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CookieChecker").finish_non_exhaustive()
    }
}

impl CookieChecker {
    /// Checker for messages addressed to the holder of `local_public`.
    pub fn new(local_public: &[u8; 32]) -> Self {
        Self {
            mac1_key: mac1_key(local_public),
            cookie_key: cookie_key(local_public),
            secret: Key32::random(),
            secret_born: None,
        }
    }

    /// Verify mac1 (constant time).
    pub fn verify_mac1(&self, msg: &[u8]) -> bool {
        let n = msg.len();
        if n < 32 {
            return false;
        }
        let expect = mac_zero_reserved(&self.mac1_key, msg, n - 32);
        subtle_eq(&expect, &msg[n - 32..n - 16])
    }

    fn current_secret(&mut self, now: Instant) -> &Key32 {
        let stale = match self.secret_born {
            Some(b) => now.saturating_duration_since(b) >= COOKIE_REFRESH_TIME,
            None => true,
        };
        if stale {
            self.secret = Key32::random();
            self.secret_born = Some(now);
        }
        &self.secret
    }

    /// `τ = MAC(Rm, Am)`: the cookie for a source address.
    pub fn cookie_for(&mut self, src: &SocketAddr, now: Instant) -> [u8; 16] {
        let addr = addr_bytes(src);
        let secret = self.current_secret(now);
        mac(secret.expose(), &[&addr])
    }

    /// Check an incoming handshake message (initiation or response).
    pub fn check(
        &mut self,
        msg: &[u8],
        src: Option<&SocketAddr>,
        under_load: bool,
        reserved: [u8; 3],
        now: Instant,
    ) -> Result<MacCheck, WgError> {
        if !self.verify_mac1(msg) {
            return Err(WgError::InvalidMac);
        }
        let Some(src) = src.filter(|_| under_load) else {
            return Ok(MacCheck::Accept);
        };
        let n = msg.len();
        let cookie = self.cookie_for(src, now);
        let expect = mac_zero_reserved(&cookie, msg, n - 16);
        if subtle_eq(&expect, &msg[n - 16..]) {
            return Ok(MacCheck::Accept);
        }
        let sender = u32::from_le_bytes([msg[4], msg[5], msg[6], msg[7]]);
        Ok(MacCheck::SendCookie(create_cookie_reply(
            &self.cookie_key,
            sender,
            &cookie,
            &msg[n - 32..n - 16],
            reserved,
        )))
    }
}

fn subtle_eq(a: &[u8], b: &[u8]) -> bool {
    use subtle::ConstantTimeEq;
    a.len() == b.len() && bool::from(a.ct_eq(b))
}

fn addr_bytes(src: &SocketAddr) -> Vec<u8> {
    let mut v = match src.ip() {
        std::net::IpAddr::V4(a) => a.octets().to_vec(),
        std::net::IpAddr::V6(a) => a.octets().to_vec(),
    };
    v.extend_from_slice(&src.port().to_be_bytes());
    v
}

/// Handshake rate meter deciding "under load" for cookie mode.
#[derive(Debug, Clone)]
pub struct LoadMeter {
    threshold_per_sec: u32,
    window_start: Option<Instant>,
    count: u32,
    forced: Option<bool>,
}

/// Default handshake messages per second above which cookie mode engages.
pub const DEFAULT_LOAD_THRESHOLD: u32 = 64;

impl Default for LoadMeter {
    fn default() -> Self {
        Self::new(DEFAULT_LOAD_THRESHOLD)
    }
}

impl LoadMeter {
    pub fn new(threshold_per_sec: u32) -> Self {
        Self {
            threshold_per_sec,
            window_start: None,
            count: 0,
            forced: None,
        }
    }

    /// Force cookie mode on/off (operator override), or `None` for automatic.
    pub fn force(&mut self, forced: Option<bool>) {
        self.forced = forced;
    }

    /// Record one handshake message and report whether we are under load.
    pub fn record(&mut self, now: Instant) -> bool {
        match self.window_start {
            Some(s) if now.saturating_duration_since(s) < Duration::from_secs(1) => {
                self.count = self.count.saturating_add(1);
            }
            _ => {
                self.window_start = Some(now);
                self.count = 1;
            }
        }
        self.forced.unwrap_or(self.count > self.threshold_per_sec)
    }
}

/// A 16-byte cookie received from a peer, with the time it arrived.
pub(crate) type Cookie = Secret<16>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn construction_constants() {
        // Initial chaining key and hash as computed by every WireGuard implementation.
        let ck = initial_chain_key();
        assert_eq!(
            hex(&ck),
            "60e26daef327efc02ec335e2a025d2d016eb4206f87277f52d38d1988b78cd36"
        );
        let h = hash(&[&ck, IDENTIFIER]);
        assert_eq!(
            hex(&h),
            "2211b361081ac566691243db458ad5322d9c6c662293e8b70ee19c65ba079ef3"
        );
    }

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    #[test]
    fn hmac_blake2s_matches_rfc2104_construction() {
        // HMAC with a 32-byte key == H(K^opad || H(K^ipad || m)).
        let key = [0x0bu8; 32];
        let mut ipad = [0x36u8; 64];
        let mut opad = [0x5cu8; 64];
        for i in 0..32 {
            ipad[i] ^= key[i];
            opad[i] ^= key[i];
        }
        let inner = hash(&[&ipad, b"Hi There"]);
        let expect = hash(&[&opad, &inner]);
        assert_eq!(hmac(&key, &[b"Hi ", b"There"]), expect);
    }

    #[test]
    fn tai64n_strictly_increases() {
        let t0 = Instant::now();
        let mut c = Tai64nClock::new(t0);
        let a = c.stamp(t0);
        let b = c.stamp(t0);
        let d = c.stamp(t0 + Duration::from_secs(1));
        assert!(a < b && b < d);
        assert_eq!(&a[..2], &[0x40, 0x00]);
    }

    #[test]
    fn full_handshake_keys_agree() {
        let si = generate_private_key();
        let sr = generate_private_key();
        let (pi, pr) = (public_key(&si), public_key(&sr));
        let psk = Key32::new([3u8; 32]);
        let mut m1 = [0u8; INITIATION_LEN];
        let st = create_initiation(
            &static_secret(&si),
            &pi,
            &pr,
            7,
            &[1u8; 12],
            [0; 3],
            &mut m1,
        )
        .unwrap();
        let ri = consume_initiation(&static_secret(&sr), &pr, &m1).unwrap();
        assert_eq!(ri.remote_static, pi);
        assert_eq!(ri.sender_index, 7);
        assert_eq!(ri.timestamp, [1u8; 12]);
        let mut m2 = [0u8; RESPONSE_LEN];
        let rk = create_response(&ri, &psk, 9, [0; 3], &mut m2).unwrap();
        let (ik, idx) = consume_response(&st, &static_secret(&si), &psk, &m2).unwrap();
        assert_eq!(idx, 9);
        assert_eq!(ik.send, rk.recv);
        assert_eq!(ik.recv, rk.send);
        // Wrong PSK fails key confirmation.
        assert_eq!(
            consume_response(&st, &static_secret(&si), &Key32::zero(), &m2).err(),
            Some(WgError::Decrypt)
        );
    }

    #[test]
    fn cookie_reply_roundtrip() {
        let sr = generate_private_key();
        let pr = public_key(&sr);
        let mut checker = CookieChecker::new(&pr);
        let mut msg = vec![0u8; INITIATION_LEN];
        msg[0] = TYPE_INITIATION;
        msg[4..8].copy_from_slice(&5u32.to_le_bytes());
        let m1 = write_macs(&mut msg, &mac1_key(&pr), None);
        let src: SocketAddr = "198.51.100.7:4444".parse().unwrap();
        let now = Instant::now();
        assert_eq!(
            checker.check(&msg, Some(&src), false, [0; 3], now).unwrap(),
            MacCheck::Accept
        );
        let MacCheck::SendCookie(reply) =
            checker.check(&msg, Some(&src), true, [0; 3], now).unwrap()
        else {
            panic!("expected cookie");
        };
        assert_eq!(reply.len(), COOKIE_REPLY_LEN);
        let cookie = consume_cookie_reply(&cookie_key(&pr), &reply, &m1).unwrap();
        write_macs(&mut msg, &mac1_key(&pr), Some(&cookie));
        assert_eq!(
            checker.check(&msg, Some(&src), true, [0; 3], now).unwrap(),
            MacCheck::Accept
        );
        msg[20] ^= 1;
        assert_eq!(
            checker.check(&msg, Some(&src), false, [0; 3], now),
            Err(WgError::InvalidMac)
        );
    }
}
