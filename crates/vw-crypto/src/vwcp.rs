//! VWCP — the in-tunnel post-quantum control protocol (ARCHITECTURE.md §6).
//!
//! Sans-IO: every function consumes message *bodies* or raw datagrams and
//! returns datagrams to send. Time is passed in explicitly ([`Reassembler`]),
//! so the whole protocol is deterministic under test.
//!
//! ```text
//! header (8 B) = "VWCP" | ver u8 = 1 | type u8 | frag_idx u8 | frag_cnt u8
//!
//! 0x01 ClientHello = epoch u32 · client_nonce[32] · client_x25519_eph[32] · token_len u16 · token
//! 0x02 ServerHello = epoch u32 · server_nonce[32] · server_x25519_eph[32] · session_id[16]
//!                    · mlkem_ek[1568] · sig[64]
//! 0x03 ClientKem   = session_id[16] · mlkem_ct[1568] · confirm[32]
//! 0x04 ServerAck   = session_id[16] · v4[4] · v4_prefix u8 · v6[16] · v6_prefix u8
//!                    · rotate_secs u16 · confirm[32]
//! 0x05 Error       = code u16 · reason_len u8 · reason utf8
//! ```
//!
//! All integers are big-endian. Bodies longer than [`MAX_FRAGMENT_BODY`] are
//! split into fragments of exactly 1200 bytes except the last.
//!
//! ```text
//! transcript = BLAKE3(ClientHello body || ServerHello body without sig)
//! sig        = Ed25519(node_identity, "VWCP-SH-v1" || transcript)
//! th         = BLAKE3(transcript || ClientKem.mlkem_ct)
//! ```
//! Key schedule: see [`crate::kdf`].

use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::{Duration, Instant};

use rand::RngCore;
use subtle::ConstantTimeEq;
use vw_core::config::Bytes32;
use vw_core::consts::PQ_ROTATE_SECS;
use vw_core::secret::Key32;

use crate::error::{CryptoError, Result};
use crate::hybrid::{mlkem_encapsulate, MlKemKeypair, X25519Ephemeral, MLKEM_CT_LEN, MLKEM_EK_LEN};
use crate::identity::{self, NodeIdentity, SIGNATURE_LEN};
use crate::kdf::{derive_session_keys, SessionKeys};

/// Header magic.
pub const MAGIC: [u8; 4] = *b"VWCP";
/// Protocol version carried in every header.
pub const VERSION: u8 = 1;
/// Header length in bytes.
pub const HEADER_LEN: usize = 8;
/// Maximum fragment body length.
pub const MAX_FRAGMENT_BODY: usize = 1200;
/// Maximum fragments per message (`frag_cnt` is a `u8`).
pub const MAX_FRAGMENTS: usize = 255;
/// Reassembly timeout.
pub const REASSEMBLY_TIMEOUT: Duration = Duration::from_secs(2);
/// Domain separator of the ServerHello signature.
pub const SH_SIG_DOMAIN: &[u8] = b"VWCP-SH-v1";

/// Fixed part of ClientHello (everything except the token).
pub const CLIENT_HELLO_FIXED_LEN: usize = 4 + 32 + 32 + 2;
/// ServerHello body length.
pub const SERVER_HELLO_LEN: usize = 4 + 32 + 32 + 16 + MLKEM_EK_LEN + SIGNATURE_LEN;
/// Signed prefix of the ServerHello body (all but `sig`).
pub const SERVER_HELLO_SIGNED_LEN: usize = SERVER_HELLO_LEN - SIGNATURE_LEN;
/// ClientKem body length.
pub const CLIENT_KEM_LEN: usize = 16 + MLKEM_CT_LEN + 32;
/// ServerAck body length.
pub const SERVER_ACK_LEN: usize = 16 + 4 + 1 + 16 + 1 + 2 + 32;
/// Fixed part of the Error body.
pub const ERROR_FIXED_LEN: usize = 3;

/// VWCP error codes carried in [`ErrorMsg`].
pub mod error_code {
    /// Malformed or unexpected message.
    pub const BAD_MESSAGE: u16 = 1;
    /// Unsupported protocol version.
    pub const UNSUPPORTED_VERSION: u16 = 2;
    /// Capability token refused (invalid, spent, wrong tier).
    pub const TOKEN_REJECTED: u16 = 3;
    /// Epoch replayed or stale.
    pub const EPOCH_REJECTED: u16 = 4;
    /// Key confirmation failed.
    pub const CONFIRM_FAILED: u16 = 5;
    /// Unknown session id.
    pub const SESSION_UNKNOWN: u16 = 6;
    /// Node-side failure.
    pub const INTERNAL: u16 = 7;
    /// Too many handshakes from this peer.
    pub const RATE_LIMITED: u16 = 8;
}

/// VWCP message types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum MsgType {
    /// 0x01, client → node.
    ClientHello = 0x01,
    /// 0x02, node → client.
    ServerHello = 0x02,
    /// 0x03, client → node.
    ClientKem = 0x03,
    /// 0x04, node → client.
    ServerAck = 0x04,
    /// 0x05, either direction.
    Error = 0x05,
}

impl MsgType {
    /// Parse a type byte.
    pub fn from_u8(b: u8) -> Result<Self> {
        Ok(match b {
            0x01 => MsgType::ClientHello,
            0x02 => MsgType::ServerHello,
            0x03 => MsgType::ClientKem,
            0x04 => MsgType::ServerAck,
            0x05 => MsgType::Error,
            other => return Err(CryptoError::UnexpectedType(other)),
        })
    }
}

/// A parsed 8-byte VWCP header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    /// Message type.
    pub ty: MsgType,
    /// Zero-based fragment index.
    pub frag_idx: u8,
    /// Total fragments of the message (≥ 1).
    pub frag_cnt: u8,
}

impl Header {
    /// Serialize to the 8 wire bytes.
    pub fn encode(&self) -> [u8; HEADER_LEN] {
        [
            MAGIC[0],
            MAGIC[1],
            MAGIC[2],
            MAGIC[3],
            VERSION,
            self.ty as u8,
            self.frag_idx,
            self.frag_cnt,
        ]
    }

    /// Parse and validate one datagram, returning the header and fragment body.
    ///
    /// Enforces: magic, version 1, known type, `frag_cnt ≥ 1`,
    /// `frag_idx < frag_cnt`, body ≤ 1200 bytes, non-final fragments exactly
    /// 1200 bytes and non-empty final fragments of multi-fragment messages.
    pub fn parse(datagram: &[u8]) -> Result<(Header, &[u8])> {
        if datagram.len() < HEADER_LEN {
            return Err(CryptoError::Malformed("VWCP header"));
        }
        if datagram[..4] != MAGIC {
            return Err(CryptoError::Malformed("VWCP magic"));
        }
        if datagram[4] != VERSION {
            return Err(CryptoError::Version(datagram[4]));
        }
        let ty = MsgType::from_u8(datagram[5])?;
        let (frag_idx, frag_cnt) = (datagram[6], datagram[7]);
        if frag_cnt == 0 || frag_idx >= frag_cnt {
            return Err(CryptoError::Malformed("VWCP fragment index"));
        }
        let body = &datagram[HEADER_LEN..];
        if body.len() > MAX_FRAGMENT_BODY {
            return Err(CryptoError::Malformed("VWCP fragment too large"));
        }
        let last = frag_idx + 1 == frag_cnt;
        if !last && body.len() != MAX_FRAGMENT_BODY {
            return Err(CryptoError::Malformed("VWCP short non-final fragment"));
        }
        if last && frag_cnt > 1 && body.is_empty() {
            return Err(CryptoError::Malformed("VWCP empty final fragment"));
        }
        Ok((
            Header {
                ty,
                frag_idx,
                frag_cnt,
            },
            body,
        ))
    }
}

/// Split a message body into header-prefixed datagrams.
pub fn fragment(ty: MsgType, body: &[u8]) -> Result<Vec<Vec<u8>>> {
    let cnt = body.len().div_ceil(MAX_FRAGMENT_BODY).max(1);
    if cnt > MAX_FRAGMENTS {
        return Err(CryptoError::Length {
            what: "VWCP message",
            expected: MAX_FRAGMENTS * MAX_FRAGMENT_BODY,
            got: body.len(),
        });
    }
    let mut out = Vec::with_capacity(cnt);
    for idx in 0..cnt {
        let start = idx * MAX_FRAGMENT_BODY;
        let end = (start + MAX_FRAGMENT_BODY).min(body.len());
        let hdr = Header {
            ty,
            frag_idx: idx as u8,
            frag_cnt: cnt as u8,
        };
        let mut d = Vec::with_capacity(HEADER_LEN + end - start);
        d.extend_from_slice(&hdr.encode());
        d.extend_from_slice(&body[start..end]);
        out.push(d);
    }
    Ok(out)
}

/// A fully reassembled VWCP message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    /// Message type.
    pub ty: MsgType,
    /// Concatenated body.
    pub body: Vec<u8>,
}

struct Partial {
    started: Instant,
    parts: Vec<Option<Vec<u8>>>,
    have: usize,
}

/// Fragment reassembly keyed by `(type, frag_cnt)` with a fixed timeout.
///
/// Duplicate fragments are ignored; a partial message older than the timeout
/// is discarded. The caller supplies `now`, making behaviour deterministic.
pub struct Reassembler {
    pending: HashMap<(u8, u8), Partial>,
    timeout: Duration,
}

impl Default for Reassembler {
    fn default() -> Self {
        Self::new()
    }
}

impl Reassembler {
    /// Reassembler with the protocol's 2 s timeout.
    pub fn new() -> Self {
        Self::with_timeout(REASSEMBLY_TIMEOUT)
    }

    /// Reassembler with a custom timeout.
    pub fn with_timeout(timeout: Duration) -> Self {
        Self {
            pending: HashMap::new(),
            timeout,
        }
    }

    /// Number of partially received messages.
    pub fn pending(&self) -> usize {
        self.pending.len()
    }

    /// Drop partial messages whose first fragment arrived ≥ timeout ago.
    pub fn expire(&mut self, now: Instant) {
        let timeout = self.timeout;
        self.pending
            .retain(|_, p| now.saturating_duration_since(p.started) < timeout);
    }

    /// Feed one datagram. Returns the message once every fragment is present.
    pub fn push(&mut self, datagram: &[u8], now: Instant) -> Result<Option<Message>> {
        let (hdr, body) = Header::parse(datagram)?;
        self.expire(now);
        if hdr.frag_cnt == 1 {
            return Ok(Some(Message {
                ty: hdr.ty,
                body: body.to_vec(),
            }));
        }
        let key = (hdr.ty as u8, hdr.frag_cnt);
        let partial = self.pending.entry(key).or_insert_with(|| Partial {
            started: now,
            parts: vec![None; hdr.frag_cnt as usize],
            have: 0,
        });
        let slot = &mut partial.parts[hdr.frag_idx as usize];
        if slot.is_none() {
            *slot = Some(body.to_vec());
            partial.have += 1;
        }
        if partial.have < partial.parts.len() {
            return Ok(None);
        }
        let done = self
            .pending
            .remove(&key)
            .ok_or(CryptoError::State("reassembly entry vanished"))?;
        let mut out = Vec::with_capacity(done.parts.len() * MAX_FRAGMENT_BODY);
        for part in done.parts.into_iter().flatten() {
            out.extend_from_slice(&part);
        }
        Ok(Some(Message {
            ty: hdr.ty,
            body: out,
        }))
    }
}

fn arr<const N: usize>(b: &[u8]) -> [u8; N] {
    let mut a = [0u8; N];
    a.copy_from_slice(&b[..N]);
    a
}

fn exact_len(what: &'static str, body: &[u8], expected: usize) -> Result<()> {
    if body.len() != expected {
        return Err(CryptoError::Length {
            what,
            expected,
            got: body.len(),
        });
    }
    Ok(())
}

/// ClientHello body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientHello {
    /// Rotation epoch requested by the client.
    pub epoch: u32,
    /// Fresh client nonce.
    pub client_nonce: [u8; 32],
    /// Client ephemeral X25519 public key.
    pub client_eph: [u8; 32],
    /// Capability token (empty in `open-owner` mode).
    pub token: Vec<u8>,
}

impl ClientHello {
    /// Encode the body.
    pub fn encode(&self) -> Result<Vec<u8>> {
        let tlen = u16::try_from(self.token.len()).map_err(|_| CryptoError::Length {
            what: "VWCP token",
            expected: u16::MAX as usize,
            got: self.token.len(),
        })?;
        let mut b = Vec::with_capacity(CLIENT_HELLO_FIXED_LEN + self.token.len());
        b.extend_from_slice(&self.epoch.to_be_bytes());
        b.extend_from_slice(&self.client_nonce);
        b.extend_from_slice(&self.client_eph);
        b.extend_from_slice(&tlen.to_be_bytes());
        b.extend_from_slice(&self.token);
        Ok(b)
    }

    /// Decode with exact length checks.
    pub fn decode(b: &[u8]) -> Result<Self> {
        if b.len() < CLIENT_HELLO_FIXED_LEN {
            return Err(CryptoError::Length {
                what: "ClientHello",
                expected: CLIENT_HELLO_FIXED_LEN,
                got: b.len(),
            });
        }
        let tlen = u16::from_be_bytes([b[68], b[69]]) as usize;
        exact_len("ClientHello", b, CLIENT_HELLO_FIXED_LEN + tlen)?;
        Ok(Self {
            epoch: u32::from_be_bytes(arr(&b[0..4])),
            client_nonce: arr(&b[4..36]),
            client_eph: arr(&b[36..68]),
            token: b[70..].to_vec(),
        })
    }
}

/// ServerHello body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerHello {
    /// Echo of the client's epoch.
    pub epoch: u32,
    /// Fresh server nonce.
    pub server_nonce: [u8; 32],
    /// Server ephemeral X25519 public key.
    pub server_eph: [u8; 32],
    /// Server-chosen session id.
    pub session_id: [u8; 16],
    /// ML-KEM-1024 encapsulation key (1568 bytes).
    pub mlkem_ek: Vec<u8>,
    /// Ed25519 signature over `"VWCP-SH-v1" || transcript`.
    pub sig: [u8; 64],
}

impl ServerHello {
    fn encode_unsigned(&self) -> Result<Vec<u8>> {
        exact_len("ML-KEM encapsulation key", &self.mlkem_ek, MLKEM_EK_LEN)?;
        let mut b = Vec::with_capacity(SERVER_HELLO_LEN);
        b.extend_from_slice(&self.epoch.to_be_bytes());
        b.extend_from_slice(&self.server_nonce);
        b.extend_from_slice(&self.server_eph);
        b.extend_from_slice(&self.session_id);
        b.extend_from_slice(&self.mlkem_ek);
        Ok(b)
    }

    /// Encode the full body including `sig`.
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut b = self.encode_unsigned()?;
        b.extend_from_slice(&self.sig);
        Ok(b)
    }

    /// Decode with exact length checks.
    pub fn decode(b: &[u8]) -> Result<Self> {
        exact_len("ServerHello", b, SERVER_HELLO_LEN)?;
        Ok(Self {
            epoch: u32::from_be_bytes(arr(&b[0..4])),
            server_nonce: arr(&b[4..36]),
            server_eph: arr(&b[36..68]),
            session_id: arr(&b[68..84]),
            mlkem_ek: b[84..84 + MLKEM_EK_LEN].to_vec(),
            sig: arr(&b[SERVER_HELLO_SIGNED_LEN..]),
        })
    }
}

/// ClientKem body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientKem {
    /// Session id from ServerHello.
    pub session_id: [u8; 16],
    /// ML-KEM-1024 ciphertext (1568 bytes).
    pub mlkem_ct: Vec<u8>,
    /// Client confirmation tag.
    pub confirm: [u8; 32],
}

impl ClientKem {
    /// Encode the body.
    pub fn encode(&self) -> Result<Vec<u8>> {
        exact_len("ML-KEM ciphertext", &self.mlkem_ct, MLKEM_CT_LEN)?;
        let mut b = Vec::with_capacity(CLIENT_KEM_LEN);
        b.extend_from_slice(&self.session_id);
        b.extend_from_slice(&self.mlkem_ct);
        b.extend_from_slice(&self.confirm);
        Ok(b)
    }

    /// Decode with exact length checks.
    pub fn decode(b: &[u8]) -> Result<Self> {
        exact_len("ClientKem", b, CLIENT_KEM_LEN)?;
        Ok(Self {
            session_id: arr(&b[0..16]),
            mlkem_ct: b[16..16 + MLKEM_CT_LEN].to_vec(),
            confirm: arr(&b[16 + MLKEM_CT_LEN..]),
        })
    }
}

/// Tunnel addressing and rotation policy handed to the client in ServerAck.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Assignment {
    /// Client IPv4 address.
    pub v4: Ipv4Addr,
    /// IPv4 prefix length (≤ 32).
    pub v4_prefix: u8,
    /// Client IPv6 address.
    pub v6: Ipv6Addr,
    /// IPv6 prefix length (≤ 128).
    pub v6_prefix: u8,
    /// Seconds until the next PSK rotation (> 0).
    pub rotate_secs: u16,
}

impl Assignment {
    /// Host routes (`/32`, `/128`) with the default rotation interval.
    pub fn host(v4: Ipv4Addr, v6: Ipv6Addr) -> Self {
        Self {
            v4,
            v4_prefix: 32,
            v6,
            v6_prefix: 128,
            rotate_secs: PQ_ROTATE_SECS.min(u16::MAX as u64) as u16,
        }
    }

    fn validate(&self) -> Result<()> {
        if self.v4_prefix > 32 || self.v6_prefix > 128 {
            return Err(CryptoError::Malformed("ServerAck prefix length"));
        }
        if self.rotate_secs == 0 {
            return Err(CryptoError::Malformed("ServerAck rotate_secs"));
        }
        Ok(())
    }
}

/// ServerAck body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerAck {
    /// Session id.
    pub session_id: [u8; 16],
    /// Address assignment and rotation interval.
    pub assignment: Assignment,
    /// Server confirmation tag.
    pub confirm: [u8; 32],
}

impl ServerAck {
    /// Encode the body.
    pub fn encode(&self) -> Result<Vec<u8>> {
        let a = &self.assignment;
        a.validate()?;
        let mut b = Vec::with_capacity(SERVER_ACK_LEN);
        b.extend_from_slice(&self.session_id);
        b.extend_from_slice(&a.v4.octets());
        b.push(a.v4_prefix);
        b.extend_from_slice(&a.v6.octets());
        b.push(a.v6_prefix);
        b.extend_from_slice(&a.rotate_secs.to_be_bytes());
        b.extend_from_slice(&self.confirm);
        Ok(b)
    }

    /// Decode with exact length and range checks.
    pub fn decode(b: &[u8]) -> Result<Self> {
        exact_len("ServerAck", b, SERVER_ACK_LEN)?;
        let assignment = Assignment {
            v4: Ipv4Addr::from(arr::<4>(&b[16..20])),
            v4_prefix: b[20],
            v6: Ipv6Addr::from(arr::<16>(&b[21..37])),
            v6_prefix: b[37],
            rotate_secs: u16::from_be_bytes([b[38], b[39]]),
        };
        assignment.validate()?;
        Ok(Self {
            session_id: arr(&b[0..16]),
            assignment,
            confirm: arr(&b[40..72]),
        })
    }
}

/// Error body (`code u16 · reason_len u8 · reason utf8`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ErrorMsg {
    /// One of [`error_code`].
    pub code: u16,
    /// Short human-readable reason (≤ 255 bytes, untrusted).
    pub reason: String,
}

impl ErrorMsg {
    /// Build an error message, truncating `reason` to 255 bytes on a char boundary.
    pub fn new(code: u16, reason: &str) -> Self {
        let mut end = reason.len().min(u8::MAX as usize);
        while !reason.is_char_boundary(end) {
            end -= 1;
        }
        Self {
            code,
            reason: reason[..end].to_owned(),
        }
    }

    /// Map a local failure to the error reported to the peer. Reasons are
    /// generic and never echo secrets or peer-supplied data.
    pub fn from_error(e: &CryptoError) -> Self {
        let code = match e {
            CryptoError::Version(_) => error_code::UNSUPPORTED_VERSION,
            CryptoError::TokenRejected(_) | CryptoError::DoubleSpend | CryptoError::Expired => {
                error_code::TOKEN_REJECTED
            }
            CryptoError::Epoch { .. } => error_code::EPOCH_REJECTED,
            CryptoError::BadConfirm => error_code::CONFIRM_FAILED,
            CryptoError::SessionMismatch => error_code::SESSION_UNKNOWN,
            CryptoError::Backend(_) | CryptoError::State(_) => error_code::INTERNAL,
            _ => error_code::BAD_MESSAGE,
        };
        Self::new(code, e.kind())
    }

    /// Encode the body.
    pub fn encode(&self) -> Vec<u8> {
        let r = Self::new(self.code, &self.reason);
        let mut b = Vec::with_capacity(ERROR_FIXED_LEN + r.reason.len());
        b.extend_from_slice(&r.code.to_be_bytes());
        b.push(r.reason.len() as u8);
        b.extend_from_slice(r.reason.as_bytes());
        b
    }

    /// Encode as ready-to-send datagrams.
    pub fn datagrams(&self) -> Vec<Vec<u8>> {
        let body = self.encode();
        let mut d = Vec::with_capacity(HEADER_LEN + body.len());
        d.extend_from_slice(
            &Header {
                ty: MsgType::Error,
                frag_idx: 0,
                frag_cnt: 1,
            }
            .encode(),
        );
        d.extend_from_slice(&body);
        vec![d]
    }

    /// Decode with exact length and UTF-8 checks.
    pub fn decode(b: &[u8]) -> Result<Self> {
        if b.len() < ERROR_FIXED_LEN {
            return Err(CryptoError::Length {
                what: "VWCP Error",
                expected: ERROR_FIXED_LEN,
                got: b.len(),
            });
        }
        let rlen = b[2] as usize;
        exact_len("VWCP Error", b, ERROR_FIXED_LEN + rlen)?;
        let reason = std::str::from_utf8(&b[3..])
            .map_err(|_| CryptoError::Malformed("VWCP Error reason"))?
            .to_owned();
        Ok(Self {
            code: u16::from_be_bytes([b[0], b[1]]),
            reason,
        })
    }

    /// Convert into a [`CryptoError::Peer`].
    pub fn into_error(self) -> CryptoError {
        CryptoError::Peer {
            code: self.code,
            reason: self.reason,
        }
    }
}

/// Capability granted by a validated token.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TokenGrant {
    /// Bandwidth tier of the token's issuing key.
    pub tier: u8,
    /// Rate limit to apply to this peer (0 = unlimited).
    pub bandwidth_bps: u64,
}

/// Result of a successful VWCP exchange, identical on both sides.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PqSession {
    /// WireGuard pre-shared key (zeroized on drop, redacted in `Debug`).
    pub psk: Key32,
    /// Session identifier.
    pub session_id: [u8; 16],
    /// Rotation epoch this PSK belongs to.
    pub epoch: u32,
    /// Assigned client IPv4 address.
    pub v4: Ipv4Addr,
    /// IPv4 prefix length.
    pub v4_prefix: u8,
    /// Assigned client IPv6 address.
    pub v6: Ipv6Addr,
    /// IPv6 prefix length.
    pub v6_prefix: u8,
    /// Seconds until the next rotation (`epoch + 1`).
    pub rotate_secs: u16,
}

impl PqSession {
    fn new(keys: &SessionKeys, session_id: [u8; 16], epoch: u32, a: &Assignment) -> Self {
        Self {
            psk: keys.psk.clone(),
            session_id,
            epoch,
            v4: a.v4,
            v4_prefix: a.v4_prefix,
            v6: a.v6,
            v6_prefix: a.v6_prefix,
            rotate_secs: a.rotate_secs,
        }
    }
}

fn random<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    rand::rngs::OsRng.fill_bytes(&mut b);
    b
}

fn transcript_with(ch_hash: &blake3::Hasher, sh_signed: &[u8]) -> [u8; 32] {
    let mut h = ch_hash.clone();
    h.update(sh_signed);
    *h.finalize().as_bytes()
}

fn sig_input(transcript: &[u8; 32]) -> [u8; 42] {
    let mut m = [0u8; 42];
    m[..10].copy_from_slice(SH_SIG_DOMAIN);
    m[10..].copy_from_slice(transcript);
    m
}

fn th_of(transcript: &[u8; 32], ct: &[u8]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(transcript);
    h.update(ct);
    *h.finalize().as_bytes()
}

enum ClientState {
    AwaitServerHello,
    AwaitServerAck {
        session_id: [u8; 16],
        keys: SessionKeys,
    },
    Failed,
}

/// Client side of one VWCP exchange.
pub struct ClientHandshake {
    node_identity: Bytes32,
    epoch: u32,
    ch_hash: blake3::Hasher,
    eph: Option<X25519Ephemeral>,
    state: ClientState,
}

impl std::fmt::Debug for ClientHandshake {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let state = match self.state {
            ClientState::AwaitServerHello => "AwaitServerHello",
            ClientState::AwaitServerAck { .. } => "AwaitServerAck",
            ClientState::Failed => "Failed",
        };
        f.debug_struct("ClientHandshake")
            .field("node_identity", &self.node_identity)
            .field("epoch", &self.epoch)
            .field("state", &state)
            .finish_non_exhaustive()
    }
}

impl ClientHandshake {
    /// Begin a handshake with the node whose Ed25519 identity is
    /// `node_identity`, for rotation `epoch`, presenting `token`.
    ///
    /// Returns the handshake state and the ClientHello datagrams. Fails only
    /// if the token exceeds 65535 bytes.
    pub fn start(
        node_identity: Bytes32,
        epoch: u32,
        token: Vec<u8>,
    ) -> Result<(ClientHandshake, Vec<Vec<u8>>)> {
        let eph = X25519Ephemeral::generate();
        let ch = ClientHello {
            epoch,
            client_nonce: random(),
            client_eph: eph.public(),
            token,
        };
        let body = ch.encode()?;
        let mut ch_hash = blake3::Hasher::new();
        ch_hash.update(&body);
        let datagrams = fragment(MsgType::ClientHello, &body)?;
        Ok((
            ClientHandshake {
                node_identity,
                epoch,
                ch_hash,
                eph: Some(eph),
                state: ClientState::AwaitServerHello,
            },
            datagrams,
        ))
    }

    /// The epoch this handshake negotiates.
    pub fn epoch(&self) -> u32 {
        self.epoch
    }

    /// Process a ServerHello body; returns the ClientKem datagrams.
    ///
    /// Malformed, wrong-epoch or badly signed ServerHellos are rejected
    /// *without* consuming state, so a forged packet cannot kill a handshake
    /// that a genuine ServerHello can still complete. Failures after the
    /// signature verified (invalid KEM key, low-order X25519 key) are fatal.
    pub fn on_server_hello(&mut self, body: &[u8]) -> Result<Vec<Vec<u8>>> {
        if !matches!(self.state, ClientState::AwaitServerHello) {
            return Err(CryptoError::State("ServerHello not expected"));
        }
        let sh = ServerHello::decode(body)?;
        if sh.epoch != self.epoch {
            return Err(CryptoError::Epoch {
                expected: self.epoch,
                got: sh.epoch,
            });
        }
        let transcript = transcript_with(&self.ch_hash, &body[..SERVER_HELLO_SIGNED_LEN]);
        identity::verify(&self.node_identity, &sig_input(&transcript), &sh.sig)?;

        let result = self.complete_kem(&sh, &transcript);
        if result.is_err() {
            self.state = ClientState::Failed;
        }
        result
    }

    fn complete_kem(&mut self, sh: &ServerHello, transcript: &[u8; 32]) -> Result<Vec<Vec<u8>>> {
        let eph = self
            .eph
            .take()
            .ok_or(CryptoError::State("ephemeral already used"))?;
        let ss_x = eph.diffie_hellman(&sh.server_eph)?;
        let (ct, ss_k) = mlkem_encapsulate(&sh.mlkem_ek)?;
        let th = th_of(transcript, &ct);
        let keys = derive_session_keys(&ss_x, &ss_k, &th, &sh.session_id, self.epoch);
        let kem = ClientKem {
            session_id: sh.session_id,
            mlkem_ct: ct,
            confirm: keys.confirm_c,
        };
        let datagrams = fragment(MsgType::ClientKem, &kem.encode()?)?;
        self.state = ClientState::AwaitServerAck {
            session_id: sh.session_id,
            keys,
        };
        Ok(datagrams)
    }

    /// Process the ServerAck body, verifying `confirm_s`, and yield the session.
    pub fn on_server_ack(self, body: &[u8]) -> Result<PqSession> {
        let ClientState::AwaitServerAck { session_id, keys } = &self.state else {
            return Err(CryptoError::State("ServerAck not expected"));
        };
        let ack = ServerAck::decode(body)?;
        if !bool::from(ack.session_id.ct_eq(session_id)) {
            return Err(CryptoError::SessionMismatch);
        }
        if !keys.check_server(&ack.confirm) {
            return Err(CryptoError::BadConfirm);
        }
        Ok(PqSession::new(
            keys,
            *session_id,
            self.epoch,
            &ack.assignment,
        ))
    }
}

/// Node side of one VWCP exchange (after ClientHello, awaiting ClientKem).
pub struct ServerHandshake {
    epoch: u32,
    session_id: [u8; 16],
    grant: TokenGrant,
    mlkem: MlKemKeypair,
    ss_x: Key32,
    transcript: [u8; 32],
}

impl std::fmt::Debug for ServerHandshake {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServerHandshake")
            .field("epoch", &self.epoch)
            .field("grant", &self.grant)
            .finish_non_exhaustive()
    }
}

impl ServerHandshake {
    /// Process a ClientHello body (any epoch accepted). See
    /// [`ServerHandshake::on_client_hello_min_epoch`].
    pub fn on_client_hello(
        identity: &NodeIdentity,
        body: &[u8],
        validate_token: impl FnOnce(&[u8]) -> Result<TokenGrant>,
    ) -> Result<(ServerHandshake, Vec<Vec<u8>>)> {
        Self::on_client_hello_min_epoch(identity, body, 0, validate_token)
    }

    /// Process a ClientHello body, rejecting epochs below `min_epoch`
    /// (the node passes `last_completed_epoch + 1` for an existing peer).
    ///
    /// `validate_token` is called before any expensive key generation; its
    /// error is returned unchanged. Returns the ServerHello datagrams.
    pub fn on_client_hello_min_epoch(
        identity: &NodeIdentity,
        body: &[u8],
        min_epoch: u32,
        validate_token: impl FnOnce(&[u8]) -> Result<TokenGrant>,
    ) -> Result<(ServerHandshake, Vec<Vec<u8>>)> {
        let ch = ClientHello::decode(body)?;
        if ch.epoch < min_epoch {
            return Err(CryptoError::Epoch {
                expected: min_epoch,
                got: ch.epoch,
            });
        }
        let grant = validate_token(&ch.token)?;

        let eph = X25519Ephemeral::generate();
        let server_eph = eph.public();
        let ss_x = eph.diffie_hellman(&ch.client_eph)?;
        let mlkem = MlKemKeypair::generate();
        let mut sh = ServerHello {
            epoch: ch.epoch,
            server_nonce: random(),
            server_eph,
            session_id: random(),
            mlkem_ek: mlkem.encapsulation_key().to_vec(),
            sig: [0u8; 64],
        };
        let mut signed = sh.encode_unsigned()?;
        let mut h = blake3::Hasher::new();
        h.update(body);
        let transcript = transcript_with(&h, &signed);
        sh.sig = identity.sign(&sig_input(&transcript));
        signed.extend_from_slice(&sh.sig);
        let datagrams = fragment(MsgType::ServerHello, &signed)?;
        Ok((
            ServerHandshake {
                epoch: ch.epoch,
                session_id: sh.session_id,
                grant,
                mlkem,
                ss_x,
                transcript,
            },
            datagrams,
        ))
    }

    /// Capability granted by the client's token.
    pub fn grant(&self) -> TokenGrant {
        self.grant
    }

    /// Epoch being negotiated.
    pub fn epoch(&self) -> u32 {
        self.epoch
    }

    /// Session id chosen for this exchange.
    pub fn session_id(&self) -> [u8; 16] {
        self.session_id
    }

    /// Process the ClientKem body, verify `confirm_c`, and emit ServerAck.
    pub fn on_client_kem(
        self,
        body: &[u8],
        assignment: Assignment,
    ) -> Result<(PqSession, Vec<Vec<u8>>)> {
        assignment.validate()?;
        let kem = ClientKem::decode(body)?;
        if !bool::from(kem.session_id.ct_eq(&self.session_id)) {
            return Err(CryptoError::SessionMismatch);
        }
        let ss_k = self.mlkem.decapsulate(&kem.mlkem_ct)?;
        let th = th_of(&self.transcript, &kem.mlkem_ct);
        let keys = derive_session_keys(&self.ss_x, &ss_k, &th, &self.session_id, self.epoch);
        if !keys.check_client(&kem.confirm) {
            return Err(CryptoError::BadConfirm);
        }
        let ack = ServerAck {
            session_id: self.session_id,
            assignment,
            confirm: keys.confirm_s,
        };
        let datagrams = fragment(MsgType::ServerAck, &ack.encode()?)?;
        Ok((
            PqSession::new(&keys, self.session_id, self.epoch, &assignment),
            datagrams,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t0() -> Instant {
        Instant::now()
    }

    fn reassemble_all(datagrams: &[Vec<u8>]) -> Message {
        let mut r = Reassembler::new();
        let now = t0();
        let mut out = None;
        for d in datagrams {
            if let Some(m) = r.push(d, now).unwrap() {
                out = Some(m);
            }
        }
        out.expect("complete message")
    }

    fn grant_ok(tok: &[u8]) -> Result<TokenGrant> {
        if tok == b"good-token" {
            Ok(TokenGrant {
                tier: 2,
                bandwidth_bps: 50_000_000,
            })
        } else {
            Err(CryptoError::TokenRejected("unknown token"))
        }
    }

    fn assignment() -> Assignment {
        Assignment::host(
            Ipv4Addr::new(100, 96, 0, 7),
            "fd00:564f:4944:1::7".parse().unwrap(),
        )
    }

    struct Run {
        node: NodeIdentity,
        client: ClientHandshake,
        server: ServerHandshake,
        sh: Vec<Vec<u8>>,
    }

    fn begin(epoch: u32) -> Run {
        let node = NodeIdentity::generate();
        let (client, ch) =
            ClientHandshake::start(node.public(), epoch, b"good-token".to_vec()).unwrap();
        let ch = reassemble_all(&ch);
        assert_eq!(ch.ty, MsgType::ClientHello);
        let (server, sh) = ServerHandshake::on_client_hello(&node, &ch.body, grant_ok).unwrap();
        Run {
            node,
            client,
            server,
            sh,
        }
    }

    #[test]
    fn full_roundtrip_identical_psk() {
        let Run {
            mut client,
            server,
            sh,
            ..
        } = begin(7);
        assert_eq!(server.grant().tier, 2);
        assert_eq!(sh.len(), 2, "ServerHello must fragment");
        // Deliver ServerHello in reverse order with a duplicate.
        let mut r = Reassembler::new();
        let now = t0();
        assert!(r.push(&sh[1], now).unwrap().is_none());
        assert!(r.push(&sh[1], now).unwrap().is_none());
        let msg = r.push(&sh[0], now).unwrap().unwrap();
        assert_eq!(msg.ty, MsgType::ServerHello);
        assert_eq!(msg.body.len(), SERVER_HELLO_LEN);

        let kem = client.on_server_hello(&msg.body).unwrap();
        assert_eq!(kem.len(), 2);
        let kem = reassemble_all(&kem);
        assert_eq!(kem.ty, MsgType::ClientKem);
        let (s_sess, ack) = server.on_client_kem(&kem.body, assignment()).unwrap();
        assert_eq!(ack.len(), 1);
        let ack = reassemble_all(&ack);
        assert_eq!(ack.ty, MsgType::ServerAck);
        assert_eq!(ack.body.len(), SERVER_ACK_LEN);
        let c_sess = client.on_server_ack(&ack.body).unwrap();

        assert_eq!(c_sess, s_sess);
        assert_eq!(c_sess.psk, s_sess.psk);
        assert!(!c_sess.psk.is_zero());
        assert_eq!(c_sess.epoch, 7);
        assert_eq!(c_sess.v4, Ipv4Addr::new(100, 96, 0, 7));
        assert_eq!(c_sess.v4_prefix, 32);
        assert_eq!(c_sess.v6_prefix, 128);
        assert_eq!(c_sess.rotate_secs, 120);
        assert!(format!("{c_sess:?}").contains("REDACTED"));
    }

    #[test]
    fn independent_sessions_have_different_psks() {
        let mut psks = Vec::new();
        for _ in 0..2 {
            let Run {
                mut client,
                server,
                sh,
                ..
            } = begin(1);
            let kem = client.on_server_hello(&reassemble_all(&sh).body).unwrap();
            let (s, _) = server
                .on_client_kem(&reassemble_all(&kem).body, assignment())
                .unwrap();
            psks.push(s.psk);
        }
        assert_ne!(psks[0], psks[1]);
    }

    #[test]
    fn tampered_server_hello_rejected_without_killing_handshake() {
        let Run { mut client, sh, .. } = begin(3);
        let good = reassemble_all(&sh).body;
        // Flip a signature bit.
        let mut bad = good.clone();
        bad[SERVER_HELLO_LEN - 1] ^= 0x01;
        assert_eq!(
            client.on_server_hello(&bad).unwrap_err(),
            CryptoError::BadSignature
        );
        // Flip a bit of the (signed) KEM key.
        let mut bad = good.clone();
        bad[200] ^= 0x80;
        assert_eq!(
            client.on_server_hello(&bad).unwrap_err(),
            CryptoError::BadSignature
        );
        // Truncated.
        assert!(matches!(
            client.on_server_hello(&good[..100]),
            Err(CryptoError::Length { .. })
        ));
        // The genuine message still completes the handshake.
        client.on_server_hello(&good).unwrap();
        // ...exactly once.
        assert!(matches!(
            client.on_server_hello(&good),
            Err(CryptoError::State(_))
        ));
    }

    #[test]
    fn wrong_node_identity_rejected() {
        let Run { sh, .. } = begin(0);
        let other = NodeIdentity::generate();
        // A client that expected a different node rejects this ServerHello.
        let (mut c2, ch2) = ClientHandshake::start(other.public(), 0, vec![]).unwrap();
        let _ = ch2;
        assert!(c2.on_server_hello(&reassemble_all(&sh).body).is_err());
    }

    #[test]
    fn epoch_mismatch_and_min_epoch() {
        let node = NodeIdentity::generate();
        let (mut c5, _) = ClientHandshake::start(node.public(), 5, b"good-token".to_vec()).unwrap();
        let (_c6, ch6) = ClientHandshake::start(node.public(), 6, b"good-token".to_vec()).unwrap();
        let (_s, sh6) =
            ServerHandshake::on_client_hello(&node, &reassemble_all(&ch6).body, grant_ok).unwrap();
        assert_eq!(
            c5.on_server_hello(&reassemble_all(&sh6).body).unwrap_err(),
            CryptoError::Epoch {
                expected: 5,
                got: 6
            }
        );
        // Node refuses replayed / old epochs.
        let (_c, ch) = ClientHandshake::start(node.public(), 4, b"good-token".to_vec()).unwrap();
        let err = ServerHandshake::on_client_hello_min_epoch(
            &node,
            &reassemble_all(&ch).body,
            5,
            grant_ok,
        )
        .unwrap_err();
        assert_eq!(
            err,
            CryptoError::Epoch {
                expected: 5,
                got: 4
            }
        );
    }

    #[test]
    fn token_rejection_propagates() {
        let node = NodeIdentity::generate();
        let (_c, ch) = ClientHandshake::start(node.public(), 0, b"forged".to_vec()).unwrap();
        let err = ServerHandshake::on_client_hello(&node, &reassemble_all(&ch).body, grant_ok)
            .unwrap_err();
        assert_eq!(err, CryptoError::TokenRejected("unknown token"));
        let em = ErrorMsg::from_error(&err);
        assert_eq!(em.code, error_code::TOKEN_REJECTED);
    }

    #[test]
    fn tampered_ciphertext_and_confirm_rejected() {
        // Ciphertext tamper: ML-KEM implicit rejection => confirm mismatch.
        let Run {
            mut client,
            server,
            sh,
            ..
        } = begin(1);
        let kem = reassemble_all(&client.on_server_hello(&reassemble_all(&sh).body).unwrap()).body;
        let mut bad = kem.clone();
        bad[16 + 5] ^= 0x10;
        assert_eq!(
            server.on_client_kem(&bad, assignment()).unwrap_err(),
            CryptoError::BadConfirm
        );

        // confirm_c tamper.
        let Run {
            mut client,
            server,
            sh,
            ..
        } = begin(1);
        let kem = reassemble_all(&client.on_server_hello(&reassemble_all(&sh).body).unwrap()).body;
        let mut bad = kem.clone();
        *bad.last_mut().unwrap() ^= 1;
        assert_eq!(
            server.on_client_kem(&bad, assignment()).unwrap_err(),
            CryptoError::BadConfirm
        );

        // Wrong session id.
        let Run {
            mut client,
            server,
            sh,
            ..
        } = begin(1);
        let kem = reassemble_all(&client.on_server_hello(&reassemble_all(&sh).body).unwrap()).body;
        let mut bad = kem.clone();
        bad[0] ^= 1;
        assert_eq!(
            server.on_client_kem(&bad, assignment()).unwrap_err(),
            CryptoError::SessionMismatch
        );
        assert!(matches!(
            ServerHandshake::on_client_hello(&NodeIdentity::generate(), &kem[..10], grant_ok),
            Err(CryptoError::Length { .. })
        ));
    }

    #[test]
    fn tampered_server_ack_rejected() {
        for (offset, expect) in [
            (SERVER_ACK_LEN - 1, CryptoError::BadConfirm),
            (0, CryptoError::SessionMismatch),
        ] {
            let Run {
                mut client,
                server,
                sh,
                ..
            } = begin(9);
            let kem =
                reassemble_all(&client.on_server_hello(&reassemble_all(&sh).body).unwrap()).body;
            let (_s, ack) = server.on_client_kem(&kem, assignment()).unwrap();
            let mut ack = reassemble_all(&ack).body;
            ack[offset] ^= 1;
            assert_eq!(client.on_server_ack(&ack).unwrap_err(), expect);
        }
        // ServerAck before ServerHello.
        let Run { client, .. } = begin(9);
        assert!(matches!(
            client.on_server_ack(&[0u8; SERVER_ACK_LEN]),
            Err(CryptoError::State(_))
        ));
    }

    #[test]
    fn header_layout_is_byte_exact() {
        let d = fragment(MsgType::ClientHello, &[0xAA; 10]).unwrap();
        assert_eq!(d.len(), 1);
        assert_eq!(&d[0][..8], b"VWCP\x01\x01\x00\x01");
        assert_eq!(&d[0][8..], &[0xAA; 10]);

        let body = vec![0x55u8; 2500];
        let d = fragment(MsgType::ServerHello, &body).unwrap();
        assert_eq!(d.len(), 3);
        assert_eq!(&d[0][..8], &[b'V', b'W', b'C', b'P', 1, 2, 0, 3]);
        assert_eq!(&d[1][..8], &[b'V', b'W', b'C', b'P', 1, 2, 1, 3]);
        assert_eq!(&d[2][..8], &[b'V', b'W', b'C', b'P', 1, 2, 2, 3]);
        assert_eq!(d[0].len(), 8 + 1200);
        assert_eq!(d[1].len(), 8 + 1200);
        assert_eq!(d[2].len(), 8 + 100);

        // Empty body is one header-only datagram.
        let d = fragment(MsgType::Error, &[]).unwrap();
        assert_eq!(d, vec![b"VWCP\x01\x05\x00\x01".to_vec()]);
        assert!(fragment(MsgType::ClientHello, &vec![0; 255 * 1200 + 1]).is_err());

        // Body sizes from the spec.
        assert_eq!(SERVER_HELLO_LEN, 1716);
        assert_eq!(CLIENT_KEM_LEN, 1616);
        assert_eq!(SERVER_ACK_LEN, 72);
    }

    #[test]
    fn message_encodings_byte_exact() {
        let ch = ClientHello {
            epoch: 0x01020304,
            client_nonce: [0x11; 32],
            client_eph: [0x22; 32],
            token: vec![0x33; 3],
        };
        let b = ch.encode().unwrap();
        assert_eq!(&b[..4], &[1, 2, 3, 4]);
        assert_eq!(&b[4..36], &[0x11; 32]);
        assert_eq!(&b[36..68], &[0x22; 32]);
        assert_eq!(&b[68..70], &[0, 3]);
        assert_eq!(&b[70..], &[0x33; 3]);
        assert_eq!(ClientHello::decode(&b).unwrap(), ch);
        assert!(ClientHello::decode(&b[..72]).is_err());
        let mut long = b.clone();
        long.push(0);
        assert!(ClientHello::decode(&long).is_err());

        let ack = ServerAck {
            session_id: [0x44; 16],
            assignment: Assignment {
                v4: Ipv4Addr::new(100, 96, 0, 9),
                v4_prefix: 12,
                v6: Ipv6Addr::LOCALHOST,
                v6_prefix: 64,
                rotate_secs: 0x0102,
            },
            confirm: [0x55; 32],
        };
        let b = ack.encode().unwrap();
        assert_eq!(&b[16..20], &[100, 96, 0, 9]);
        assert_eq!(b[20], 12);
        assert_eq!(b[37], 64);
        assert_eq!(&b[38..40], &[1, 2]);
        assert_eq!(ServerAck::decode(&b).unwrap(), ack);
        let mut bad = b.clone();
        bad[20] = 33;
        assert!(ServerAck::decode(&bad).is_err());
        let mut bad = b;
        bad[38] = 0;
        bad[39] = 0;
        assert!(ServerAck::decode(&bad).is_err());
    }

    #[test]
    fn error_message_roundtrip() {
        let e = ErrorMsg::new(error_code::EPOCH_REJECTED, "stale epoch");
        let b = e.encode();
        assert_eq!(&b[..3], &[0, 4, 11]);
        assert_eq!(ErrorMsg::decode(&b).unwrap(), e);
        let d = e.datagrams();
        assert_eq!(&d[0][..8], b"VWCP\x01\x05\x00\x01");
        let m = reassemble_all(&d);
        assert_eq!(m.ty, MsgType::Error);
        assert_eq!(
            ErrorMsg::decode(&m.body).unwrap().into_error(),
            CryptoError::Peer {
                code: 4,
                reason: "stale epoch".into()
            }
        );
        // Truncation at a char boundary.
        let long = "é".repeat(200);
        let e = ErrorMsg::new(1, &long);
        assert_eq!(e.reason.len(), 254);
        assert!(ErrorMsg::decode(&[0, 1, 5, b'a']).is_err());
        assert!(ErrorMsg::decode(&[0, 1, 2, 0xff, 0xfe]).is_err());
    }

    #[test]
    fn header_validation() {
        let good = fragment(MsgType::ServerAck, &[1, 2, 3]).unwrap().remove(0);
        assert!(Header::parse(&good).is_ok());
        let mut bad = good.clone();
        bad[0] = b'X';
        assert!(Header::parse(&bad).is_err());
        let mut bad = good.clone();
        bad[4] = 2;
        assert_eq!(Header::parse(&bad).unwrap_err(), CryptoError::Version(2));
        let mut bad = good.clone();
        bad[5] = 0x06;
        assert_eq!(
            Header::parse(&bad).unwrap_err(),
            CryptoError::UnexpectedType(6)
        );
        let mut bad = good.clone();
        bad[7] = 0;
        assert!(Header::parse(&bad).is_err());
        let mut bad = good.clone();
        bad[6] = 1;
        assert!(Header::parse(&bad).is_err());
        assert!(Header::parse(&good[..7]).is_err());
        // Short non-final fragment.
        let mut bad = good.clone();
        bad[6] = 0;
        bad[7] = 2;
        assert!(Header::parse(&bad).is_err());
        // Oversized fragment.
        let mut big = good[..8].to_vec();
        big.extend_from_slice(&[0; 1201]);
        assert!(Header::parse(&big).is_err());
    }

    #[test]
    fn reassembly_timeout_and_keys() {
        let body: Vec<u8> = (0..3000u32).map(|i| i as u8).collect();
        let d = fragment(MsgType::ClientKem, &body).unwrap();
        assert_eq!(d.len(), 3);
        let start = t0();
        let mut r = Reassembler::new();

        // Timeout: fragments 0 and 1 at t0, fragment 2 at t0 + 2 s => dropped.
        assert!(r.push(&d[0], start).unwrap().is_none());
        assert!(r.push(&d[1], start).unwrap().is_none());
        assert_eq!(r.pending(), 1);
        let late = start + Duration::from_secs(2);
        assert!(r.push(&d[2], late).unwrap().is_none());
        // The stale entry was evicted; the late fragment started a new one.
        assert_eq!(r.pending(), 1);
        // Completing within the window from the new start works.
        assert!(r
            .push(&d[0], late + Duration::from_millis(500))
            .unwrap()
            .is_none());
        let m = r
            .push(&d[1], late + Duration::from_millis(1999))
            .unwrap()
            .unwrap();
        assert_eq!(m.body, body);
        assert_eq!(r.pending(), 0);

        // Just under the timeout still completes.
        let mut r = Reassembler::new();
        r.push(&d[2], start).unwrap();
        r.push(&d[0], start).unwrap();
        let m = r
            .push(&d[1], start + Duration::from_millis(1999))
            .unwrap()
            .unwrap();
        assert_eq!(m.body, body);

        // Explicit expiry.
        let mut r = Reassembler::new();
        r.push(&d[0], start).unwrap();
        r.expire(start + Duration::from_secs(1));
        assert_eq!(r.pending(), 1);
        r.expire(start + Duration::from_secs(3));
        assert_eq!(r.pending(), 0);

        // Different (type, frag_cnt) keys reassemble independently.
        let other = fragment(MsgType::ServerHello, &body).unwrap();
        let two = fragment(MsgType::ClientKem, &body[..2000]).unwrap();
        let mut r = Reassembler::new();
        r.push(&d[0], start).unwrap();
        r.push(&other[2], start).unwrap();
        r.push(&two[1], start).unwrap();
        assert_eq!(r.pending(), 3);
        let m = r.push(&two[0], start).unwrap().unwrap();
        assert_eq!(
            (m.ty, m.body.as_slice()),
            (MsgType::ClientKem, &body[..2000])
        );
        r.push(&other[0], start).unwrap();
        let m = r.push(&other[1], start).unwrap().unwrap();
        assert_eq!(m.ty, MsgType::ServerHello);
        assert_eq!(m.body, body);
        assert_eq!(r.pending(), 1);
        assert!(r.push(b"junk", start).is_err());
    }

    #[test]
    fn full_handshake_under_shuffled_delivery() {
        let Run {
            mut client,
            server,
            sh,
            node,
        } = begin(42);
        let _ = node;
        let now = t0();
        let mut r = Reassembler::new();
        // Interleave both ServerHello fragments with garbage and duplicates.
        assert!(r.push(&sh[1], now).unwrap().is_none());
        assert!(r.push(b"VWCP", now).is_err());
        assert!(r.push(&sh[1], now).unwrap().is_none());
        let shm = r.push(&sh[0], now).unwrap().unwrap();
        let kem = client.on_server_hello(&shm.body).unwrap();
        let mut rs = Reassembler::new();
        assert!(rs.push(&kem[1], now).unwrap().is_none());
        let kemm = rs.push(&kem[0], now).unwrap().unwrap();
        let (s, ack) = server.on_client_kem(&kemm.body, assignment()).unwrap();
        let c = client.on_server_ack(&reassemble_all(&ack).body).unwrap();
        assert_eq!(c.psk, s.psk);
        assert_eq!(c.session_id, s.session_id);
    }
}
