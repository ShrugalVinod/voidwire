//! `vw-crypto` — VoidWire cryptography.
//!
//! * [`kdf`] — HKDF-BLAKE3 (ARCHITECTURE.md §6) and the VWCP PSK / key
//!   confirmation schedule.
//! * [`hybrid`] — ephemeral X25519 and ML-KEM-1024 (FIPS 203) primitives.
//! * [`identity`] — Ed25519 node identities with strict verification.
//! * [`vwcp`] — the sans-IO in-tunnel post-quantum control protocol.
//! * [`blind`] — RFC 9474 RSABSSA-SHA384-PSS-Randomized session tokens.
//! * [`invite`] — signed friend-to-friend invites (ARCHITECTURE.md §8).
//! * [`attest`] — the signed runtime attestation envelope.
//!
//! All private material lives in [`vw_core::secret`] containers or in types
//! that zeroize on drop and redact their `Debug` output.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod attest;
pub mod blind;
pub mod error;
pub mod hybrid;
pub mod identity;
pub mod invite;
pub mod kdf;
pub mod vwcp;

pub use attest::{AttestationReport, SignedAttestation};
pub use blind::{
    blind_sign, finalize, prepare_token, verify as verify_token, BlindRequest, PendingToken,
    SessionToken, SpentSet, TokenIssuerKey, TokenPublicKey,
};
pub use error::{CryptoError, Result};
pub use hybrid::{MlKemKeypair, X25519Ephemeral};
pub use identity::{verify, NodeIdentity};
pub use invite::{parse_bandwidth, parse_duration, Invite};
pub use kdf::{derive_psk, derive_session_keys, expand, extract, SessionKeys};
pub use vwcp::{
    Assignment, ClientHandshake, ErrorMsg, MsgType, PqSession, Reassembler, ServerHandshake,
    TokenGrant,
};
