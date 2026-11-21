//! Engine error type.

use vw_core::VwError;

/// Why the WireGuard engine rejected a datagram or operation.
///
/// Every variant is cheap to produce and carries no secret or address data, so
/// it is safe to log at `debug`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum WgError {
    #[error("malformed WireGuard message")]
    Malformed,
    #[error("invalid mac1")]
    InvalidMac,
    #[error("unknown receiver index")]
    UnknownIndex,
    #[error("replayed or out-of-window counter")]
    Replay,
    #[error("AEAD authentication failed")]
    Decrypt,
    #[error("handshake from an unexpected static key")]
    WrongPeer,
    #[error("handshake from an unknown peer")]
    UnknownPeer,
    #[error("stale or replayed handshake timestamp")]
    StaleTimestamp,
    #[error("handshake initiations arriving too fast")]
    Flood,
    #[error("no handshake in progress")]
    NoHandshake,
    #[error("session expired")]
    Expired,
    #[error("non-contributory Diffie-Hellman result")]
    WeakKey,
    #[error("peer table full")]
    PeerTableFull,
    #[error("decrypted payload is not an IP packet")]
    InvalidPlaintext,
    #[error("cascade needs at least one hop")]
    EmptyCascade,
}

impl WgError {
    /// Static description (used when converting into [`VwError`]).
    pub const fn as_str(self) -> &'static str {
        match self {
            WgError::Malformed => "malformed WireGuard message",
            WgError::InvalidMac => "invalid mac1",
            WgError::UnknownIndex => "unknown receiver index",
            WgError::Replay => "replayed counter",
            WgError::Decrypt => "AEAD authentication failed",
            WgError::WrongPeer => "unexpected static key",
            WgError::UnknownPeer => "unknown peer",
            WgError::StaleTimestamp => "stale handshake timestamp",
            WgError::Flood => "handshake flood",
            WgError::NoHandshake => "no handshake in progress",
            WgError::Expired => "session expired",
            WgError::WeakKey => "non-contributory DH",
            WgError::PeerTableFull => "peer table full",
            WgError::InvalidPlaintext => "invalid plaintext packet",
            WgError::EmptyCascade => "empty cascade",
        }
    }
}

impl From<WgError> for VwError {
    fn from(e: WgError) -> Self {
        VwError::Crypto(e.as_str())
    }
}
