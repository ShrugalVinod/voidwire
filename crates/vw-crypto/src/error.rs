//! Error type for every fallible operation in `vw-crypto`.

use vw_core::VwError;

/// Result alias using [`CryptoError`].
pub type Result<T, E = CryptoError> = std::result::Result<T, E>;

/// Cryptographic and protocol failures.
///
/// Messages never contain key material; they are safe to log at any level.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CryptoError {
    /// A message or encoding was structurally invalid.
    #[error("malformed {0}")]
    Malformed(&'static str),
    /// A field had the wrong length.
    #[error("invalid length for {what}: expected {expected}, got {got}")]
    Length {
        /// Which field or message.
        what: &'static str,
        /// Required length.
        expected: usize,
        /// Observed length.
        got: usize,
    },
    /// An unsupported protocol or encoding version.
    #[error("unsupported version {0}")]
    Version(u8),
    /// A message type that is not valid here.
    #[error("unexpected message type {0:#04x}")]
    UnexpectedType(u8),
    /// The handshake object is not in a state that accepts this message.
    #[error("handshake state error: {0}")]
    State(&'static str),
    /// A signature did not verify.
    #[error("signature verification failed")]
    BadSignature,
    /// A key-confirmation tag did not match.
    #[error("key confirmation failed")]
    BadConfirm,
    /// A session identifier did not match the one in progress.
    #[error("session id mismatch")]
    SessionMismatch,
    /// The epoch was not the expected one (replay or stale rotation).
    #[error("epoch rejected: expected {expected}, got {got}")]
    Epoch {
        /// Expected (or minimum) epoch.
        expected: u32,
        /// Observed epoch.
        got: u32,
    },
    /// A public key or private key failed validation.
    #[error("invalid key: {0}")]
    InvalidKey(&'static str),
    /// A low-order / non-contributory Diffie-Hellman result.
    #[error("non-contributory key exchange")]
    NonContributory,
    /// An invite or token has expired.
    #[error("expired")]
    Expired,
    /// A capability token was refused.
    #[error("token rejected: {0}")]
    TokenRejected(&'static str),
    /// A token `msg` was already redeemed.
    #[error("token already spent")]
    DoubleSpend,
    /// The peer sent a VWCP Error message.
    #[error("peer reported error {code}: {reason}")]
    Peer {
        /// VWCP error code.
        code: u16,
        /// Peer-supplied reason (untrusted text).
        reason: String,
    },
    /// Underlying library failure (RSA, KEM, encoding).
    #[error("crypto backend failure: {0}")]
    Backend(&'static str),
    /// Human input (bandwidth / duration strings) could not be parsed.
    #[error("parse error: {0}")]
    Parse(String),
}

impl CryptoError {
    /// Short static description, used when converting into [`VwError::Crypto`].
    pub fn kind(&self) -> &'static str {
        match self {
            CryptoError::Malformed(w) => w,
            CryptoError::Length { what, .. } => what,
            CryptoError::Version(_) => "unsupported version",
            CryptoError::UnexpectedType(_) => "unexpected message type",
            CryptoError::State(s) => s,
            CryptoError::BadSignature => "signature verification failed",
            CryptoError::BadConfirm => "key confirmation failed",
            CryptoError::SessionMismatch => "session id mismatch",
            CryptoError::Epoch { .. } => "epoch rejected",
            CryptoError::InvalidKey(s) => s,
            CryptoError::NonContributory => "non-contributory key exchange",
            CryptoError::Expired => "expired",
            CryptoError::TokenRejected(s) => s,
            CryptoError::DoubleSpend => "token already spent",
            CryptoError::Peer { .. } => "peer reported error",
            CryptoError::Backend(s) => s,
            CryptoError::Parse(_) => "parse error",
        }
    }
}

impl From<CryptoError> for VwError {
    fn from(e: CryptoError) -> Self {
        match e {
            CryptoError::Parse(s) => VwError::Config(s),
            CryptoError::Expired | CryptoError::TokenRejected(_) | CryptoError::DoubleSpend => {
                VwError::Auth
            }
            other => VwError::Crypto(other.kind()),
        }
    }
}
