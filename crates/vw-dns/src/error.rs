//! Error type of the DNS vault.

/// Result alias used throughout `vw-dns`.
pub type Result<T, E = DnsError> = std::result::Result<T, E>;

/// Errors raised by the vault, the Shield and the encrypted upstream clients.
///
/// Display strings never contain queried names or peer addresses, so they are
/// safe to surface in logs at any level.
#[derive(Debug, thiserror::Error)]
pub enum DnsError {
    #[error("malformed dns message: {0}")]
    Malformed(&'static str),
    #[error("dns encoding failed")]
    Encode,
    #[error("upstream {upstream} failed: {reason}")]
    Upstream {
        upstream: &'static str,
        reason: String,
    },
    #[error("upstream response does not match the query")]
    Mismatch,
    #[error("operation timed out")]
    Timeout,
    #[error("tls configuration error: {0}")]
    Tls(String),
    #[error("odoh protocol error: {0}")]
    Odoh(&'static str),
    #[error("invalid upstream configuration: {0}")]
    Config(String),
    #[error("blocklist error: {0}")]
    Blocklist(String),
    #[error("all upstreams failed")]
    AllUpstreamsFailed,
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

impl DnsError {
    pub(crate) fn upstream(upstream: &'static str, reason: impl std::fmt::Display) -> Self {
        DnsError::Upstream {
            upstream,
            reason: reason.to_string(),
        }
    }

    /// Wrap a reqwest error with its URL (which carries resolver hostnames) removed.
    pub(crate) fn http(upstream: &'static str, e: reqwest::Error) -> Self {
        if e.is_timeout() {
            return DnsError::Timeout;
        }
        DnsError::upstream(upstream, e.without_url())
    }
}

impl From<hickory_proto::ProtoError> for DnsError {
    fn from(_: hickory_proto::ProtoError) -> Self {
        DnsError::Malformed("undecodable message")
    }
}

impl From<DnsError> for vw_core::VwError {
    fn from(e: DnsError) -> Self {
        match e {
            DnsError::Timeout => vw_core::VwError::Timeout,
            DnsError::Io(io) => vw_core::VwError::Io(io),
            other => vw_core::VwError::Dns(other.to_string()),
        }
    }
}
