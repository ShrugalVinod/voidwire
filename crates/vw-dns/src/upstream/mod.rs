//! Encrypted upstream resolvers: DoH (RFC 8484), DoT (RFC 7858) and
//! Oblivious DoH (RFC 9230), plus an ordered failover wrapper.
//!
//! # Routing
//! These clients open ordinary, **unmarked** sockets (no `FW_MARK`). On a
//! live system the default route is the VoidWire tunnel, so resolver traffic
//! is encrypted twice and leaves through the exit node, never through the
//! physical interface. Only the tunnel transport itself uses marked sockets.
//!
//! # DNSSEC
//! The vault sets the EDNS DNSSEC OK bit on every upstream query and records
//! whether the answer carries the AD (Authenticated Data) flag. Validation
//! is performed by the *upstream recursive resolver*; the vault does not
//! validate signatures itself. The AD bit is trusted only because the channel
//! to the resolver is authenticated (TLS certificate verification for
//! DoH/DoT, HPKE to the target's published key for ODoH) — an on-path
//! attacker cannot forge it. A plaintext channel would make AD meaningless.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use vw_core::config::{DnsSettings, DnsUpstream};

use crate::error::{DnsError, Result};
use crate::tls::{Bootstrap, TlsTrust};

pub mod doh;
pub mod dot;
pub mod failover;
pub mod odoh;

pub use doh::DohUpstream;
pub use dot::DotUpstream;
pub use failover::{FailoverUpstream, UpstreamHealth};
pub use odoh::OdohUpstream;

/// MIME type of RFC 8484 DNS messages.
pub const DNS_MESSAGE: &str = "application/dns-message";
/// Default per-attempt timeout.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(4);

/// One encrypted resolver. `query` takes and returns DNS wire messages; the
/// response carries the same id as the query.
#[async_trait]
pub trait Upstream: Send + Sync {
    async fn query(&self, wire: &[u8]) -> Result<Vec<u8>>;
    fn name(&self) -> &'static str;
}

#[async_trait]
impl<T: Upstream + ?Sized> Upstream for Arc<T> {
    async fn query(&self, wire: &[u8]) -> Result<Vec<u8>> {
        (**self).query(wire).await
    }
    fn name(&self) -> &'static str {
        (**self).name()
    }
}

/// Shared construction options for the upstream clients.
#[derive(Debug, Clone)]
pub struct UpstreamOptions {
    pub trust: TlsTrust,
    pub bootstrap: Bootstrap,
    /// Per-attempt timeout (connect + exchange).
    pub timeout: Duration,
}

impl UpstreamOptions {
    /// Mozilla roots, built-in bootstrap table, [`DEFAULT_TIMEOUT`].
    pub fn production() -> Result<Self> {
        Ok(Self {
            trust: TlsTrust::webpki(),
            bootstrap: Bootstrap::new()?,
            timeout: DEFAULT_TIMEOUT,
        })
    }
}

/// Instantiate one configured upstream.
pub fn build(cfg: &DnsUpstream, opts: &UpstreamOptions) -> Result<Arc<dyn Upstream>> {
    Ok(match cfg {
        DnsUpstream::Doh { url } => Arc::new(DohUpstream::with_options(url, opts)?),
        DnsUpstream::Dot { host, addr, port } => Arc::new(DotUpstream::with_options(
            host,
            std::net::SocketAddr::new(*addr, *port),
            opts,
        )?),
        DnsUpstream::Odoh {
            proxy_url,
            target_host,
            target_path,
        } => Arc::new(OdohUpstream::with_options(
            proxy_url,
            target_host,
            target_path,
            opts,
        )?),
    })
}

/// Build the ordered failover chain from `DnsSettings::upstreams`.
pub fn from_settings(settings: &DnsSettings, opts: &UpstreamOptions) -> Result<FailoverUpstream> {
    if settings.upstreams.is_empty() {
        return Err(DnsError::Config("no dns upstreams configured".into()));
    }
    let list = settings
        .upstreams
        .iter()
        .map(|u| build(u, opts))
        .collect::<Result<Vec<_>>>()?;
    Ok(FailoverUpstream::new(list, opts.timeout))
}

/// Cheap sanity check on a response before returning it: header present,
/// QR set and the id echoed.
pub(crate) fn check_response(upstream: &'static str, query: &[u8], resp: &[u8]) -> Result<()> {
    if resp.len() < 12 || query.len() < 2 {
        return Err(DnsError::upstream(upstream, "short dns response"));
    }
    if resp[2] & 0x80 == 0 {
        return Err(DnsError::upstream(upstream, "response without QR bit"));
    }
    if resp[0..2] != query[0..2] {
        return Err(DnsError::Mismatch);
    }
    Ok(())
}

/// Copy `id` into the first two bytes of a DNS message.
pub(crate) fn with_id(wire: &[u8], id: [u8; 2]) -> Vec<u8> {
    let mut v = wire.to_vec();
    if v.len() >= 2 {
        v[0..2].copy_from_slice(&id);
    }
    v
}
