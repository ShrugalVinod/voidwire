//! `vw-dns` — the VoidWire DNS vault.
//!
//! * [`vault::DnsVault`]: local resolver (validation, local-only names, Shield,
//!   RAM cache, encrypted forwarding, CNAME uncloaking) plus UDP/TCP servers
//!   for the vault addresses `100.64.0.1:53` / `[fd00:564f:4944::1]:53`.
//! * [`intercept::intercept`]: pipeline hook that answers port-53 packets to
//!   any address and drops foreign DoT.
//! * [`shield::Shield`] / [`shield::BlocklistUpdater`]: blocklists.
//! * [`upstream`]: DoH, DoT, ODoH clients and ordered failover.
//!
//! Privacy invariants: no query history is kept anywhere; the cache is
//! RAM-only and bounded; names and addresses are only ever logged at
//! `debug`/`trace`, fingerprinted through [`vw_core::redact`].

#![forbid(unsafe_code)]

pub mod cache;
pub mod error;
pub mod intercept;
pub mod message;
pub mod shield;
pub mod tls;
pub mod uncloak;
pub mod upstream;
pub mod vault;

#[cfg(test)]
mod tests;

pub use error::{DnsError, Result};
pub use intercept::{intercept, InterceptVerdict};
pub use shield::{BlocklistSource, BlocklistUpdater, Shield};
pub use tls::{Bootstrap, TlsTrust};
pub use upstream::{
    DohUpstream, DotUpstream, FailoverUpstream, OdohUpstream, Upstream, UpstreamOptions,
};
pub use vault::{
    serve_tcp, serve_udp, Disposition, DnsServer, DnsVault, InspectorEvent, Resolution,
};
