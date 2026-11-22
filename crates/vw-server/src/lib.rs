//! `vw-server` — the `voidwire-node` RAM-only exit/relay node.
//!
//! * [`node`]: sans-IO core — WireGuard [`vw_wg::Responder`], per-peer VWCP
//!   admission (owner keys, Chaumian session tokens, F2F invites), PQ PSK
//!   installation and rotation, token redemption, attestation, gateway ICMP
//!   echo, anti-spoofing, no client-to-client, per-session bandwidth.
//! * [`admission`]: tiers, issuer keys, token parsing, spent ledger, invites,
//!   address pool. [`bandwidth`]: token buckets. [`icmp`]: echo replies.
//! * [`listeners`]: shared plain/AmneziaWG UDP port, MASQUE and TLS-WS
//!   multiplexed into the core, plus the async serve loop.
//! * [`forward`]: nftables NAT ruleset (rendering everywhere, applying on Linux).
//! * [`state`]: state directory, descriptor and `node.uri`.
//! * [`attestation`]: runtime facts. [`control`]: local control socket.
//! * [`cli`] / [`run`]: the binary's command line and `run` orchestration.
//!
//! Logging policy: the node never logs client addresses, destinations, DNS
//! names or key material at any level; the default level is `off`.

#![forbid(unsafe_code)]

pub mod admission;
pub mod attestation;
pub mod bandwidth;
pub mod cli;
pub mod control;
pub mod forward;
pub mod icmp;
pub mod listeners;
pub mod node;
pub mod run;
pub mod state;

#[cfg(test)]
mod tests;
