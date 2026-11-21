//! `vw-wg` — VoidWire's userspace WireGuard engine.
//!
//! * [`noise`]: Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s primitives and the four
//!   WireGuard message types, written from the whitepaper.
//! * [`session`]: transport keypairs and the 2048-counter replay window.
//! * [`peer`]: the per-peer state machine ([`Peer`]): handshakes, timers,
//!   cookies, previous/current/next keypair rotation, PSK rotation and
//!   per-peer `reserved` bytes (Cloudflare WARP client id).
//! * [`responder`]: the multi-peer server view ([`Responder`]).
//! * [`cascade`]: userspace multi-hop ([`Cascade`]).
//! * [`sanitize`]: TTL / MSS / TCP-timestamp normalisation ([`Sanitizer`]).
//! * [`daita`]: bucket padding and chaff.
//! * [`tun`]: [`VirtualTunChannel`] and the OS device [`OsTun`].
//! * [`driver`]: the async [`TunnelDriver`] with pluggable [`PacketFilter`]s.
//!
//! Everything except `tun` and `driver` is sans-IO: callers pass datagrams
//! and `std::time::Instant`s in explicitly, which keeps tests deterministic.
//! Interoperability with `boringtun` is verified in `tests/interop.rs`.

#![forbid(unsafe_code)]

pub mod cascade;
pub mod daita;
pub mod driver;
pub mod error;
pub mod noise;
pub mod peer;
pub mod responder;
pub mod sanitize;
pub mod session;
pub mod timers;
pub mod tun;

pub use cascade::{Cascade, CascadeHop, CascadeOutput};
pub use daita::{chaff_plaintext, is_chaff, pad_plaintext, strip_padding, EngineChaff};
pub use driver::{
    DriverConfig, DriverHandle, Engine, EngineOutput, FilterVerdict, PacketFilter, PassThrough,
    TunnelDriver,
};
pub use error::WgError;
pub use noise::{generate_private_key, public_key};
pub use peer::{Decapsulated, Peer, Role};
pub use responder::{Admission, PeerHandle, Responder, Routed};
pub use sanitize::{SanitizeReport, Sanitizer};
pub use tun::{OsTun, OsTunConfig, VirtualTunChannel};
