//! `vw-freecloud` — the "$0 forever" engine.
//!
//! * [`warp`]: anonymous Cloudflare WARP device registration and endpoint
//!   candidates (free, no data cap, classical WireGuard).
//! * [`cloud`]: hardened, RAM-only `voidwire-node` deployment bundles for
//!   Oracle Cloud Always Free, Google Cloud Free Tier, Fly.io and any Docker host.
//! * [`http`]: a minimal HTTPS JSON client whose sockets can carry the VoidWire
//!   firewall mark and pinned addresses, so it works while the Iron Dome is armed.
//! * [`qr`]: terminal QR rendering for `voidwire://` URIs.

#![forbid(unsafe_code)]

pub mod cloud;
pub mod http;
pub mod qr;
pub mod warp;

pub use cloud::{generate_bundle, Bundle, BundleOptions, Provider};
pub use warp::WarpRegistrar;
