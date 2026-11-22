//! `vw-daemon` — the privileged VoidWire client service (`voidwired`).
//!
//! * [`controller`]: owns the Iron Dome FSM and drives the whole lifecycle
//!   (boot lock, optimizer, cascade + VWCP handshakes, canary, rotation,
//!   panic, link-loss recovery, disarm).
//! * [`pipeline`]: the client packet filters of ARCHITECTURE.md §3 plugged
//!   into `vw_wg::TunnelDriver`, plus the multiplexing TUN and control demux.
//! * [`link`]: sans-IO WireGuard probe sessions, in-tunnel control links,
//!   the VWCP client, ICMP echo and F2F redemption.
//! * [`optimizer`]: real probes, scoring, hop/transport/MTU selection and
//!   the per-network decision cache (ARCHITECTURE.md §10).
//! * [`platform`]: every OS side effect behind one trait (the real
//!   [`platform::OsPlatform`]; tests use in-memory implementations).
//! * [`ipc_server`], [`store`], [`exec`], [`canary_hooks`], [`events`],
//!   [`service`] (launchd / Windows SCM / systemd).

pub mod canary_hooks;
pub mod controller;
pub mod events;
pub mod exec;
pub mod ipc_server;
pub mod link;
pub mod optimizer;
pub mod pipeline;
pub mod platform;
pub mod service;
pub mod store;
pub mod tunnel;
pub mod util;

/// Version reported over IPC.
pub const DAEMON_VERSION: &str = env!("CARGO_PKG_VERSION");
