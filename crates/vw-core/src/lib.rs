//! `vw-core` — the shared foundation of VoidWire.
//!
//! Every other crate depends on this one for constants, configuration schemas,
//! zeroizing secret containers, the Iron Dome state machine, raw packet
//! parsing helpers, the local IPC protocol and the `StealthTransport` trait.

#![forbid(unsafe_code)]

pub mod config;
pub mod consts;
pub mod error;
pub mod ipc;
pub mod packet;
pub mod paths;
pub mod probe;
pub mod redact;
pub mod secret;
pub mod state;
pub mod telemetry;
pub mod transport;
pub mod uri;
pub mod wgconf;

pub use error::{Result, VwError};
