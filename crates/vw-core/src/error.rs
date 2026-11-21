//! Shared error type.

use crate::state::{DomeEvent, DomeState};

pub type Result<T, E = VwError> = std::result::Result<T, E>;

#[derive(Debug, thiserror::Error)]
pub enum VwError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("serialization error: {0}")]
    Serde(#[from] serde_json::Error),
    #[error("invalid Iron Dome transition {from:?} --{event:?}-->")]
    InvalidTransition { from: DomeState, event: DomeEvent },
    #[error("invalid configuration: {0}")]
    Config(String),
    #[error("malformed packet: {0}")]
    Packet(&'static str),
    #[error("ipc protocol error: {0}")]
    Ipc(String),
    #[error("authentication failed")]
    Auth,
    #[error("cryptographic failure: {0}")]
    Crypto(&'static str),
    #[error("transport error: {0}")]
    Transport(String),
    #[error("firewall error: {0}")]
    Firewall(String),
    #[error("dns error: {0}")]
    Dns(String),
    #[error("operation timed out")]
    Timeout,
    #[error("not supported on this platform: {0}")]
    Unsupported(&'static str),
    #[error("permission denied: {0}")]
    Permission(String),
    #[error("invalid uri: {0}")]
    Uri(String),
}
