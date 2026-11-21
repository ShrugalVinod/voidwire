//! Windows: WFP lockdown (persistent + boot-time filters) and IP Helper
//! routing. The filter policy itself is the pure model in
//! [`crate::windows_spec`]; this module only performs the FFI.

pub mod routes;
pub mod wfp;

pub use wfp::WfpBackend;
