//! macOS: pf anchor lockdown and utun split routes.
//!
//! Rendering (`pf`, `routes`) compiles on every OS; the pf executor only on macOS.

pub mod pf;
pub mod routes;

#[cfg(target_os = "macos")]
mod backend;

#[cfg(target_os = "macos")]
pub use backend::PfBackend;
pub use pf::{render_pf_anchor, PF_ANCHOR};
