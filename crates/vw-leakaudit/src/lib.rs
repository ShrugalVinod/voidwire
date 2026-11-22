//! `vw-leakaudit` — VoidWire's leak verification.
//!
//! * [`canary`]: the live canary self-verifier the daemon runs in
//!   `CanaryAuditing` (and on `voidwire status --audit`). It is written
//!   against the [`canary::CanaryHooks`] trait: the daemon provides OS-backed
//!   hooks, tests provide in-memory ones.

#![forbid(unsafe_code)]

pub mod canary;

pub use canary::{run_canary, CanaryContext, CanaryHooks};
