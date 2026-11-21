//! `vw-tui` — the VoidWire cyberpunk terminal dashboard (`voidwire tui`).
//!
//! Architecture:
//! - [`app::App`] is pure state, updated from daemon data with
//!   [`App::apply_status`], [`App::apply_event`] and [`App::apply_audit`];
//! - [`ui::draw`] is a pure renderer of an `App`;
//! - [`run`] / [`run_with`] drive both: one IPC connection polls
//!   `Request::Status` every second, a second one consumes the `Subscribe`
//!   event stream, each command opens its own connection, and key presses
//!   arrive through crossterm's `EventStream`.
//!
//! Everything on screen comes from `voidwired`; when it cannot be reached the
//! dashboard shows the error full-screen and retries every 2 s.

#![forbid(unsafe_code)]

pub mod app;
pub mod format;
mod runtime;
pub mod ui;

pub use app::{map_key, Action, App, Command, Focus};
pub use runtime::{run, run_with, POLL_INTERVAL, RETRY_INTERVAL};

#[cfg(test)]
mod tests;
