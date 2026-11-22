//! `vw-cli` — the `voidwire` command (ARCHITECTURE.md §13).
//!
//! Every command talks to the privileged `voidwired` daemon over the
//! authenticated VWIPC channel (`vw_core::ipc`), except `cloud generate` and
//! `completions`, which only write local output. The binary is a thin wrapper
//! around [`main_entry`]; the library exposes the parser, pure formatters and
//! command handlers so they can be tested against an in-process daemon.
//!
//! Exit codes are listed in [`exit::ExitCode`].

#![forbid(unsafe_code)]

pub mod cli;
pub mod commands;
pub mod daemon;
pub mod exit;
pub mod output;
pub mod render;

use std::ffi::OsString;

use clap::Parser;

pub use cli::Cli;
pub use commands::execute;
pub use exit::{CliError, ExitCode};
pub use output::{Out, Theme};

/// Parse `args`, run the command and return the process exit code.
pub fn main_entry<I, T>(args: I) -> i32
where
    I: IntoIterator<Item = T>,
    T: Into<OsString> + Clone,
{
    let cli = match Cli::try_parse_from(args) {
        Ok(c) => c,
        Err(e) => {
            let code = if e.use_stderr() {
                ExitCode::Usage.code()
            } else {
                ExitCode::Success.code()
            };
            let _ = e.print();
            return code;
        }
    };
    let mut out = Out::terminal(cli.json);
    let rt = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            out.error(&CliError::failure(format!(
                "cannot start async runtime: {e}"
            )));
            return ExitCode::Failure.code();
        }
    };
    let result = rt.block_on(execute(cli, &mut out));
    // Do not wait for lingering blocking tasks (e.g. an unanswered prompt).
    rt.shutdown_background();
    match result {
        Ok(code) => code,
        Err(e) => {
            out.error(&e);
            e.code.code()
        }
    }
}
