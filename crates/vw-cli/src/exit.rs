//! Exit codes and the CLI error type.
//!
//! Scripts can rely on these codes; they are part of the CLI contract.

use std::fmt;
use std::io::ErrorKind;

use vw_core::VwError;

/// Process exit codes of `voidwire`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum ExitCode {
    Success = 0,
    /// Unspecified failure.
    Failure = 1,
    /// Bad command line or input document.
    Usage = 2,
    /// `voidwired` is not installed, not running or the connection dropped.
    DaemonUnavailable = 3,
    /// The IPC token is unreadable or was rejected.
    PermissionDenied = 4,
    /// The daemon ended in `FailsafeLockdown`: the firewall is still locked.
    Lockdown = 5,
    /// `status --audit` found at least one failing check.
    AuditFailed = 6,
    /// Waiting for the daemon timed out.
    Timeout = 7,
    /// The daemon refused or failed the request.
    Rejected = 8,
    /// The user declined a confirmation (or none could be asked).
    Cancelled = 9,
}

impl ExitCode {
    pub const fn code(self) -> i32 {
        self as i32
    }

    pub const fn name(self) -> &'static str {
        match self {
            ExitCode::Success => "success",
            ExitCode::Failure => "failure",
            ExitCode::Usage => "usage",
            ExitCode::DaemonUnavailable => "daemon-unavailable",
            ExitCode::PermissionDenied => "permission-denied",
            ExitCode::Lockdown => "lockdown",
            ExitCode::AuditFailed => "audit-failed",
            ExitCode::Timeout => "timeout",
            ExitCode::Rejected => "rejected",
            ExitCode::Cancelled => "cancelled",
        }
    }
}

/// A failure with an exit code, a message and an optional remedy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CliError {
    pub code: ExitCode,
    pub message: String,
    pub hint: Option<String>,
}

impl CliError {
    pub fn new(code: ExitCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            hint: None,
        }
    }

    pub fn with_hint(mut self, hint: impl Into<String>) -> Self {
        self.hint = Some(hint.into());
        self
    }

    pub fn usage(message: impl Into<String>) -> Self {
        Self::new(ExitCode::Usage, message)
    }

    pub fn failure(message: impl Into<String>) -> Self {
        Self::new(ExitCode::Failure, message)
    }

    /// Map an error raised by an IPC request on an established connection.
    pub fn from_request(e: VwError) -> Self {
        match e {
            VwError::Ipc(m) => Self::new(ExitCode::Rejected, format!("voidwired: {m}")),
            VwError::Io(io)
                if matches!(
                    io.kind(),
                    ErrorKind::UnexpectedEof
                        | ErrorKind::BrokenPipe
                        | ErrorKind::ConnectionReset
                        | ErrorKind::ConnectionAborted
                ) =>
            {
                Self::new(
                    ExitCode::DaemonUnavailable,
                    "voidwired closed the connection (did the service restart or crash?)",
                )
                .with_hint("The firewall lockdown is kernel-persistent; run `voidwire status` once the service is back.")
            }
            VwError::Timeout => Self::new(ExitCode::Timeout, "timed out waiting for voidwired"),
            VwError::Auth => Self::new(ExitCode::PermissionDenied, "voidwired rejected the IPC token"),
            VwError::Permission(m) => Self::new(ExitCode::PermissionDenied, m),
            other => Self::failure(other.to_string()),
        }
    }

    pub fn json(&self) -> serde_json::Value {
        serde_json::json!({
            "error": {
                "code": self.code.code(),
                "kind": self.code.name(),
                "message": self.message,
                "hint": self.hint,
            }
        })
    }
}

impl fmt::Display for CliError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for CliError {}

impl From<std::io::Error> for CliError {
    fn from(e: std::io::Error) -> Self {
        Self::failure(e.to_string())
    }
}

pub type CliResult<T> = Result<T, CliError>;

/// Exit status of a child process as a shell would report it.
pub fn child_exit_code(status: &std::process::ExitStatus) -> i32 {
    if let Some(c) = status.code() {
        return c;
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        if let Some(sig) = status.signal() {
            return 128 + sig;
        }
    }
    ExitCode::Failure.code()
}
