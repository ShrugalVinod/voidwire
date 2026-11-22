//! Connecting to `voidwired` and issuing requests with sensible deadlines.

use std::time::Duration;

use vw_core::ipc::{IpcClient, Request, Response};
use vw_core::{paths, VwError};

use crate::exit::{CliError, CliResult, ExitCode};

/// Time allowed for connect + challenge/response authentication.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// Upper bound for one request/response pair, by request kind.
pub fn request_timeout(req: &Request) -> Duration {
    match req {
        Request::Up { .. } | Request::Optimize => Duration::from_secs(180),
        Request::Audit => Duration::from_secs(120),
        Request::RegisterWarp | Request::RedeemInvite { .. } => Duration::from_secs(90),
        Request::Panic | Request::Down { .. } | Request::Disarm => Duration::from_secs(60),
        _ => Duration::from_secs(20),
    }
}

/// Short name of a request for messages.
pub fn request_name(req: &Request) -> &'static str {
    match req {
        Request::Status => "Status",
        Request::Up { .. } => "Up",
        Request::Down { .. } => "Down",
        Request::Disarm => "Disarm",
        Request::Panic => "Panic",
        Request::Audit => "Audit",
        Request::Optimize => "Optimize",
        Request::GetSettings => "GetSettings",
        Request::SetSettings(_) => "SetSettings",
        Request::ListNodes => "ListNodes",
        Request::ImportNode { .. } => "ImportNode",
        Request::RemoveNode { .. } => "RemoveNode",
        Request::RedeemInvite { .. } => "RedeemInvite",
        Request::ImportWireGuard { .. } => "ImportWireGuard",
        Request::RegisterWarp => "RegisterWarp",
        Request::Telemetry => "Telemetry",
        Request::Subscribe => "Subscribe",
        Request::ExecPrepare => "ExecPrepare",
    }
}

/// Short name of a response for messages.
pub fn response_name(resp: &Response) -> &'static str {
    match resp {
        Response::Ok => "Ok",
        Response::Error { .. } => "Error",
        Response::Status(_) => "Status",
        Response::Audit(_) => "Audit",
        Response::Optimized(_) => "Optimized",
        Response::Settings(_) => "Settings",
        Response::Nodes(_) => "Nodes",
        Response::Telemetry(_) => "Telemetry",
        Response::Exec(_) => "Exec",
        Response::Event(_) => "Event",
    }
}

/// Error for a well-formed but unexpected response variant.
pub fn unexpected(req: &Request, resp: &Response) -> CliError {
    CliError::new(
        ExitCode::Failure,
        format!(
            "voidwired answered {} with an unexpected {} response (version mismatch?)",
            request_name(req),
            response_name(resp)
        ),
    )
}

/// Whether the IPC token file is present, as far as we can tell.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenState {
    /// The file does not exist: the daemon is not installed.
    Missing,
    /// The file exists (or its directory is not listable by us).
    Present,
}

pub fn token_state() -> TokenState {
    match paths::token_file().try_exists() {
        Ok(false) => TokenState::Missing,
        Ok(true) | Err(_) => TokenState::Present,
    }
}

/// How to install the daemon on this OS.
pub fn install_hint() -> &'static str {
    #[cfg(target_os = "windows")]
    {
        "Install VoidWire with the installer, or run `voidwired.exe install` from an elevated (Run as administrator) terminal."
    }
    #[cfg(not(target_os = "windows"))]
    {
        "Install and start the daemon with `sudo voidwired install`."
    }
}

/// How to start an installed but stopped daemon on this OS.
pub fn start_hint() -> &'static str {
    #[cfg(target_os = "windows")]
    {
        "Start the `VoidWire` service (elevated: `sc start VoidWire`), or re-run the installer / an elevated `voidwired.exe install` (idempotent)."
    }
    #[cfg(target_os = "macos")]
    {
        "Start it with `sudo launchctl kickstart -k system/com.voidwire.daemon`, or re-run `sudo voidwired install` (idempotent)."
    }
    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    {
        "Start it with `sudo systemctl start voidwired`, or re-run `sudo voidwired install` (idempotent)."
    }
}

/// How to gain read access to the IPC token on this OS.
pub fn permission_hint() -> &'static str {
    #[cfg(target_os = "windows")]
    {
        "The IPC token is readable by Administrators and interactive users; re-run the installer to repair its ACL, or use an elevated terminal."
    }
    #[cfg(target_os = "macos")]
    {
        "The IPC token is readable by the `admin` group; use an administrator account or run with sudo."
    }
    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    {
        "The IPC token is readable by the `voidwire` group: `sudo usermod -aG voidwire $USER`, then log in again (or run with sudo)."
    }
}

/// Turn a connect/handshake failure into an actionable error.
pub fn classify_connect_error(e: VwError, token: TokenState, endpoint: &str) -> CliError {
    match (e, token) {
        (VwError::Permission(_), TokenState::Missing) => CliError::new(
            ExitCode::DaemonUnavailable,
            format!(
                "voidwired does not appear to be installed (no IPC token at {})",
                paths::token_file().display()
            ),
        )
        .with_hint(install_hint()),
        (VwError::Permission(m), TokenState::Present) => {
            CliError::new(ExitCode::PermissionDenied, m).with_hint(permission_hint())
        }
        (VwError::Auth, _) => CliError::new(
            ExitCode::PermissionDenied,
            "voidwired rejected the IPC token",
        )
        .with_hint("The token on disk does not match the running daemon; re-run the daemon install to regenerate both."),
        (VwError::Ipc(m), TokenState::Missing) => {
            CliError::new(ExitCode::DaemonUnavailable, m).with_hint(install_hint())
        }
        (VwError::Ipc(m), TokenState::Present) => {
            CliError::new(ExitCode::DaemonUnavailable, m).with_hint(start_hint())
        }
        (VwError::Io(io), _) => CliError::new(
            ExitCode::DaemonUnavailable,
            format!("cannot talk to voidwired at {endpoint}: {io}"),
        )
        .with_hint(start_hint()),
        (VwError::Timeout, _) => CliError::new(
            ExitCode::DaemonUnavailable,
            format!("timed out connecting to voidwired at {endpoint}"),
        )
        .with_hint(start_hint()),
        (other, _) => CliError::failure(format!("cannot connect to voidwired: {other}")),
    }
}

/// Connect and authenticate to the platform default endpoint.
pub async fn connect() -> CliResult<IpcClient> {
    let endpoint = paths::ipc_endpoint();
    match tokio::time::timeout(CONNECT_TIMEOUT, IpcClient::connect_default()).await {
        Ok(Ok(c)) => Ok(c),
        Ok(Err(e)) => Err(classify_connect_error(e, token_state(), &endpoint)),
        Err(_) => Err(classify_connect_error(
            VwError::Timeout,
            token_state(),
            &endpoint,
        )),
    }
}

/// Send one request on an existing connection, with its deadline.
pub async fn call(client: &mut IpcClient, req: &Request) -> CliResult<Response> {
    match tokio::time::timeout(request_timeout(req), client.request(req)).await {
        Ok(r) => r.map_err(CliError::from_request),
        Err(_) => Err(CliError::new(
            ExitCode::Timeout,
            format!("voidwired did not answer {} in time", request_name(req)),
        )),
    }
}

/// Connect, send one request, return the response.
pub async fn call_once(req: &Request) -> CliResult<Response> {
    let mut c = connect().await?;
    call(&mut c, req).await
}

/// Expect `Response::Ok`.
pub async fn call_ok(req: &Request) -> CliResult<()> {
    match call_once(req).await? {
        Response::Ok => Ok(()),
        other => Err(unexpected(req, &other)),
    }
}

/// Fetch a status report on an existing connection.
pub async fn status(client: &mut IpcClient) -> CliResult<vw_core::ipc::StatusReport> {
    let req = Request::Status;
    match call(client, &req).await? {
        Response::Status(s) => Ok(*s),
        other => Err(unexpected(&req, &other)),
    }
}
