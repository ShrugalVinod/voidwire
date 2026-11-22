//! Thin, typed bridge from Tauri commands to `voidwired` over VWIPC.
//!
//! Every call opens a fresh authenticated [`IpcClient`]: the socket / named
//! pipe is local, the handshake is a single round trip, and a per-call
//! connection means a slow request (`Up`, `Audit`, `Optimize`) never blocks a
//! concurrent `Status` poll from the UI. Errors are turned into readable
//! strings for the webview.

use std::time::Duration;

use vw_core::ipc::{IpcClient, Request, Response};
use vw_core::VwError;

/// Time allowed for connect + challenge/response authentication.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// Upper bound for a single request/response pair, by request kind.
///
/// `Up` covers boot lock, handshakes, the canary audit and possibly an
/// optimizer pass, so it gets the longest budget.
fn request_timeout(req: &Request) -> Duration {
    match req {
        Request::Up { .. } | Request::Optimize => Duration::from_secs(180),
        Request::Audit => Duration::from_secs(120),
        Request::RegisterWarp | Request::RedeemInvite { .. } => Duration::from_secs(90),
        Request::Panic | Request::Down { .. } | Request::Disarm => Duration::from_secs(60),
        _ => Duration::from_secs(20),
    }
}

/// Short human name of a request, used in error messages.
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

/// Short human name of a response variant, used in error messages.
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

/// Turn a `VwError` into a sentence suitable for the UI.
pub fn describe(e: &VwError) -> String {
    match e {
        VwError::Ipc(m) => m.clone(),
        VwError::Permission(m) => m.clone(),
        VwError::Auth => "voidwired rejected this app's IPC token; reinstall the VoidWire \
                          service to regenerate it"
            .into(),
        VwError::Timeout => "timed out waiting for voidwired".into(),
        VwError::Io(io) if io.kind() == std::io::ErrorKind::UnexpectedEof => {
            "voidwired closed the connection (did the service restart?)".into()
        }
        other => other.to_string(),
    }
}

/// Open and authenticate a connection with the on-disk token.
pub async fn connect() -> Result<IpcClient, String> {
    match tokio::time::timeout(CONNECT_TIMEOUT, IpcClient::connect_default()).await {
        Ok(Ok(c)) => Ok(c),
        Ok(Err(e)) => Err(describe(&e)),
        Err(_) => Err("timed out connecting to voidwired".into()),
    }
}

/// Send one request and wait for its response. `Response::Error` is already
/// converted into `Err` by `IpcClient::request`.
pub async fn call(req: Request) -> Result<Response, String> {
    let budget = request_timeout(&req);
    let name = request_name(&req);
    let mut client = connect().await?;
    match tokio::time::timeout(budget, client.request(&req)).await {
        Ok(Ok(resp)) => Ok(resp),
        Ok(Err(e)) => Err(format!("{name}: {}", describe(&e))),
        Err(_) => Err(format!(
            "{name}: voidwired did not answer within {} s",
            budget.as_secs()
        )),
    }
}

/// Helper for typed queries: run `req` and extract the expected variant.
pub async fn call_expect<T>(
    req: Request,
    expected: &'static str,
    pick: impl FnOnce(Response) -> Option<T>,
) -> Result<T, String> {
    let name = request_name(&req);
    let resp = call(req).await?;
    let got = response_name(&resp);
    pick(resp).ok_or_else(|| format!("{name}: voidwired answered {got}, expected {expected}"))
}
