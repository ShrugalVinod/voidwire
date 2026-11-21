//! Tauri commands: one per VWIPC request, plus service management helpers.
//!
//! Typed queries return the payload of the expected `Response` variant;
//! actions return the daemon's `Response` verbatim (usually `Ok`) so the UI
//! can show exactly what the daemon said.

use serde::Serialize;
use tauri::{AppHandle, State};
use vw_core::config::{Profile, Settings, TransportKind};
use vw_core::ipc::{AuditReport, NodeSummary, Request, Response, StatusReport};
use vw_core::probe::OptimizerDecision;
use vw_core::telemetry::TelemetrySnapshot;

use crate::bridge::{call, call_expect};
use crate::events::{self, Link, LinkStatus};
use crate::service::{self, DaemonPresence};

#[tauri::command(rename_all = "snake_case")]
pub async fn status() -> Result<StatusReport, String> {
    call_expect(Request::Status, "Status", |r| match r {
        Response::Status(s) => Some(*s),
        _ => None,
    })
    .await
}

#[tauri::command(rename_all = "snake_case")]
pub async fn up(
    profile: Profile,
    country: Option<String>,
    transport: Option<TransportKind>,
) -> Result<Response, String> {
    let country = country
        .map(|c| c.trim().to_ascii_uppercase())
        .filter(|c| !c.is_empty());
    if let Some(c) = &country {
        if c.len() != 2 || !c.chars().all(|ch| ch.is_ascii_alphabetic()) {
            return Err("country filter must be a two-letter ISO 3166-1 code".into());
        }
    }
    call(Request::Up {
        profile,
        country,
        transport,
    })
    .await
}

#[tauri::command(rename_all = "snake_case")]
pub async fn down(keep_lockdown: bool) -> Result<Response, String> {
    call(Request::Down { keep_lockdown }).await
}

#[tauri::command(rename_all = "snake_case")]
pub async fn disarm() -> Result<Response, String> {
    call(Request::Disarm).await
}

#[tauri::command(rename_all = "snake_case")]
pub async fn panic(app: AppHandle) -> Result<(), String> {
    events::trigger_panic(&app, "ui").await
}

#[tauri::command(rename_all = "snake_case")]
pub async fn audit() -> Result<AuditReport, String> {
    call_expect(Request::Audit, "Audit", |r| match r {
        Response::Audit(a) => Some(a),
        _ => None,
    })
    .await
}

#[tauri::command(rename_all = "snake_case")]
pub async fn optimize() -> Result<OptimizerDecision, String> {
    call_expect(Request::Optimize, "Optimized", |r| match r {
        Response::Optimized(d) => Some(*d),
        _ => None,
    })
    .await
}

#[tauri::command(rename_all = "snake_case")]
pub async fn get_settings() -> Result<Settings, String> {
    call_expect(Request::GetSettings, "Settings", |r| match r {
        Response::Settings(s) => Some(*s),
        _ => None,
    })
    .await
}

#[tauri::command(rename_all = "snake_case")]
pub async fn set_settings(settings: Settings) -> Result<Response, String> {
    call(Request::SetSettings(Box::new(settings))).await
}

#[tauri::command(rename_all = "snake_case")]
pub async fn list_nodes() -> Result<Vec<NodeSummary>, String> {
    call_expect(Request::ListNodes, "Nodes", |r| match r {
        Response::Nodes(n) => Some(n),
        _ => None,
    })
    .await
}

fn clean_uri(uri: &str, prefix: &str) -> Result<String, String> {
    let uri = uri.trim();
    if !uri.starts_with(prefix) {
        return Err(format!("expected a URI starting with {prefix}"));
    }
    Ok(uri.to_string())
}

#[tauri::command(rename_all = "snake_case")]
pub async fn import_node(uri: String) -> Result<Response, String> {
    let uri = clean_uri(&uri, vw_core::uri::NODE_PREFIX)?;
    // Validate locally first for a precise error before bothering the daemon.
    vw_core::uri::decode_node(&uri).map_err(|e| e.to_string())?;
    call(Request::ImportNode { uri }).await
}

#[tauri::command(rename_all = "snake_case")]
pub async fn remove_node(name: String) -> Result<Response, String> {
    if name.trim().is_empty() {
        return Err("node name is empty".into());
    }
    call(Request::RemoveNode { name }).await
}

#[tauri::command(rename_all = "snake_case")]
pub async fn redeem_invite(uri: String) -> Result<Response, String> {
    let uri = clean_uri(&uri, vw_core::uri::F2F_PREFIX)?;
    vw_core::uri::decode_blob(vw_core::uri::F2F_PREFIX, &uri).map_err(|e| e.to_string())?;
    call(Request::RedeemInvite { uri }).await
}

#[tauri::command(rename_all = "snake_case")]
pub async fn register_warp() -> Result<Response, String> {
    call(Request::RegisterWarp).await
}

#[tauri::command(rename_all = "snake_case")]
pub async fn telemetry() -> Result<TelemetrySnapshot, String> {
    call_expect(Request::Telemetry, "Telemetry", |r| match r {
        Response::Telemetry(t) => Some(t),
        _ => None,
    })
    .await
}

#[tauri::command(rename_all = "snake_case")]
pub async fn daemon_installed() -> Result<DaemonPresence, String> {
    Ok(service::presence().await)
}

#[tauri::command(rename_all = "snake_case")]
pub async fn install_service() -> Result<String, String> {
    tauri::async_runtime::spawn_blocking(service::install_elevated)
        .await
        .map_err(|e| format!("installer thread failed: {e}"))?
}

#[tauri::command(rename_all = "snake_case")]
pub fn link_status(link: State<'_, Link>) -> LinkStatus {
    link.snapshot()
}

/// Registration error of the global panic shortcut, if another app owns it.
pub struct ShortcutStatus(pub Option<String>);

#[derive(Debug, Clone, Serialize)]
pub struct AppInfo {
    pub os: &'static str,
    pub arch: &'static str,
    pub version: &'static str,
    pub panic_shortcut: &'static str,
    pub shortcut_error: Option<String>,
}

#[tauri::command(rename_all = "snake_case")]
pub fn app_info(shortcut: State<'_, ShortcutStatus>) -> AppInfo {
    AppInfo {
        shortcut_error: shortcut.0.clone(),
        os: std::env::consts::OS,
        arch: std::env::consts::ARCH,
        version: env!("CARGO_PKG_VERSION"),
        panic_shortcut: if cfg!(target_os = "macos") {
            "⌘⇧X"
        } else {
            "Ctrl+Shift+X"
        },
    }
}
