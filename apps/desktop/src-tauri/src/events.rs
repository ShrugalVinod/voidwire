//! Background bridge: subscribes to the daemon event stream and re-emits
//! every `DaemonEvent` to the webview, reconnecting with exponential backoff
//! whenever `voidwired` restarts or is not installed yet.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde::Serialize;
use tauri::{AppHandle, Emitter, Manager};
use vw_core::ipc::{DaemonEvent, Request, Response};
use vw_core::state::DomeState;

use crate::{bridge, tray};

/// Webview event carrying a serialized `DaemonEvent`.
pub const EVENT_DAEMON: &str = "voidwire://event";
/// Webview event carrying [`LinkStatus`] whenever it changes.
pub const EVENT_LINK: &str = "voidwire://link";
/// Webview event carrying [`PanicNotice`] (global shortcut, tray, button).
pub const EVENT_PANIC: &str = "voidwire://panic";
/// Webview event carrying [`Notice`] for actions started outside the webview.
pub const EVENT_NOTICE: &str = "voidwire://notice";

const BACKOFF_MIN: Duration = Duration::from_millis(250);
const BACKOFF_MAX: Duration = Duration::from_secs(8);

/// Whether the event stream to the daemon is currently up.
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct LinkStatus {
    pub connected: bool,
    pub daemon_version: Option<String>,
    pub error: Option<String>,
    /// Last Iron Dome state seen (from `Status` or `StateChanged`).
    pub state: Option<DomeState>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PanicNotice {
    /// `requested`, `done` or `failed`.
    pub stage: &'static str,
    /// What triggered it: `shortcut`, `tray` or `ui`.
    pub source: &'static str,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Notice {
    pub level: &'static str,
    pub message: String,
}

/// Shared, managed link state.
#[derive(Default, Clone)]
pub struct Link(pub Arc<Mutex<LinkStatus>>);

impl Link {
    pub fn snapshot(&self) -> LinkStatus {
        self.0.lock().map(|g| g.clone()).unwrap_or_default()
    }

    fn update(&self, app: &AppHandle, f: impl FnOnce(&mut LinkStatus)) {
        let snap = match self.0.lock() {
            Ok(mut g) => {
                let before = g.clone();
                f(&mut g);
                if *g == before {
                    return;
                }
                g.clone()
            }
            Err(_) => return,
        };
        tray::set_tooltip(app, &snap);
        let _ = app.emit(EVENT_LINK, &snap);
    }
}

pub fn notice(app: &AppHandle, level: &'static str, message: impl Into<String>) {
    let _ = app.emit(
        EVENT_NOTICE,
        Notice {
            level,
            message: message.into(),
        },
    );
}

/// Panic request shared by the global shortcut, the tray and the UI button.
pub async fn trigger_panic(app: &AppHandle, source: &'static str) -> Result<(), String> {
    let _ = app.emit(
        EVENT_PANIC,
        PanicNotice {
            stage: "requested",
            source,
            error: None,
        },
    );
    let res = bridge::call(Request::Panic).await.map(|_| ());
    let _ = app.emit(
        EVENT_PANIC,
        PanicNotice {
            stage: if res.is_ok() { "done" } else { "failed" },
            source,
            error: res.as_ref().err().cloned(),
        },
    );
    res
}

/// Start the subscribe/re-emit loop on Tauri's async runtime.
pub fn spawn(app: AppHandle) {
    tauri::async_runtime::spawn(async move {
        let link = app.state::<Link>().inner().clone();
        let mut backoff = BACKOFF_MIN;
        loop {
            match run_once(&app, &link).await {
                // The stream was up and then dropped: retry quickly.
                Ok(()) => backoff = BACKOFF_MIN,
                Err(e) => {
                    link.update(&app, |s| {
                        s.connected = false;
                        s.daemon_version = None;
                        s.error = Some(e);
                    });
                }
            }
            tokio::time::sleep(backoff).await;
            backoff = (backoff * 2).min(BACKOFF_MAX);
        }
    });
}

/// One connection lifetime. Returns `Ok` if the stream was established and
/// later closed, `Err` if it could not be established.
async fn run_once(app: &AppHandle, link: &Link) -> Result<(), String> {
    // Seed the state from a Status call so the tray is right before the
    // first StateChanged arrives.
    let initial = match bridge::call(Request::Status).await? {
        Response::Status(s) => Some(s.state),
        _ => None,
    };
    let client = bridge::connect().await?;
    let version = client.daemon_version.clone();
    let mut stream = client.subscribe().await.map_err(|e| bridge::describe(&e))?;
    link.update(app, |s| {
        s.connected = true;
        s.daemon_version = Some(version);
        s.error = None;
        if initial.is_some() {
            s.state = initial;
        }
    });
    loop {
        match stream.next().await {
            Ok(ev) => {
                if let DaemonEvent::StateChanged { to, .. } = &ev {
                    let to = *to;
                    link.update(app, |s| s.state = Some(to));
                }
                let _ = app.emit(EVENT_DAEMON, &ev);
            }
            Err(e) => {
                link.update(app, |s| {
                    s.connected = false;
                    s.daemon_version = None;
                    s.error = Some(bridge::describe(&e));
                });
                return Ok(());
            }
        }
    }
}
