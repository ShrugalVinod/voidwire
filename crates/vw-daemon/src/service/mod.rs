//! `voidwired run | install | uninstall | status` (ARCHITECTURE.md §13).

use std::future::Future;
use std::path::Path;
use std::sync::Arc;

use anyhow::Context;
use vw_core::paths;
use vw_core::secret::Key32;

use crate::controller::{install_panic_hook, Controller};
use crate::events::EventHub;
use crate::platform::OsPlatform;
use crate::store::Store;
use crate::util::{set_access, write_protected, Access};

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(windows)]
pub mod windows;

#[cfg(target_os = "linux")]
use linux as os;
#[cfg(target_os = "macos")]
use macos as os;
#[cfg(windows)]
use windows as os;

/// Service registration state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ServiceStatus {
    pub installed: bool,
    pub running: bool,
}

/// Run the daemon until `shutdown` resolves. The lockdown is deliberately
/// left in place on exit (fail-closed); launchd / SCM / systemd restart us.
pub async fn run_daemon(
    events: EventHub,
    shutdown: impl Future<Output = ()>,
) -> anyhow::Result<()> {
    let state = paths::state_dir();
    if !state.exists() {
        std::fs::create_dir_all(&state)?;
        set_access(&state, Access::Dir)?;
    }
    let token = ensure_token(&paths::token_file())?;
    let store = Store::load(&paths::store_file()).context("loading client store")?;
    let platform = Arc::new(OsPlatform::new(state));
    let c = Controller::with_events(platform, store, events);
    install_panic_hook(&c);
    if let Err(e) = c.start().await {
        tracing::error!(error = %e, "startup incomplete; lockdown state preserved");
    }
    let endpoint = paths::ipc_endpoint();
    tokio::select! {
        r = crate::ipc_server::listen(c.clone(), &endpoint, token) => r.context("IPC server")?,
        _ = shutdown => tracing::info!("stopping; lockdown left in place"),
    }
    Ok(())
}

/// Keep a valid token, otherwise write a fresh 32-byte hex token (0640).
pub fn ensure_token(path: &Path) -> anyhow::Result<Key32> {
    if let Ok(t) = vw_core::ipc::load_token(path) {
        set_access(path, Access::GroupRead)?;
        return Ok(t);
    }
    let t = Key32::random();
    let hex = zeroize::Zeroizing::new(hex::encode(t.expose()));
    write_protected(path, hex.as_bytes(), Access::GroupRead)?;
    Ok(t)
}

/// State dir (0750 / ACL) and token.
pub fn prepare_state() -> anyhow::Result<()> {
    let state = paths::state_dir();
    std::fs::create_dir_all(&state)?;
    set_access(&state, Access::Dir)?;
    ensure_token(&paths::token_file())?;
    Ok(())
}

/// Remove the lockdown before uninstalling: through the running daemon when
/// possible, otherwise directly.
pub async fn disarm_for_uninstall() -> anyhow::Result<()> {
    let via_ipc = async {
        let mut c = vw_core::ipc::IpcClient::connect_default().await?;
        c.request(&vw_core::ipc::Request::Disarm).await
    };
    match tokio::time::timeout(std::time::Duration::from_secs(20), via_ipc).await {
        Ok(Ok(_)) => return Ok(()),
        _ => tracing::info!("daemon not reachable; disarming directly"),
    }
    tokio::task::spawn_blocking(|| -> anyhow::Result<()> {
        vw_firewall::platform_backend().disarm()?;
        vw_firewall::sysdns::SystemDns::new(&paths::state_dir()).restore()?;
        let _ = std::fs::remove_file(paths::lockdown_marker());
        Ok(())
    })
    .await?
}

/// Delete the state dir, keeping store and token with `keep_config`.
pub fn remove_state(keep_config: bool) -> anyhow::Result<()> {
    let state = paths::state_dir();
    if !state.exists() {
        return Ok(());
    }
    if !keep_config {
        std::fs::remove_dir_all(&state)?;
        return Ok(());
    }
    let keep = [paths::store_file(), paths::token_file()];
    for e in std::fs::read_dir(&state)? {
        let p = e?.path();
        if keep.contains(&p) {
            continue;
        }
        if p.is_dir() {
            std::fs::remove_dir_all(&p)?;
        } else {
            std::fs::remove_file(&p)?;
        }
    }
    Ok(())
}

pub async fn install() -> anyhow::Result<()> {
    os::require_admin()?;
    os::install().await
}

pub async fn uninstall(keep_config: bool) -> anyhow::Result<()> {
    os::require_admin()?;
    disarm_for_uninstall().await?;
    os::uninstall().await?;
    remove_state(keep_config)
}

pub fn status() -> anyhow::Result<ServiceStatus> {
    os::status()
}

/// Atomically copy `src` to `dst` (write temp + rename) with mode 0755 on unix.
pub fn copy_binary(src: &Path, dst: &Path) -> anyhow::Result<()> {
    if src == dst {
        return Ok(());
    }
    if let Some(d) = dst.parent() {
        std::fs::create_dir_all(d)?;
    }
    let tmp = dst.with_extension("new");
    std::fs::copy(src, &tmp).with_context(|| format!("copying to {}", tmp.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o755))?;
        std::os::unix::fs::chown(&tmp, Some(0), Some(0))?;
    }
    std::fs::rename(&tmp, dst)?;
    Ok(())
}

#[cfg(unix)]
fn require_root() -> anyhow::Result<()> {
    if !nix::unistd::geteuid().is_root() {
        anyhow::bail!("this command must run as root (sudo voidwired ...)");
    }
    Ok(())
}

/// Tracing: stderr + sanitized forwarding to IPC subscribers.
pub fn init_tracing(events: EventHub) {
    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::util::SubscriberInitExt;
    use tracing_subscriber::EnvFilter;
    let filter = EnvFilter::try_from_env("VOIDWIRE_LOG").unwrap_or_else(|_| EnvFilter::new("info"));
    let _ = tracing_subscriber::registry()
        .with(filter)
        .with(tracing_subscriber::fmt::layer().with_writer(std::io::stderr))
        .with(crate::events::LogForward::new(events))
        .try_init();
}
