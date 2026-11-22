//! `voidwire exec -- <cmd...>`: run one program confined to the tunnel.
//!
//! The daemon prepares the isolation (`ExecPrepare`). On Linux it returns a
//! network namespace whose only route is the tunnel; the program is started
//! inside it through `ip netns exec`, dropped back to the invoking user with
//! `setpriv`. On macOS and Windows the system-wide Iron Dome lockdown is the
//! isolation, so the program is spawned directly once the tunnel is verified
//! active. User arguments are always passed as argv, never through a shell.

use std::ffi::OsString;

use vw_core::ipc::{ExecTicket, Request, Response};

use crate::daemon;
use crate::exit::{child_exit_code, CliError, CliResult, ExitCode};
use crate::output::Out;
use crate::render;

/// Who the program should run as inside the namespace.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Identity {
    pub uid: u32,
    pub gid: u32,
}

/// Resolve the invoking user: `SUDO_UID`/`SUDO_GID` when we run as root via
/// sudo, otherwise our own ids.
pub fn invoking_identity(
    euid: u32,
    egid: u32,
    sudo_uid: Option<&str>,
    sudo_gid: Option<&str>,
) -> Identity {
    if euid == 0 {
        let uid = sudo_uid.and_then(|s| s.trim().parse().ok());
        let gid = sudo_gid.and_then(|s| s.trim().parse().ok());
        if let (Some(uid), Some(gid)) = (uid, gid) {
            return Identity { uid, gid };
        }
    }
    Identity {
        uid: euid,
        gid: egid,
    }
}

/// argv for running `cmd` in namespace `ns` as `who`. When we are not root the
/// whole invocation is wrapped in `sudo`.
pub fn netns_argv(ns: &str, who: Identity, is_root: bool, cmd: &[OsString]) -> Vec<OsString> {
    let mut v: Vec<OsString> = Vec::with_capacity(cmd.len() + 12);
    if !is_root {
        v.push("sudo".into());
        v.push("--".into());
    }
    for a in [
        "ip",
        "netns",
        "exec",
        ns,
        "setpriv",
        "--reuid",
        &who.uid.to_string(),
        "--regid",
        &who.gid.to_string(),
        "--init-groups",
        "--",
    ] {
        v.push(a.into());
    }
    v.extend(cmd.iter().cloned());
    v
}

/// Namespace names come from the daemon; reject anything that could be
/// mistaken for an option or a path.
pub fn valid_netns_name(ns: &str) -> bool {
    !ns.is_empty()
        && ns.len() <= 64
        && !ns.starts_with('-')
        && ns
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
        && ns != "."
        && ns != ".."
}

async fn spawn_and_wait(argv: &[OsString]) -> CliResult<i32> {
    let (prog, args) = argv
        .split_first()
        .ok_or_else(|| CliError::usage("no command given"))?;
    let mut child = tokio::process::Command::new(prog)
        .args(args)
        .spawn()
        .map_err(|e| {
            CliError::new(
                ExitCode::Failure,
                format!("cannot start {}: {e}", prog.to_string_lossy()),
            )
        })?;
    // The terminal delivers Ctrl-C to the child too; we keep running so its
    // exit status is propagated instead of dying first.
    let swallow = tokio::spawn(async { while tokio::signal::ctrl_c().await.is_ok() {} });
    let status = child.wait().await;
    swallow.abort();
    let status = status.map_err(|e| CliError::failure(format!("waiting for child: {e}")))?;
    Ok(child_exit_code(&status))
}

#[cfg(target_os = "linux")]
fn current_ids() -> CliResult<(u32, u32)> {
    use std::os::unix::fs::MetadataExt;
    // /proc/self is owned by the effective uid/gid of this process.
    let m = std::fs::metadata("/proc/self")
        .map_err(|e| CliError::failure(format!("cannot determine current user: {e}")))?;
    Ok((m.uid(), m.gid()))
}

#[cfg(target_os = "linux")]
async fn run_in_netns(out: &mut Out, ns: &str, cmd: &[OsString]) -> CliResult<i32> {
    if !valid_netns_name(ns) {
        return Err(CliError::failure(format!(
            "voidwired returned an invalid namespace name {ns:?}"
        )));
    }
    let (euid, egid) = current_ids()?;
    let sudo_uid = std::env::var("SUDO_UID").ok();
    let sudo_gid = std::env::var("SUDO_GID").ok();
    let who = invoking_identity(euid, egid, sudo_uid.as_deref(), sudo_gid.as_deref());
    let is_root = euid == 0;
    if !is_root {
        out.note(&out.theme.dim(
            "Entering the tunnel namespace needs root: sudo may ask for your password. \
             The command itself runs as you (setpriv drops privileges).",
        ));
    }
    spawn_and_wait(&netns_argv(ns, who, is_root, cmd)).await
}

#[cfg(not(target_os = "linux"))]
async fn run_in_netns(_out: &mut Out, ns: &str, _cmd: &[OsString]) -> CliResult<i32> {
    Err(CliError::failure(format!(
        "voidwired offered network namespace {ns:?}, but namespaces only exist on Linux"
    )))
}

pub async fn run(out: &mut Out, cmd: Vec<OsString>) -> CliResult<i32> {
    if cmd.is_empty() {
        return Err(CliError::usage("no command given"));
    }
    let mut client = daemon::connect().await?;
    let req = Request::ExecPrepare;
    let ticket: ExecTicket = match daemon::call(&mut client, &req).await? {
        Response::Exec(t) => t,
        other => return Err(daemon::unexpected(&req, &other)),
    };
    let status = daemon::status(&mut client).await?;
    drop(client);
    if !status.state.traffic_allowed() {
        return Err(CliError::new(
            ExitCode::Rejected,
            format!(
                "the tunnel is not active (state {}); refusing to run the command",
                render::state_name(status.state)
            ),
        )
        .with_hint("Bring it up first with `voidwire up`."));
    }
    let t = out.theme;
    out.note(&format!("{} {}", t.accent("isolation:"), ticket.isolation));
    match ticket.netns.as_deref() {
        Some(ns) => run_in_netns(out, ns, &cmd).await,
        None => spawn_and_wait(&cmd).await,
    }
}
