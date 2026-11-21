//! Detection and installation of the privileged `voidwired` service.
//!
//! The daemon and CLI ship as Tauri sidecars (`bundle.externalBin`). Tauri
//! places them next to the main executable with the target-triple suffix
//! stripped (`VoidWire.app/Contents/MacOS/voidwired`,
//! `C:\Program Files\VoidWire\voidwired.exe`), and `tauri dev` copies them
//! into the cargo target directory the same way, so one lookup covers
//! development and release builds.
//!
//! Contract with the daemon (`voidwired install` / `voidwired uninstall`):
//! `install` must be idempotent, run elevated, copy itself to a stable
//! location, register the launchd daemon / Windows service, create the state
//! directory and the IPC token, start the service and exit 0 on success
//! (non-zero plus a message on stderr otherwise).

use std::io::ErrorKind;
use std::path::{Path, PathBuf};

use serde::Serialize;

use crate::bridge;

#[cfg(windows)]
const DAEMON_FILE: &str = "voidwired.exe";
#[cfg(not(windows))]
const DAEMON_FILE: &str = "voidwired";

/// What the UI needs to explain why it cannot talk to the daemon.
#[derive(Debug, Clone, Serialize)]
pub struct DaemonPresence {
    /// `<state_dir>/ipc.token` exists (the service has been installed).
    pub token_present: bool,
    /// The token exists and this user may read it.
    pub token_readable: bool,
    /// Where the token is expected.
    pub token_path: String,
    /// Socket path / pipe name.
    pub endpoint: String,
    /// An authenticated VWIPC handshake succeeded just now.
    pub reachable: bool,
    pub daemon_version: Option<String>,
    /// Path of the bundled `voidwired` sidecar, if it is present.
    pub sidecar: Option<String>,
    /// Last connection error, verbatim from the bridge.
    pub error: Option<String>,
}

/// Locate the bundled daemon binary next to the running executable.
pub fn sidecar_path() -> Option<PathBuf> {
    let exe = std::env::current_exe().ok()?;
    let dir = exe.parent()?;
    let candidate = dir.join(DAEMON_FILE);
    candidate.is_file().then_some(candidate)
}

fn token_state(path: &Path) -> (bool, bool) {
    match std::fs::File::open(path) {
        Ok(_) => (true, true),
        Err(e) if e.kind() == ErrorKind::PermissionDenied => (true, false),
        Err(_) => match std::fs::metadata(path) {
            Ok(_) => (true, false),
            // Parent directory not traversable: the state dir exists but is
            // locked down, which means the service was installed.
            Err(e) if e.kind() == ErrorKind::PermissionDenied => (true, false),
            Err(_) => (false, false),
        },
    }
}

pub async fn presence() -> DaemonPresence {
    let token_path = vw_core::paths::token_file();
    let (token_present, token_readable) = token_state(&token_path);
    let (reachable, daemon_version, error) = match bridge::connect().await {
        Ok(c) => (true, Some(c.daemon_version.clone()), None),
        Err(e) => (false, None, Some(e)),
    };
    DaemonPresence {
        token_present,
        token_readable,
        token_path: token_path.display().to_string(),
        endpoint: vw_core::paths::ipc_endpoint(),
        reachable,
        daemon_version,
        sidecar: sidecar_path().map(|p| p.display().to_string()),
        error,
    }
}

/// Run `voidwired install` with administrator rights. Blocks until the
/// elevated process exits; call from a blocking thread.
pub fn install_elevated() -> Result<String, String> {
    let daemon = sidecar_path().ok_or_else(|| {
        format!(
            "the bundled {DAEMON_FILE} was not found next to the app executable; \
             reinstall VoidWire from the official release"
        )
    })?;
    run_elevated(&daemon, "install")
}

/// Quote `s` for a POSIX shell (single quotes, `'` → `'\''`).
#[cfg(any(target_os = "macos", test))]
fn sh_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', r"'\''"))
}

/// Escape `s` for use inside an AppleScript double-quoted string literal.
#[cfg(any(target_os = "macos", test))]
fn applescript_escape(s: &str) -> String {
    s.replace('\\', r"\\").replace('"', "\\\"")
}

#[cfg(any(target_os = "macos", test))]
fn osascript_program(daemon: &Path, verb: &str) -> String {
    let cmd = format!("{} {verb}", sh_quote(&daemon.display().to_string()));
    format!(
        "do shell script \"{}\" with administrator privileges",
        applescript_escape(&cmd)
    )
}

#[cfg(target_os = "macos")]
fn run_elevated(daemon: &Path, verb: &str) -> Result<String, String> {
    let out = std::process::Command::new("/usr/bin/osascript")
        .arg("-e")
        .arg(osascript_program(daemon, verb))
        .output()
        .map_err(|e| format!("cannot start osascript: {e}"))?;
    let stdout = String::from_utf8_lossy(&out.stdout).trim().to_string();
    let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();
    if out.status.success() {
        return Ok(if stdout.is_empty() {
            "VoidWire service installed".into()
        } else {
            stdout
        });
    }
    // AppleScript error -128 = the user dismissed the password prompt.
    if stderr.contains("(-128)") {
        return Err("installation cancelled at the administrator prompt".into());
    }
    Err(if stderr.is_empty() {
        format!("voidwired {verb} failed ({})", out.status)
    } else {
        format!("voidwired {verb} failed: {stderr}")
    })
}

#[cfg(windows)]
fn run_elevated(daemon: &Path, verb: &str) -> Result<String, String> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, ERROR_CANCELLED};
    use windows_sys::Win32::System::Threading::{
        GetExitCodeProcess, WaitForSingleObject, INFINITE,
    };
    use windows_sys::Win32::UI::Shell::{
        ShellExecuteExW, SEE_MASK_NOASYNC, SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW,
    };
    use windows_sys::Win32::UI::WindowsAndMessaging::SW_HIDE;

    fn wide(s: &std::ffi::OsStr) -> Vec<u16> {
        s.encode_wide().chain(std::iter::once(0)).collect()
    }
    let file = wide(daemon.as_os_str());
    let params = wide(std::ffi::OsStr::new(verb));
    let runas = wide(std::ffi::OsStr::new("runas"));

    // SAFETY: SHELLEXECUTEINFOW is a plain C struct; all-zero is its
    // documented "unset" state before we fill the fields we use.
    let mut info: SHELLEXECUTEINFOW = unsafe { std::mem::zeroed() };
    info.cbSize = std::mem::size_of::<SHELLEXECUTEINFOW>() as u32;
    info.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC;
    info.lpVerb = runas.as_ptr();
    info.lpFile = file.as_ptr();
    info.lpParameters = params.as_ptr();
    info.nShow = SW_HIDE;

    // SAFETY: `info` is fully initialised and the UTF-16 buffers it points to
    // (`runas`, `file`, `params`) outlive the call.
    let ok = unsafe { ShellExecuteExW(&mut info) };
    if ok == 0 {
        // SAFETY: reads the calling thread's last-error value; no pointers.
        let err = unsafe { GetLastError() };
        if err == ERROR_CANCELLED {
            return Err("installation cancelled at the UAC prompt".into());
        }
        return Err(format!(
            "could not start voidwired {verb} elevated (error {err})"
        ));
    }
    if info.hProcess.is_null() {
        return Err(format!("voidwired {verb} started without a process handle"));
    }
    let mut code: u32 = 1;
    // SAFETY: `hProcess` is a valid process handle returned because we set
    // SEE_MASK_NOCLOSEPROCESS; we wait on it, read its exit code and close it
    // exactly once.
    unsafe {
        WaitForSingleObject(info.hProcess, INFINITE);
        GetExitCodeProcess(info.hProcess, &mut code);
        CloseHandle(info.hProcess);
    }
    if code == 0 {
        Ok("VoidWire service installed".into())
    } else {
        Err(format!("voidwired {verb} exited with code {code}"))
    }
}

#[cfg(not(any(target_os = "macos", windows)))]
fn run_elevated(daemon: &Path, verb: &str) -> Result<String, String> {
    // Linux desktops: polkit's pkexec shows the graphical admin prompt.
    let out = std::process::Command::new("pkexec")
        .arg(daemon)
        .arg(verb)
        .output()
        .map_err(|e| format!("cannot start pkexec: {e}"))?;
    if out.status.success() {
        Ok("VoidWire service installed".into())
    } else if out.status.code() == Some(126) {
        Err("installation cancelled at the administrator prompt".into())
    } else {
        Err(format!(
            "voidwired {verb} failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quoting_survives_hostile_paths() {
        let p = Path::new(r#"/Applications/Vo"id 'Wire\.app/Contents/MacOS/voidwired"#);
        let prog = osascript_program(p, "install");
        assert_eq!(
            prog,
            r#"do shell script "'/Applications/Vo\"id '\\''Wire\\.app/Contents/MacOS/voidwired' install" with administrator privileges"#
        );
    }

    #[test]
    fn sh_quote_plain() {
        assert_eq!(sh_quote("/a b/c"), "'/a b/c'");
    }
}
