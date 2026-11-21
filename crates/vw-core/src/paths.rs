//! Per-OS filesystem and IPC locations.

use std::path::PathBuf;

/// Directory holding the client store, settings and IPC token.
pub fn state_dir() -> PathBuf {
    if let Some(p) = std::env::var_os("VOIDWIRE_STATE_DIR") {
        return PathBuf::from(p);
    }
    #[cfg(target_os = "macos")]
    {
        PathBuf::from("/Library/Application Support/VoidWire")
    }
    #[cfg(target_os = "windows")]
    {
        let base = std::env::var_os("ProgramData").unwrap_or_else(|| "C:\\ProgramData".into());
        PathBuf::from(base).join("VoidWire")
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    {
        PathBuf::from("/var/lib/voidwire")
    }
}

pub fn store_file() -> PathBuf {
    state_dir().join("store.json")
}

pub fn token_file() -> PathBuf {
    state_dir().join("ipc.token")
}

/// Marker that re-arms the lockdown at boot.
pub fn lockdown_marker() -> PathBuf {
    state_dir().join("lockdown.armed")
}

/// IPC endpoint: a Unix socket path, or a Windows named pipe name.
pub fn ipc_endpoint() -> String {
    if let Ok(p) = std::env::var("VOIDWIRE_IPC") {
        return p;
    }
    #[cfg(target_os = "windows")]
    {
        r"\\.\pipe\voidwired".to_string()
    }
    #[cfg(not(target_os = "windows"))]
    {
        "/var/run/voidwire/voidwired.sock".to_string()
    }
}
