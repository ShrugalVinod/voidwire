//! launchd integration.

use std::path::Path;

use super::ServiceStatus;
use crate::util::{run, run_ok};

pub const LABEL: &str = "com.voidwire.daemon";
pub const BIN: &str = "/Library/PrivilegedHelperTools/com.voidwire.daemon";
pub const PLIST: &str = "/Library/LaunchDaemons/com.voidwire.daemon.plist";
const LAUNCHCTL: &str = "/bin/launchctl";

pub fn require_admin() -> anyhow::Result<()> {
    super::require_root()
}

/// The LaunchDaemon property list.
pub fn plist() -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{LABEL}</string>
    <key>ProgramArguments</key>
    <array>
        <string>{BIN}</string>
        <string>run</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>ProcessType</key>
    <string>Interactive</string>
    <key>StandardErrorPath</key>
    <string>/Library/Logs/VoidWire/voidwired.log</string>
</dict>
</plist>
"#
    )
}

pub async fn install() -> anyhow::Result<()> {
    let target = format!("system/{LABEL}");
    // Stop a running copy before replacing the binary (idempotent).
    let _ = run(LAUNCHCTL, &["bootout", &target]).await;
    super::copy_binary(&std::env::current_exe()?, Path::new(BIN))?;
    std::fs::create_dir_all("/Library/Logs/VoidWire")?;
    let tmp = Path::new(PLIST).with_extension("tmp");
    std::fs::write(&tmp, plist())?;
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o644))?;
        std::os::unix::fs::chown(&tmp, Some(0), Some(0))?;
    }
    std::fs::rename(&tmp, PLIST)?;
    super::prepare_state()?;
    run_ok(LAUNCHCTL, &["bootstrap", "system", PLIST]).await?;
    run_ok(LAUNCHCTL, &["enable", &target]).await?;
    run_ok(LAUNCHCTL, &["kickstart", "-k", &target]).await?;
    Ok(())
}

pub async fn uninstall() -> anyhow::Result<()> {
    let _ = run(LAUNCHCTL, &["bootout", &format!("system/{LABEL}")]).await;
    for p in [PLIST, BIN] {
        match std::fs::remove_file(p) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
    }
    Ok(())
}

pub fn status() -> anyhow::Result<ServiceStatus> {
    let installed = Path::new(PLIST).exists() && Path::new(BIN).exists();
    let running = crate::util::run_sync(LAUNCHCTL, &["print", &format!("system/{LABEL}")])
        .map(|o| o.success && o.stdout.contains("state = running"))
        .unwrap_or(false);
    Ok(ServiceStatus { installed, running })
}

#[cfg(test)]
mod tests {
    #[test]
    fn plist_has_required_keys() {
        let p = super::plist();
        for k in [
            "RunAtLoad",
            "KeepAlive",
            super::LABEL,
            super::BIN,
            "<string>run</string>",
        ] {
            assert!(p.contains(k), "{k}");
        }
    }
}
