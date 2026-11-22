//! systemd integration.

use std::path::Path;

use super::ServiceStatus;
use crate::util::{run, run_ok};

pub const BIN: &str = "/usr/local/sbin/voidwired";
pub const UNIT: &str = "/etc/systemd/system/voidwired.service";
const SYSTEMCTL: &str = "systemctl";

pub fn require_admin() -> anyhow::Result<()> {
    super::require_root()
}

pub fn unit() -> String {
    format!(
        "[Unit]\nDescription=VoidWire privileged client daemon\nAfter=network-pre.target\nWants=network-pre.target\n\n\
[Service]\nType=simple\nExecStart={BIN} run\nRestart=always\nRestartSec=2\n\n\
[Install]\nWantedBy=multi-user.target\n"
    )
}

pub async fn install() -> anyhow::Result<()> {
    if nix::unistd::Group::from_name(crate::util::ADMIN_GROUP)?.is_none() {
        run_ok("groupadd", &["--system", crate::util::ADMIN_GROUP]).await?;
    }
    let _ = run(SYSTEMCTL, &["stop", "voidwired"]).await;
    super::copy_binary(&std::env::current_exe()?, Path::new(BIN))?;
    std::fs::write(UNIT, unit())?;
    super::prepare_state()?;
    run_ok(SYSTEMCTL, &["daemon-reload"]).await?;
    run_ok(SYSTEMCTL, &["enable", "--now", "voidwired"]).await?;
    Ok(())
}

pub async fn uninstall() -> anyhow::Result<()> {
    let _ = run(SYSTEMCTL, &["disable", "--now", "voidwired"]).await;
    for p in [UNIT, BIN] {
        match std::fs::remove_file(p) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
    }
    let _ = run(SYSTEMCTL, &["daemon-reload"]).await;
    Ok(())
}

pub fn status() -> anyhow::Result<ServiceStatus> {
    let installed = Path::new(UNIT).exists() && Path::new(BIN).exists();
    let running = crate::util::run_sync(SYSTEMCTL, &["is-active", "--quiet", "voidwired"])
        .map(|o| o.success)
        .unwrap_or(false);
    Ok(ServiceStatus { installed, running })
}
