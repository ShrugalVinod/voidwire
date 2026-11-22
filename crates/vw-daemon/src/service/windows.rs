//! Windows Service Control Manager integration (`VoidWire` service).

use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::Context;
use windows_service::service::{
    ServiceAccess, ServiceAction, ServiceActionType, ServiceControl, ServiceControlAccept,
    ServiceErrorControl, ServiceExitCode, ServiceFailureActions, ServiceFailureResetPeriod,
    ServiceInfo, ServiceStartType, ServiceState, ServiceStatus as WinStatus, ServiceType,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};
use windows_service::{define_windows_service, service_dispatcher};

use super::ServiceStatus;

pub const SERVICE_NAME: &str = "VoidWire";
const DISPLAY_NAME: &str = "VoidWire Daemon";
/// ERROR_FAILED_SERVICE_CONTROLLER_CONNECT: not started by the SCM.
const NOT_A_SERVICE: i32 = 1063;

fn install_dir() -> PathBuf {
    let pf = std::env::var_os("ProgramFiles").unwrap_or_else(|| "C:\\Program Files".into());
    PathBuf::from(pf).join("VoidWire")
}

/// True when the process token is elevated.
pub fn is_elevated() -> bool {
    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
    use windows_sys::Win32::Security::{
        GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
    let mut token: HANDLE = std::ptr::null_mut();
    // SAFETY: GetCurrentProcess returns a pseudo handle; `token` is a valid out pointer.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return false;
    }
    let mut elev = TOKEN_ELEVATION { TokenIsElevated: 0 };
    let mut len = 0u32;
    // SAFETY: `elev` is a writable TOKEN_ELEVATION of the size we pass.
    let ok = unsafe {
        GetTokenInformation(
            token,
            TokenElevation,
            (&mut elev as *mut TOKEN_ELEVATION).cast(),
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut len,
        )
    };
    // SAFETY: `token` was opened above and is closed exactly once.
    unsafe { CloseHandle(token) };
    ok != 0 && elev.TokenIsElevated != 0
}

pub fn require_admin() -> anyhow::Result<()> {
    if !is_elevated() {
        anyhow::bail!("this command must run from an elevated (Administrator) prompt");
    }
    Ok(())
}

/// `wintun.dll` next to the source exe or in the Tauri resources dir.
fn find_wintun(src_exe: &Path) -> Option<PathBuf> {
    let dir = src_exe.parent()?;
    [
        dir.join("wintun.dll"),
        dir.join("resources").join("wintun.dll"),
        dir.join("resources").join("bin").join("wintun.dll"),
        dir.join("..").join("resources").join("wintun.dll"),
    ]
    .into_iter()
    .find(|p| p.is_file())
}

fn service_info(exe: PathBuf) -> ServiceInfo {
    ServiceInfo {
        name: OsString::from(SERVICE_NAME),
        display_name: OsString::from(DISPLAY_NAME),
        service_type: ServiceType::OWN_PROCESS,
        start_type: ServiceStartType::AutoStart,
        error_control: ServiceErrorControl::Normal,
        executable_path: exe,
        launch_arguments: vec![OsString::from("run")],
        dependencies: vec![],
        account_name: None,
        account_password: None,
    }
}

pub async fn install() -> anyhow::Result<()> {
    let src = std::env::current_exe()?;
    let dir = install_dir();
    let exe = dir.join("voidwired.exe");
    let wintun = find_wintun(&src)
        .context("wintun.dll not found next to voidwired.exe or in the app resources")?;
    let manager = ServiceManager::local_computer(
        None::<&str>,
        ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE,
    )?;
    let access = ServiceAccess::QUERY_STATUS
        | ServiceAccess::START
        | ServiceAccess::STOP
        | ServiceAccess::CHANGE_CONFIG;
    let existing = manager.open_service(SERVICE_NAME, access).ok();
    if let Some(s) = &existing {
        if s.query_status()?.current_state != ServiceState::Stopped {
            let _ = s.stop();
            for _ in 0..50 {
                if s.query_status()?.current_state == ServiceState::Stopped {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
        }
    }
    super::copy_binary(&src, &exe)?;
    let dll_dst = dir.join("wintun.dll");
    if wintun != dll_dst {
        std::fs::copy(&wintun, &dll_dst).context("copying wintun.dll")?;
    }
    super::prepare_state()?;
    let info = service_info(exe);
    let service = match existing {
        Some(s) => {
            s.change_config(&info)?;
            s
        }
        None => manager.create_service(&info, access)?,
    };
    let _ = service.set_description("VoidWire fail-closed VPN client service");
    service.update_failure_actions(ServiceFailureActions {
        reset_period: ServiceFailureResetPeriod::After(Duration::from_secs(86_400)),
        reboot_msg: None,
        command: None,
        actions: Some(vec![
            ServiceAction {
                action_type: ServiceActionType::Restart,
                delay: Duration::from_secs(2),
            };
            3
        ]),
    })?;
    service.set_failure_actions_on_non_crash_failures(true)?;
    service.start(&[] as &[&OsStr])?;
    Ok(())
}

pub async fn uninstall() -> anyhow::Result<()> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
    if let Ok(s) = manager.open_service(
        SERVICE_NAME,
        ServiceAccess::QUERY_STATUS | ServiceAccess::STOP | ServiceAccess::DELETE,
    ) {
        if s.query_status()?.current_state != ServiceState::Stopped {
            let _ = s.stop();
            for _ in 0..50 {
                if s.query_status()?.current_state == ServiceState::Stopped {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
        }
        s.delete()?;
    }
    let dir = install_dir();
    if dir.exists() {
        std::fs::remove_dir_all(&dir)?;
    }
    Ok(())
}

pub fn status() -> anyhow::Result<ServiceStatus> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
    match manager.open_service(SERVICE_NAME, ServiceAccess::QUERY_STATUS) {
        Ok(s) => Ok(ServiceStatus {
            installed: true,
            running: s.query_status()?.current_state == ServiceState::Running,
        }),
        Err(_) => Ok(ServiceStatus {
            installed: false,
            running: false,
        }),
    }
}

define_windows_service!(ffi_service_main, service_main);

fn service_main(_args: Vec<OsString>) {
    if let Err(e) = run_service() {
        tracing::error!(error = %e, "service terminated with error");
    }
}

fn run_service() -> anyhow::Result<()> {
    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    let tx = std::sync::Mutex::new(Some(tx));
    let handler = move |ev| match ev {
        ServiceControl::Stop | ServiceControl::Shutdown => {
            if let Some(t) = tx.lock().ok().and_then(|mut g| g.take()) {
                let _ = t.send(());
            }
            ServiceControlHandlerResult::NoError
        }
        ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
        _ => ServiceControlHandlerResult::NotImplemented,
    };
    let handle = service_control_handler::register(SERVICE_NAME, handler)?;
    let status = |state, accept| WinStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: state,
        controls_accepted: accept,
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: None,
    };
    handle.set_service_status(status(
        ServiceState::Running,
        ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
    ))?;
    let rt = tokio::runtime::Runtime::new()?;
    let events = crate::events::EventHub::new();
    crate::service::init_tracing(events.clone());
    let r = rt.block_on(super::run_daemon(events, async {
        let _ = rx.await;
    }));
    handle.set_service_status(status(ServiceState::Stopped, ServiceControlAccept::empty()))?;
    r
}

/// Run under the SCM dispatcher. Returns `Ok(false)` when the process was
/// not started by the SCM (console mode).
pub fn dispatch() -> anyhow::Result<bool> {
    match service_dispatcher::start(SERVICE_NAME, ffi_service_main) {
        Ok(()) => Ok(true),
        Err(windows_service::Error::Winapi(e)) if e.raw_os_error() == Some(NOT_A_SERVICE) => {
            Ok(false)
        }
        Err(e) => Err(e.into()),
    }
}
