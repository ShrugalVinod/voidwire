//! VWIPC server (ARCHITECTURE.md §5): Unix socket / Windows named pipe,
//! token handshake, request dispatch and the `Subscribe` event stream.

use std::sync::Arc;

use tokio::io::{AsyncRead, AsyncWrite};
use vw_core::ipc::{read_frame, server_handshake, write_frame, Request, Response};
use vw_core::secret::Key32;
use vw_core::{Result, VwError};

use crate::controller::Controller;

fn err(e: VwError) -> Response {
    Response::Error {
        message: vw_firewall::scrub_addresses(&e.to_string()),
    }
}

fn ok(r: Result<()>) -> Response {
    match r {
        Ok(()) => Response::Ok,
        Err(e) => err(e),
    }
}

/// Execute one request.
pub async fn handle(c: &Arc<Controller>, req: Request) -> Response {
    match req {
        Request::Status => Response::Status(Box::new(c.status().await)),
        Request::Up {
            profile,
            country,
            transport,
            gateway,
        } => ok(c.up(profile, country, transport, gateway).await),
        Request::ImportWireGuard {
            name,
            config,
            country,
        } => ok(c.import_wireguard(&name, &config, country.as_deref()).await),
        Request::Down { keep_lockdown } => ok(c.down(keep_lockdown).await),
        Request::Disarm => ok(c.disarm().await),
        Request::Panic => ok(c.panic().await),
        Request::Audit => match c.audit().await {
            Ok(r) => Response::Audit(r),
            Err(e) => err(e),
        },
        Request::Optimize => match c.optimize().await {
            Ok(d) => Response::Optimized(Box::new(d)),
            Err(e) => err(e),
        },
        Request::GetSettings => Response::Settings(Box::new(c.get_settings().await)),
        Request::SetSettings(s) => ok(c.set_settings(*s).await),
        Request::ListNodes => Response::Nodes(c.list_nodes().await),
        Request::ImportNode { uri } => ok(c.import_node(&uri).await),
        Request::RemoveNode { name } => ok(c.remove_node(&name).await),
        Request::RedeemInvite { uri } => ok(c.redeem_invite(&uri).await),
        Request::RegisterWarp => ok(c.register_warp().await),
        Request::Telemetry => Response::Telemetry(c.counters.snapshot()),
        Request::ExecPrepare => match c.exec_prepare().await {
            Ok(t) => Response::Exec(t),
            Err(e) => err(e),
        },
        Request::Subscribe => Response::Ok,
    }
}

/// Serve one authenticated connection until it closes.
pub async fn serve_connection<S>(c: Arc<Controller>, mut stream: S, token: &Key32) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    server_handshake(&mut stream, token, crate::DAEMON_VERSION).await?;
    loop {
        let req: Request = match read_frame(&mut stream).await {
            Ok(r) => r,
            Err(VwError::Io(e)) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(e) => return Err(e),
        };
        if req == Request::Subscribe {
            return stream_events(&c, &mut stream).await;
        }
        let resp = handle(&c, req).await;
        write_frame(&mut stream, &resp).await?;
    }
}

async fn stream_events<S>(c: &Arc<Controller>, stream: &mut S) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let mut rx = c.events.subscribe();
    write_frame(stream, &Response::Ok).await?;
    let initial = vw_core::ipc::DaemonEvent::Telemetry(c.counters.snapshot());
    write_frame(stream, &Response::Event(Box::new(initial))).await?;
    loop {
        match rx.recv().await {
            Ok(ev) => write_frame(stream, &Response::Event(Box::new(ev))).await?,
            Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
            Err(_) => return Ok(()),
        }
    }
}

/// Listen on the platform endpoint forever.
pub async fn listen(c: Arc<Controller>, endpoint: &str, token: Key32) -> Result<()> {
    platform::listen(c, endpoint, Arc::new(token)).await
}

#[cfg(unix)]
mod platform {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::path::Path;

    pub async fn listen(c: Arc<Controller>, endpoint: &str, token: Arc<Key32>) -> Result<()> {
        let path = Path::new(endpoint);
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o755))?;
        }
        match std::fs::remove_file(path) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
        let listener = tokio::net::UnixListener::bind(path)?;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o660))?;
        if nix::unistd::geteuid().is_root() {
            if let Ok(Some(g)) = nix::unistd::Group::from_name(crate::util::ADMIN_GROUP) {
                std::os::unix::fs::chown(path, Some(0), Some(g.gid.as_raw()))?;
            }
        }
        tracing::info!("IPC socket listening");
        loop {
            let (stream, _) = listener.accept().await?;
            if let Ok(cred) = stream.peer_cred() {
                tracing::debug!(uid = cred.uid(), "IPC client connected");
            }
            let (c, t) = (c.clone(), token.clone());
            tokio::spawn(async move {
                if let Err(e) = serve_connection(c, stream, &t).await {
                    tracing::debug!(error = %e, "IPC connection ended");
                }
            });
        }
    }
}

#[cfg(windows)]
mod platform {
    use super::*;
    use std::ffi::c_void;
    use tokio::net::windows::named_pipe::{NamedPipeServer, ServerOptions};
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW;
    use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;

    /// SYSTEM and Administrators full control, interactive users read/write.
    const PIPE_SDDL: &str = "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;IU)";
    const SDDL_REVISION_1: u32 = 1;

    fn create(endpoint: &str, first: bool) -> Result<NamedPipeServer> {
        let sddl: Vec<u16> = PIPE_SDDL.encode_utf16().chain(std::iter::once(0)).collect();
        let mut sd: *mut c_void = std::ptr::null_mut();
        // SAFETY: `sddl` is a NUL-terminated UTF-16 string; `sd` receives a
        // LocalAlloc'd descriptor that we free below.
        let ok = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                SDDL_REVISION_1,
                &mut sd,
                std::ptr::null_mut(),
            )
        };
        if ok == 0 {
            return Err(VwError::Permission(format!(
                "cannot build pipe security descriptor: {}",
                std::io::Error::last_os_error()
            )));
        }
        let mut sa = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: sd,
            bInheritHandle: 0,
        };
        let mut opts = ServerOptions::new();
        opts.first_pipe_instance(first).reject_remote_clients(true);
        // SAFETY: `sa` is a valid SECURITY_ATTRIBUTES whose descriptor stays
        // alive until after the call; the kernel copies it into the pipe.
        let r = unsafe {
            opts.create_with_security_attributes_raw(endpoint, &mut sa as *mut _ as *mut c_void)
        };
        // SAFETY: `sd` was allocated by ConvertStringSecurityDescriptor... with LocalAlloc.
        unsafe { LocalFree(sd) };
        Ok(r?)
    }

    pub async fn listen(c: Arc<Controller>, endpoint: &str, token: Arc<Key32>) -> Result<()> {
        let mut server = create(endpoint, true)?;
        tracing::info!("IPC pipe listening");
        loop {
            server.connect().await?;
            let connected = server;
            server = create(endpoint, false)?;
            let (c, t) = (c.clone(), token.clone());
            tokio::spawn(async move {
                if let Err(e) = serve_connection(c, connected, &t).await {
                    tracing::debug!(error = %e, "IPC connection ended");
                }
            });
        }
    }
}
