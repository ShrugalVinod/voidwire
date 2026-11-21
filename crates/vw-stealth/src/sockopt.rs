//! Outer-socket construction: firewall mark and physical-interface binding.
//!
//! The lockdown firewall only lets the daemon's own, marked / interface-bound
//! sockets reach the pinned endpoints, so every transport creates its outer
//! socket here.

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::num::NonZeroU32;

use socket2::{Domain, Protocol, Socket, Type};
use vw_core::Result;

/// How the outer (physical) socket of a transport is created.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SocketOptions {
    /// Set `SO_MARK = vw_core::consts::FW_MARK` (Linux only). If the process
    /// lacks `CAP_NET_ADMIN` the mark is skipped with a warning: the lockdown
    /// drops unmarked egress, so this can only cost connectivity, never leak.
    pub fw_mark: bool,
    /// Bind to this physical interface: `IP_BOUND_IF`/`IPV6_BOUND_IF` (macOS),
    /// `IP_UNICAST_IF`/`IPV6_UNICAST_IF` (Windows), `SO_BINDTOIFINDEX` (Linux).
    pub interface_index: Option<NonZeroU32>,
}

impl Default for SocketOptions {
    fn default() -> Self {
        Self {
            fw_mark: true,
            interface_index: None,
        }
    }
}

fn unspecified(remote: &SocketAddr) -> SocketAddr {
    match remote {
        SocketAddr::V4(_) => SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)),
        SocketAddr::V6(_) => SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0)),
    }
}

fn new_socket(
    remote: &SocketAddr,
    ty: Type,
    proto: Protocol,
    opts: &SocketOptions,
) -> Result<Socket> {
    let sock = Socket::new(Domain::for_address(*remote), ty, Some(proto))?;
    apply(&sock, remote.is_ipv6(), opts)?;
    sock.set_nonblocking(true)?;
    Ok(sock)
}

/// A non-blocking UDP socket bound to an ephemeral port, ready to reach `remote`.
pub(crate) fn udp_socket(remote: &SocketAddr, opts: &SocketOptions) -> Result<std::net::UdpSocket> {
    let sock = new_socket(remote, Type::DGRAM, Protocol::UDP, opts)?;
    sock.bind(&unspecified(remote).into())?;
    Ok(sock.into())
}

/// A tokio TCP socket with the mark / interface binding applied (not yet connected).
pub(crate) fn tcp_socket(
    remote: &SocketAddr,
    opts: &SocketOptions,
) -> Result<tokio::net::TcpSocket> {
    let sock = new_socket(remote, Type::STREAM, Protocol::TCP, opts)?;
    sock.set_tcp_nodelay(true)?;
    let std_stream: std::net::TcpStream = sock.into();
    Ok(tokio::net::TcpSocket::from_std_stream(std_stream))
}

fn apply(sock: &Socket, ipv6: bool, opts: &SocketOptions) -> Result<()> {
    if opts.fw_mark {
        set_mark(sock)?;
    }
    if let Some(idx) = opts.interface_index {
        bind_interface(sock, ipv6, idx)?;
    }
    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn set_mark(sock: &Socket) -> Result<()> {
    match sock.set_mark(vw_core::consts::FW_MARK) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            tracing::warn!("cannot set firewall mark on transport socket (needs CAP_NET_ADMIN)");
            Ok(())
        }
        Err(e) => Err(e.into()),
    }
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn set_mark(_sock: &Socket) -> Result<()> {
    // Socket marks are a Linux concept; pf / WFP pin by interface and app id.
    Ok(())
}

#[cfg(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "linux",
    target_os = "android"
))]
fn bind_interface(sock: &Socket, ipv6: bool, idx: NonZeroU32) -> Result<()> {
    if ipv6 {
        sock.bind_device_by_index_v6(Some(idx))?;
    } else {
        sock.bind_device_by_index_v4(Some(idx))?;
    }
    Ok(())
}

#[cfg(windows)]
#[allow(unsafe_code)]
fn bind_interface(sock: &Socket, ipv6: bool, idx: NonZeroU32) -> Result<()> {
    use std::os::windows::io::AsRawSocket;
    use windows_sys::Win32::Networking::WinSock::{
        setsockopt, WSAGetLastError, IPPROTO_IP, IPPROTO_IPV6, IPV6_UNICAST_IF, IP_UNICAST_IF,
    };

    // IP_UNICAST_IF takes the index in network byte order, IPV6_UNICAST_IF in
    // host byte order (see the Winsock IPPROTO_IP / IPPROTO_IPV6 docs).
    let (level, name, value) = if ipv6 {
        (IPPROTO_IPV6, IPV6_UNICAST_IF, idx.get())
    } else {
        (IPPROTO_IP, IP_UNICAST_IF, idx.get().to_be())
    };
    let raw = sock.as_raw_socket() as usize;
    // SAFETY: `raw` is a valid, open socket handle owned by `sock` for the
    // duration of the call; `optval` points to a live 4-byte u32 and `optlen`
    // is exactly its size, as both options require a DWORD.
    let rc = unsafe {
        setsockopt(
            raw,
            level,
            name,
            (&value as *const u32).cast(),
            std::mem::size_of::<u32>() as i32,
        )
    };
    if rc != 0 {
        // SAFETY: WSAGetLastError has no preconditions.
        let code = unsafe { WSAGetLastError() };
        return Err(std::io::Error::from_raw_os_error(code).into());
    }
    Ok(())
}

#[cfg(not(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "linux",
    target_os = "android",
    windows
)))]
fn bind_interface(_sock: &Socket, _ipv6: bool, _idx: NonZeroU32) -> Result<()> {
    Err(vw_core::VwError::Unsupported(
        "interface-bound transport sockets",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn creates_sockets_for_both_families() {
        let opts = SocketOptions::default();
        let v4 = udp_socket(&"127.0.0.1:9".parse().unwrap(), &opts).unwrap();
        assert!(v4.local_addr().unwrap().is_ipv4());
        if let Ok(v6) = udp_socket(&"[::1]:9".parse().unwrap(), &opts) {
            assert!(v6.local_addr().unwrap().is_ipv6());
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn binds_loopback_interface() {
        // lo0 is always interface index 1 on macOS.
        let opts = SocketOptions {
            fw_mark: true,
            interface_index: NonZeroU32::new(1),
        };
        udp_socket(&"127.0.0.1:9".parse().unwrap(), &opts).unwrap();
    }
}
