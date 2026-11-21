//! Plain WireGuard over UDP.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use async_trait::async_trait;
use tokio::net::UdpSocket;
use tokio::sync::watch;
use tracing::debug;
use vw_core::config::TransportKind;
use vw_core::transport::StealthTransport;
use vw_core::{redact, Result};

use crate::sockopt::{udp_socket, SocketOptions};
use crate::{closed, PeerHandle, ServerTransport};

/// ICMP errors surface as these on connected / Windows UDP sockets; they are
/// transient for a datagram transport and must not tear the tunnel down.
fn is_transient(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        io::ErrorKind::ConnectionRefused | io::ErrorKind::ConnectionReset
    )
}

/// Client transport: a connected UDP socket with `SO_MARK` / interface binding.
pub struct NativeUdpTransport {
    remote: SocketAddr,
    opts: SocketOptions,
    /// Current socket; `None` once closed. Receivers watch it so a `rebind`
    /// immediately moves pending `recv` calls to the new socket.
    current: watch::Sender<Option<Arc<UdpSocket>>>,
}

impl NativeUdpTransport {
    pub async fn connect(remote: SocketAddr, opts: SocketOptions) -> Result<Self> {
        let sock = Self::open(remote, &opts).await?;
        let (current, _) = watch::channel(Some(Arc::new(sock)));
        Ok(Self {
            remote,
            opts,
            current,
        })
    }

    async fn open(remote: SocketAddr, opts: &SocketOptions) -> Result<UdpSocket> {
        let sock = UdpSocket::from_std(udp_socket(&remote, opts)?)?;
        sock.connect(remote).await?;
        debug!(remote = %redact::sock(&remote), "native udp socket connected");
        Ok(sock)
    }

    /// Local address of the current socket.
    pub fn local_addr(&self) -> Result<SocketAddr> {
        let s = self.socket()?;
        Ok(s.local_addr()?)
    }

    fn socket(&self) -> Result<Arc<UdpSocket>> {
        self.current.borrow().clone().ok_or_else(closed)
    }
}

#[async_trait]
impl StealthTransport for NativeUdpTransport {
    async fn send(&self, datagram: &[u8]) -> Result<()> {
        let sock = self.socket()?;
        match sock.send(datagram).await {
            Ok(_) => Ok(()),
            Err(e) if is_transient(&e) => {
                debug!("native udp send hit transient icmp error");
                Ok(())
            }
            Err(e) => Err(e.into()),
        }
    }

    async fn recv(&self, buf: &mut [u8]) -> Result<usize> {
        let mut rx = self.current.subscribe();
        loop {
            let sock = rx.borrow_and_update().clone().ok_or_else(closed)?;
            tokio::select! {
                r = sock.recv(buf) => match r {
                    Ok(n) => return Ok(n),
                    Err(e) if is_transient(&e) => continue,
                    Err(e) => return Err(e.into()),
                },
                c = rx.changed() => {
                    if c.is_err() {
                        return Err(closed());
                    }
                }
            }
        }
    }

    fn kind(&self) -> TransportKind {
        TransportKind::NativeUdp
    }

    fn remote_addr(&self) -> SocketAddr {
        self.remote
    }

    async fn rebind(&self) -> Result<()> {
        if self.current.borrow().is_none() {
            return Err(closed());
        }
        let sock = Self::open(self.remote, &self.opts).await?;
        self.current.send_replace(Some(Arc::new(sock)));
        Ok(())
    }

    async fn close(&self) -> Result<()> {
        self.current.send_replace(None);
        Ok(())
    }
}

/// Server transport: one UDP socket shared by all peers.
pub struct UdpListener {
    socket: UdpSocket,
}

impl UdpListener {
    pub async fn bind(addr: SocketAddr) -> Result<Self> {
        Ok(Self {
            socket: UdpSocket::bind(addr).await?,
        })
    }

    pub fn from_socket(socket: UdpSocket) -> Self {
        Self { socket }
    }

    pub fn local_addr(&self) -> Result<SocketAddr> {
        Ok(self.socket.local_addr()?)
    }
}

#[async_trait]
impl ServerTransport for UdpListener {
    async fn recv_from(&self, buf: &mut [u8]) -> Result<(usize, PeerHandle)> {
        loop {
            match self.socket.recv_from(buf).await {
                Ok((n, from)) => return Ok((n, PeerHandle::udp(TransportKind::NativeUdp, from))),
                Err(e) if is_transient(&e) => continue,
                Err(e) => return Err(e.into()),
            }
        }
    }

    async fn send_to(&self, datagram: &[u8], peer: &PeerHandle) -> Result<()> {
        let addr = peer.udp_addr().ok_or_else(|| {
            vw_core::VwError::Transport("peer handle does not belong to a UDP listener".into())
        })?;
        match self.socket.send_to(datagram, addr).await {
            Ok(_) => Ok(()),
            Err(e) if is_transient(&e) => Ok(()),
            Err(e) => Err(e.into()),
        }
    }

    fn kind(&self) -> TransportKind {
        TransportKind::NativeUdp
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn opts() -> SocketOptions {
        SocketOptions::default()
    }

    #[tokio::test]
    async fn round_trip_and_rebind() {
        let server = UdpListener::bind("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let addr = server.local_addr().unwrap();
        let client = Arc::new(NativeUdpTransport::connect(addr, opts()).await.unwrap());
        assert_eq!(client.remote_addr(), addr);

        client.send(b"hello").await.unwrap();
        let mut buf = [0u8; 64];
        let (n, peer) = server.recv_from(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"hello");
        server.send_to(b"world", &peer).await.unwrap();
        let n = client.recv(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"world");

        // A receive pending across a rebind must follow the new socket.
        let before = client.local_addr().unwrap();
        let c2 = client.clone();
        let pending = tokio::spawn(async move {
            let mut b = [0u8; 64];
            let n = c2.recv(&mut b).await.unwrap();
            b[..n].to_vec()
        });
        tokio::task::yield_now().await;
        client.rebind().await.unwrap();
        assert_ne!(client.local_addr().unwrap(), before);
        client.send(b"roamed").await.unwrap();
        let (n, peer2) = server.recv_from(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"roamed");
        assert_ne!(peer, peer2);
        server.send_to(b"back", &peer2).await.unwrap();
        let got = tokio::time::timeout(Duration::from_secs(5), pending)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(got, b"back");

        client.close().await.unwrap();
        assert!(client.send(b"x").await.is_err());
        assert!(client.recv(&mut buf).await.is_err());
    }
}
