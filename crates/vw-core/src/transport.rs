//! Cross-crate I/O traits: datagram transports, chaff sources and TUN devices.

use std::net::SocketAddr;

use async_trait::async_trait;

use crate::config::TransportKind;
use crate::error::Result;

/// A datagram carrier underneath the WireGuard engine.
///
/// Implementations must preserve datagram boundaries: one `send` corresponds to
/// exactly one `recv` on the peer (or loss). They must be cancel-safe.
#[async_trait]
pub trait StealthTransport: Send + Sync {
    /// Send one WireGuard datagram.
    async fn send(&self, datagram: &[u8]) -> Result<()>;
    /// Receive one WireGuard datagram into `buf`, returning its length.
    async fn recv(&self, buf: &mut [u8]) -> Result<usize>;
    fn kind(&self) -> TransportKind;
    /// Bytes of overhead added per datagram on the wire.
    fn overhead(&self) -> u16 {
        self.kind().overhead()
    }
    /// The remote address actually used on the wire (for firewall pinning).
    fn remote_addr(&self) -> SocketAddr;
    /// Hook invoked by the WG engine right before it emits a handshake
    /// initiation (AmneziaWG sends its junk burst here).
    async fn before_handshake(&self) -> Result<()> {
        Ok(())
    }
    /// Re-bind after a network change (QUIC migration, UDP rebind).
    async fn rebind(&self) -> Result<()> {
        Ok(())
    }
    async fn close(&self) -> Result<()> {
        Ok(())
    }
}

/// Produces encrypted chaff datagrams for DAITA.
pub trait ChaffSource: Send + Sync {
    /// Return an encrypted dummy datagram whose plaintext is `size` bytes, or
    /// `None` when no session is established.
    fn make_chaff(&self, size: usize) -> Option<Vec<u8>>;
}

/// An IP packet device (OS TUN or an in-memory virtual channel).
#[async_trait]
pub trait TunDevice: Send + Sync {
    async fn read_packet(&self, buf: &mut [u8]) -> Result<usize>;
    async fn write_packet(&self, packet: &[u8]) -> Result<()>;
    fn mtu(&self) -> u16;
    /// OS interface name (e.g. `utun7`, `vw0`), or a virtual label.
    fn name(&self) -> String;
}
