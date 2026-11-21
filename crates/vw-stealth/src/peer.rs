//! Opaque, cheaply clonable peer identifiers for [`crate::ServerTransport`].

use std::fmt;
use std::hash::{Hash, Hasher};
use std::net::SocketAddr;

use vw_core::config::TransportKind;
use vw_core::redact;

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
enum PeerId {
    /// Connectionless peers are identified by their UDP source address.
    Addr(SocketAddr),
    /// Connection-oriented peers (QUIC tunnel stream, TLS-WS connection).
    Conn(u64),
}

/// Identifies the sender of a datagram on a server transport.
///
/// Equality and hashing use the transport kind and the connection identity
/// only, so a handle can key a map. `Debug` never prints the address.
#[derive(Clone, Copy)]
pub struct PeerHandle {
    kind: TransportKind,
    id: PeerId,
    remote: SocketAddr,
}

impl PeerHandle {
    pub(crate) fn udp(kind: TransportKind, addr: SocketAddr) -> Self {
        Self {
            kind,
            id: PeerId::Addr(addr),
            remote: addr,
        }
    }

    pub(crate) fn conn(kind: TransportKind, id: u64, remote: SocketAddr) -> Self {
        Self {
            kind,
            id: PeerId::Conn(id),
            remote,
        }
    }

    pub(crate) fn conn_id(&self) -> Option<u64> {
        match self.id {
            PeerId::Conn(id) => Some(id),
            PeerId::Addr(_) => None,
        }
    }

    pub(crate) fn udp_addr(&self) -> Option<SocketAddr> {
        match self.id {
            PeerId::Addr(a) => Some(a),
            PeerId::Conn(_) => None,
        }
    }

    /// The transport this peer arrived on.
    pub fn kind(&self) -> TransportKind {
        self.kind
    }

    /// The peer's current outer address (for rate limiting; never log it
    /// above `debug`, and only through `vw_core::redact`).
    pub fn remote_addr(&self) -> SocketAddr {
        self.remote
    }
}

impl PartialEq for PeerHandle {
    fn eq(&self, other: &Self) -> bool {
        self.kind == other.kind && self.id == other.id
    }
}
impl Eq for PeerHandle {}

impl Hash for PeerHandle {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.kind.hash(state);
        self.id.hash(state);
    }
}

impl fmt::Debug for PeerHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.id {
            PeerId::Addr(a) => write!(f, "PeerHandle({:?}, {})", self.kind, redact::sock(&a)),
            PeerId::Conn(id) => write!(
                f,
                "PeerHandle({:?}, conn#{id}, {})",
                self.kind,
                redact::sock(&self.remote)
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_redacts_and_eq_ignores_remote() {
        let a: SocketAddr = "203.0.113.7:4444".parse().unwrap();
        let b: SocketAddr = "198.51.100.9:5555".parse().unwrap();
        let p = PeerHandle::udp(TransportKind::NativeUdp, a);
        assert!(!format!("{p:?}").contains("203"));
        let c1 = PeerHandle::conn(TransportKind::MasqueQuic, 7, a);
        let c2 = PeerHandle::conn(TransportKind::MasqueQuic, 7, b);
        assert_eq!(c1, c2);
        assert_ne!(c1, PeerHandle::conn(TransportKind::TlsWebsocket, 7, a));
        assert_eq!(c1.conn_id(), Some(7));
        assert_eq!(p.udp_addr(), Some(a));
    }
}
