//! `vw-stealth` — VoidWire's pluggable datagram transports (ARCHITECTURE.md §9).
//!
//! Every transport carries opaque WireGuard datagrams and preserves datagram
//! boundaries. Each has a client side implementing
//! [`vw_core::transport::StealthTransport`] and a server side implementing
//! [`ServerTransport`] for `voidwire-node`, which multiplexes all of its
//! listeners into one WireGuard responder.
//!
//! | module | client | server |
//! |---|---|---|
//! | [`udp`] | [`NativeUdpTransport`] | [`UdpListener`] |
//! | [`amnezia`] | [`AmneziaWgTransport`] | [`AmneziaServer`] |
//! | [`masque`] | [`MasqueTransport`] | [`MasqueListener`] |
//! | [`tlsws`] | [`TlsWsTransport`] | [`TlsWsListener`] |
//! | [`daita`] | [`DaitaTransport`] (wraps any client transport) | — |
//!
//! [`connect`] builds the right client transport for a node [`Endpoint`].

// Only Windows needs `unsafe` (IP_UNICAST_IF has no safe wrapper); it is
// confined to one audited function in `sockopt`.
#![cfg_attr(not(windows), forbid(unsafe_code))]
#![cfg_attr(windows, deny(unsafe_code))]

pub mod amnezia;
pub mod daita;
mod h3;
mod http1;
pub mod masque;
mod peer;
mod resolve;
mod sockopt;
pub mod tls;
pub mod tlsws;
pub mod udp;

use std::net::SocketAddr;
use std::time::Duration;

use async_trait::async_trait;
use vw_core::config::{AmneziaParams, Endpoint, TransportKind};
use vw_core::transport::StealthTransport;
use vw_core::{Result, VwError};

pub use amnezia::{AmneziaCodec, AmneziaServer, AmneziaWgTransport};
pub use daita::{DaitaTransport, CHAFF_FLOOR_BYTES_PER_SEC};
pub use masque::{MasqueListener, MasqueTransport};
pub use peer::PeerHandle;
pub use resolve::resolve_endpoint;
pub use sockopt::SocketOptions;
pub use tls::generate_node_cert;
pub use tlsws::{TlsWsListener, TlsWsTransport};
pub use udp::{NativeUdpTransport, UdpListener};

/// Server half of a transport, used by `voidwire-node`.
///
/// `recv_from` must be cancel-safe. Datagrams for a [`PeerHandle`] whose
/// connection has gone away fail with [`VwError::Transport`].
#[async_trait]
pub trait ServerTransport: Send + Sync {
    /// Receive one WireGuard datagram and the peer it came from.
    async fn recv_from(&self, buf: &mut [u8]) -> Result<(usize, PeerHandle)>;
    /// Send one WireGuard datagram to a peer previously seen by `recv_from`.
    async fn send_to(&self, datagram: &[u8], peer: &PeerHandle) -> Result<()>;
    fn kind(&self) -> TransportKind;
}

/// Options for [`connect`].
#[derive(Debug, Clone)]
pub struct ConnectOptions {
    /// Required for [`TransportKind::AmneziaWg`] endpoints.
    pub amnezia: Option<AmneziaParams>,
    /// Firewall mark / physical interface binding for the outer socket.
    pub socket: SocketOptions,
    /// Pre-resolved address of the endpoint (from the daemon's bootstrap
    /// resolver while the firewall pins it). When `None`, literal IPs are used
    /// as-is and host names are resolved with the system resolver.
    pub resolved: Option<SocketAddr>,
    /// CONNECT-UDP target `{host}/{port}` for MASQUE. `None` targets the node
    /// itself (`Endpoint.host`, [`vw_core::consts::DEFAULT_NODE_UDP_PORT`]),
    /// which is what `voidwire-node` expects.
    pub masque_target: Option<(String, u16)>,
    /// Upper bound on TCP/QUIC/TLS/HTTP set-up.
    pub connect_timeout: Duration,
}

impl Default for ConnectOptions {
    fn default() -> Self {
        Self {
            amnezia: None,
            socket: SocketOptions::default(),
            resolved: None,
            masque_target: None,
            connect_timeout: Duration::from_secs(10),
        }
    }
}

/// Open the client transport described by `endpoint`.
///
/// DAITA is applied by the caller once the WireGuard engine (the
/// [`vw_core::transport::ChaffSource`]) exists: wrap the result with
/// `DaitaTransport::new(Arc::from(boxed), ..)`.
pub async fn connect(
    endpoint: &Endpoint,
    opts: &ConnectOptions,
) -> Result<Box<dyn StealthTransport>> {
    let remote = resolve_endpoint(endpoint, opts.resolved).await?;
    match endpoint.transport {
        TransportKind::NativeUdp => Ok(Box::new(
            NativeUdpTransport::connect(remote, opts.socket.clone()).await?,
        )),
        TransportKind::AmneziaWg => {
            let params = opts.amnezia.ok_or_else(|| {
                VwError::Config("AmneziaWG endpoint requires obfuscation parameters".into())
            })?;
            let inner = NativeUdpTransport::connect(remote, opts.socket.clone()).await?;
            Ok(Box::new(AmneziaWgTransport::new(inner, params)?))
        }
        TransportKind::MasqueQuic => Ok(Box::new(
            MasqueTransport::connect(endpoint, remote, opts).await?,
        )),
        TransportKind::TlsWebsocket => Ok(Box::new(
            TlsWsTransport::connect(endpoint, remote, opts).await?,
        )),
    }
}

/// Map any displayable error into a transport error.
pub(crate) fn terr(e: impl std::fmt::Display) -> VwError {
    VwError::Transport(e.to_string())
}

pub(crate) fn closed() -> VwError {
    VwError::Transport("transport closed".into())
}

/// Run `fut` with a deadline, mapping expiry to [`VwError::Timeout`].
pub(crate) async fn with_timeout<T>(
    d: Duration,
    fut: impl std::future::Future<Output = Result<T>>,
) -> Result<T> {
    tokio::time::timeout(d, fut)
        .await
        .map_err(|_| VwError::Timeout)?
}

#[cfg(test)]
mod tests {
    use super::*;
    use vw_core::config::AmneziaParams;

    fn ep(kind: TransportKind, port: u16) -> Endpoint {
        Endpoint {
            transport: kind,
            host: "127.0.0.1".into(),
            port,
            sni: None,
            path: None,
            cert_sha256: None,
        }
    }

    #[tokio::test]
    async fn factory_picks_transport() {
        let srv = UdpListener::bind("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let port = srv.local_addr().unwrap().port();

        let t = connect(
            &ep(TransportKind::NativeUdp, port),
            &ConnectOptions::default(),
        )
        .await
        .unwrap();
        assert_eq!(t.kind(), TransportKind::NativeUdp);
        assert_eq!(t.remote_addr().port(), port);

        let err = connect(
            &ep(TransportKind::AmneziaWg, port),
            &ConnectOptions::default(),
        )
        .await;
        assert!(matches!(err, Err(VwError::Config(_))));

        let opts = ConnectOptions {
            amnezia: Some(AmneziaParams::random()),
            ..ConnectOptions::default()
        };
        let t = connect(&ep(TransportKind::AmneziaWg, port), &opts)
            .await
            .unwrap();
        assert_eq!(t.kind(), TransportKind::AmneziaWg);
        t.before_handshake().await.unwrap();
        let mut buf = [0u8; 2048];
        let (n, _) = srv.recv_from(&mut buf).await.unwrap();
        let p = opts.amnezia.unwrap();
        assert!((p.jmin as usize..=p.jmax as usize).contains(&n));
    }
}
