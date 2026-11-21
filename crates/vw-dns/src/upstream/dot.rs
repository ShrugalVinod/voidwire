//! DNS over TLS (RFC 7858): TCP 853, 2-byte length framing, connection
//! reuse with transparent reconnect.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use rustls::pki_types::ServerName;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio_rustls::client::TlsStream;
use tokio_rustls::TlsConnector;

use super::{check_response, Upstream, UpstreamOptions};
use crate::error::{DnsError, Result};

const NAME: &str = "dot";
/// Idle connections kept for reuse.
const POOL_SIZE: usize = 4;
/// Connections idle longer than this are not reused (servers close them).
const MAX_IDLE: Duration = Duration::from_secs(20);

type Conn = TlsStream<TcpStream>;

/// RFC 7858 client with a small pool of persistent TLS connections.
pub struct DotUpstream {
    addr: SocketAddr,
    server_name: ServerName<'static>,
    connector: TlsConnector,
    timeout: Duration,
    pool: Mutex<Vec<(Conn, tokio::time::Instant)>>,
}

impl std::fmt::Debug for DotUpstream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DotUpstream")
            .field("addr", &vw_core::redact::sock(&self.addr))
            .finish()
    }
}

impl DotUpstream {
    /// Production client (Mozilla roots). `host` is the certificate name.
    pub fn new(host: &str, addr: SocketAddr) -> Result<Self> {
        Self::with_options(host, addr, &super::UpstreamOptions::production()?)
    }

    pub fn with_options(host: &str, addr: SocketAddr, opts: &UpstreamOptions) -> Result<Self> {
        let server_name = ServerName::try_from(host.to_string())
            .map_err(|_| DnsError::Config("invalid DoT server name".into()))?;
        let cfg = opts.trust.client_config(&[b"dot"])?;
        Ok(Self {
            addr,
            server_name,
            connector: TlsConnector::from(Arc::new(cfg)),
            timeout: opts.timeout,
            pool: Mutex::new(Vec::new()),
        })
    }

    async fn connect(&self) -> Result<Conn> {
        let tcp = TcpStream::connect(self.addr).await?;
        tcp.set_nodelay(true)?;
        self.connector
            .connect(self.server_name.clone(), tcp)
            .await
            .map_err(|e| DnsError::upstream(NAME, e))
    }

    async fn take_pooled(&self) -> Option<Conn> {
        let mut pool = self.pool.lock().await;
        while let Some((c, at)) = pool.pop() {
            if at.elapsed() < MAX_IDLE {
                return Some(c);
            }
        }
        None
    }

    async fn give_back(&self, c: Conn) {
        let mut pool = self.pool.lock().await;
        if pool.len() < POOL_SIZE {
            pool.push((c, tokio::time::Instant::now()));
        }
    }

    /// Number of idle pooled connections.
    pub async fn idle_connections(&self) -> usize {
        self.pool.lock().await.len()
    }
}

async fn exchange(conn: &mut Conn, wire: &[u8]) -> Result<Vec<u8>> {
    let len = u16::try_from(wire.len()).map_err(|_| DnsError::Malformed("query too large"))?;
    let mut frame = Vec::with_capacity(wire.len() + 2);
    frame.extend_from_slice(&len.to_be_bytes());
    frame.extend_from_slice(wire);
    conn.write_all(&frame).await?;
    conn.flush().await?;
    let mut lb = [0u8; 2];
    conn.read_exact(&mut lb).await?;
    let n = u16::from_be_bytes(lb) as usize;
    let mut buf = vec![0u8; n];
    conn.read_exact(&mut buf).await?;
    Ok(buf)
}

#[async_trait]
impl Upstream for DotUpstream {
    async fn query(&self, wire: &[u8]) -> Result<Vec<u8>> {
        if wire.len() < 12 {
            return Err(DnsError::Malformed("short query"));
        }
        // A reused connection may have been closed by the server: retry once
        // on a fresh connection before reporting failure.
        if let Some(mut c) = self.take_pooled().await {
            if let Ok(Ok(resp)) = tokio::time::timeout(self.timeout, exchange(&mut c, wire)).await {
                if check_response(NAME, wire, &resp).is_ok() {
                    self.give_back(c).await;
                    return Ok(resp);
                }
            }
            tracing::trace!("dot: pooled connection stale, reconnecting");
        }
        let fut = async {
            let mut c = self.connect().await?;
            let resp = exchange(&mut c, wire).await?;
            check_response(NAME, wire, &resp)?;
            Ok::<_, DnsError>((c, resp))
        };
        let (c, resp) = tokio::time::timeout(self.timeout, fut)
            .await
            .map_err(|_| DnsError::Timeout)??;
        self.give_back(c).await;
        Ok(resp)
    }

    fn name(&self) -> &'static str {
        NAME
    }
}
