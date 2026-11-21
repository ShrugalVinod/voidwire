//! Minimal HTTPS/1.1 JSON client with firewall-mark and address pinning support.
//!
//! The daemon uses this for control-plane calls (WARP registration, bootstrap
//! DNS) that must work while the lockdown is armed: sockets carry
//! `SO_MARK = FW_MARK` on Linux and connect only to addresses the caller has
//! pinned in the firewall.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::{Method, Request};
use hyper_util::rt::TokioIo;
use rustls::pki_types::ServerName;
use tokio::net::TcpSocket;
use tokio_rustls::TlsConnector;
use vw_core::{Result, VwError};

/// Parsed `https://host[:port]/path?query` URL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpsUrl {
    pub host: String,
    pub port: u16,
    pub path_and_query: String,
}

impl HttpsUrl {
    pub fn parse(url: &str) -> Result<Self> {
        let rest = url
            .strip_prefix("https://")
            .ok_or_else(|| VwError::Config("only https:// URLs are allowed".into()))?;
        let (authority, path) = match rest.find('/') {
            Some(i) => (&rest[..i], &rest[i..]),
            None => (rest, "/"),
        };
        if authority.is_empty() || authority.contains('@') {
            return Err(VwError::Config("invalid URL authority".into()));
        }
        let (host, port) = if let Some(stripped) = authority.strip_prefix('[') {
            let end = stripped
                .find(']')
                .ok_or_else(|| VwError::Config("unterminated IPv6 literal".into()))?;
            let host = &stripped[..end];
            let port = match &stripped[end + 1..] {
                "" => 443,
                p => p
                    .strip_prefix(':')
                    .and_then(|p| p.parse().ok())
                    .ok_or_else(|| VwError::Config("invalid port".into()))?,
            };
            (host.to_string(), port)
        } else {
            match authority.rsplit_once(':') {
                Some((h, p)) => (
                    h.to_string(),
                    p.parse()
                        .map_err(|_| VwError::Config("invalid port".into()))?,
                ),
                None => (authority.to_string(), 443),
            }
        };
        Ok(Self {
            host,
            port,
            path_and_query: path.to_string(),
        })
    }
}

/// HTTPS client configuration.
#[derive(Clone)]
pub struct HttpsClient {
    tls: Arc<rustls::ClientConfig>,
    /// Firewall mark for outbound sockets (Linux only; ignored elsewhere).
    pub mark: Option<u32>,
    /// If set, connect only to these addresses instead of resolving the host.
    pub pinned: Option<Vec<SocketAddr>>,
    pub timeout: Duration,
    pub user_agent: String,
}

impl std::fmt::Debug for HttpsClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpsClient")
            .field("mark", &self.mark)
            .field("pinned", &self.pinned.as_ref().map(|p| p.len()))
            .field("timeout", &self.timeout)
            .finish()
    }
}

/// A decoded HTTP response.
#[derive(Debug, Clone)]
pub struct HttpResponse {
    pub status: u16,
    pub body: Vec<u8>,
}

impl HttpResponse {
    pub fn json(&self) -> Result<serde_json::Value> {
        Ok(serde_json::from_slice(&self.body)?)
    }
}

impl HttpsClient {
    /// Client trusting the Mozilla root store (webpki-roots).
    pub fn new() -> Result<Self> {
        let mut roots = rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        Self::with_roots(roots)
    }

    /// Client trusting exactly the given roots (used by tests and pinned servers).
    pub fn with_roots(roots: rustls::RootCertStore) -> Result<Self> {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut cfg = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|e| VwError::Config(format!("tls config: {e}")))?
            .with_root_certificates(roots)
            .with_no_client_auth();
        cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
        Ok(Self {
            tls: Arc::new(cfg),
            mark: None,
            pinned: None,
            timeout: Duration::from_secs(15),
            user_agent: format!("voidwire/{}", env!("CARGO_PKG_VERSION")),
        })
    }

    pub fn with_mark(mut self, mark: Option<u32>) -> Self {
        self.mark = mark;
        self
    }

    pub fn with_pinned(mut self, addrs: Vec<SocketAddr>) -> Self {
        self.pinned = Some(addrs);
        self
    }

    pub fn with_user_agent(mut self, ua: impl Into<String>) -> Self {
        self.user_agent = ua.into();
        self
    }

    /// Perform a request with an optional JSON body.
    pub async fn request(
        &self,
        method: Method,
        url: &str,
        headers: &[(&str, &str)],
        body: Option<&serde_json::Value>,
    ) -> Result<HttpResponse> {
        tokio::time::timeout(self.timeout, self.request_inner(method, url, headers, body))
            .await
            .map_err(|_| VwError::Timeout)?
    }

    async fn request_inner(
        &self,
        method: Method,
        url: &str,
        headers: &[(&str, &str)],
        body: Option<&serde_json::Value>,
    ) -> Result<HttpResponse> {
        let url = HttpsUrl::parse(url)?;
        let addrs: Vec<SocketAddr> = match &self.pinned {
            Some(p) => p.clone(),
            None => tokio::net::lookup_host((url.host.as_str(), url.port))
                .await?
                .collect(),
        };
        if addrs.is_empty() {
            return Err(VwError::Transport("no addresses for host".into()));
        }
        let mut last_err = None;
        for addr in addrs {
            match self.exchange(&url, addr, &method, headers, body).await {
                Ok(r) => return Ok(r),
                Err(e) => {
                    tracing::debug!(peer = %vw_core::redact::sock(&addr), "https attempt failed: {e}");
                    last_err = Some(e);
                }
            }
        }
        Err(last_err.unwrap_or_else(|| VwError::Transport("connect failed".into())))
    }

    async fn exchange(
        &self,
        url: &HttpsUrl,
        addr: SocketAddr,
        method: &Method,
        headers: &[(&str, &str)],
        body: Option<&serde_json::Value>,
    ) -> Result<HttpResponse> {
        let sock = if addr.is_ipv4() {
            TcpSocket::new_v4()?
        } else {
            TcpSocket::new_v6()?
        };
        apply_mark(&sock, self.mark)?;
        let tcp = sock.connect(addr).await?;
        tcp.set_nodelay(true)?;
        let server_name = match url.host.parse::<IpAddr>() {
            Ok(ip) => ServerName::IpAddress(ip.into()),
            Err(_) => ServerName::try_from(url.host.clone())
                .map_err(|_| VwError::Config("invalid TLS server name".into()))?,
        };
        let tls = TlsConnector::from(self.tls.clone())
            .connect(server_name, tcp)
            .await
            .map_err(|e| VwError::Transport(format!("tls: {e}")))?;
        let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tls))
            .await
            .map_err(|e| VwError::Transport(format!("http handshake: {e}")))?;
        tokio::spawn(async move {
            let _ = conn.await;
        });

        let payload = match body {
            Some(v) => serde_json::to_vec(v)?,
            None => Vec::new(),
        };
        let host_header = if url.port == 443 {
            url.host.clone()
        } else {
            format!("{}:{}", url.host, url.port)
        };
        let mut req = Request::builder()
            .method(method.clone())
            .uri(&url.path_and_query)
            .header("Host", host_header)
            .header("User-Agent", &self.user_agent)
            .header("Accept", "application/json")
            .header("Connection", "close");
        if body.is_some() {
            req = req.header("Content-Type", "application/json; charset=UTF-8");
        }
        for (k, v) in headers {
            req = req.header(*k, *v);
        }
        let req = req
            .body(Full::new(Bytes::from(payload)))
            .map_err(|e| VwError::Transport(format!("request: {e}")))?;
        let resp = sender
            .send_request(req)
            .await
            .map_err(|e| VwError::Transport(format!("http: {e}")))?;
        let status = resp.status().as_u16();
        let body = resp
            .into_body()
            .collect()
            .await
            .map_err(|e| VwError::Transport(format!("http body: {e}")))?
            .to_bytes();
        if body.len() > 4 << 20 {
            return Err(VwError::Transport("response too large".into()));
        }
        Ok(HttpResponse {
            status,
            body: body.to_vec(),
        })
    }
}

#[cfg(target_os = "linux")]
fn apply_mark(sock: &TcpSocket, mark: Option<u32>) -> Result<()> {
    if let Some(m) = mark {
        socket2::SockRef::from(sock).set_mark(m)?;
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn apply_mark(_sock: &TcpSocket, _mark: Option<u32>) -> Result<()> {
    // macOS pf pins by `user root`, Windows WFP by application ID.
    Ok(())
}

/// Resolve `host` via Cloudflare DoH JSON over pinned anycast addresses.
///
/// Used while the firewall is armed: the caller pins `BOOTSTRAP_DOH` first.
pub async fn bootstrap_resolve(host: &str, mark: Option<u32>) -> Result<Vec<IpAddr>> {
    let client = HttpsClient::new()?
        .with_mark(mark)
        .with_pinned(BOOTSTRAP_DOH.to_vec());
    let mut out = Vec::new();
    for qtype in ["A", "AAAA"] {
        let url = format!("https://cloudflare-dns.com/dns-query?name={host}&type={qtype}");
        let resp = client
            .request(
                Method::GET,
                &url,
                &[("Accept", "application/dns-json")],
                None,
            )
            .await?;
        if resp.status != 200 {
            continue;
        }
        let v = resp.json()?;
        if let Some(ans) = v.get("Answer").and_then(|a| a.as_array()) {
            for a in ans {
                if let Some(ip) = a
                    .get("data")
                    .and_then(|d| d.as_str())
                    .and_then(|d| d.parse::<IpAddr>().ok())
                {
                    out.push(ip);
                }
            }
        }
    }
    if out.is_empty() {
        return Err(VwError::Dns(
            "bootstrap resolution returned no addresses".into(),
        ));
    }
    Ok(out)
}

/// Cloudflare DoH anycast addresses used for bootstrap resolution.
pub const BOOTSTRAP_DOH: [SocketAddr; 2] = [
    SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::new(1, 1, 1, 1)), 443),
    SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::new(1, 0, 0, 1)), 443),
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_urls() {
        let u = HttpsUrl::parse("https://api.cloudflareclient.com/v0a2158/reg").unwrap();
        assert_eq!(u.host, "api.cloudflareclient.com");
        assert_eq!(u.port, 443);
        assert_eq!(u.path_and_query, "/v0a2158/reg");
        let u = HttpsUrl::parse("https://[::1]:8443").unwrap();
        assert_eq!(
            (u.host.as_str(), u.port, u.path_and_query.as_str()),
            ("::1", 8443, "/")
        );
        let u = HttpsUrl::parse("https://127.0.0.1:9/x?y=1").unwrap();
        assert_eq!(u.path_and_query, "/x?y=1");
        assert!(HttpsUrl::parse("http://example.com").is_err());
        assert!(HttpsUrl::parse("https://user@example.com/").is_err());
        assert!(HttpsUrl::parse("https://example.com:abc/").is_err());
    }
}
