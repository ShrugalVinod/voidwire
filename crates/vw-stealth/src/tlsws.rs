//! TLS 1.3 + WebSocket over TCP 443, one binary frame per datagram.
//!
//! The client sends a browser-like HTTP/1.1 Upgrade (Chrome header order and
//! casing) to the secret path `/<Endpoint.path>`. The server terminates TLS,
//! reads the request head itself and only upgrades an exact match; any other
//! request (wrong path, plain GET, other methods) gets a static decoy website
//! with nginx-like headers and the connection is closed.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;
use futures_util::stream::{SplitSink, SplitStream};
use futures_util::{SinkExt, StreamExt};
use subtle::ConstantTimeEq;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, watch, Mutex};
use tokio::task::JoinHandle;
use tokio_rustls::{TlsAcceptor, TlsConnector};
use tokio_tungstenite::tungstenite::handshake::client::generate_key;
use tokio_tungstenite::tungstenite::handshake::derive_accept_key;
use tokio_tungstenite::tungstenite::protocol::{Role, WebSocketConfig};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::WebSocketStream;
use tracing::debug;
use vw_core::config::{Endpoint, TransportKind};
use vw_core::consts::DEFAULT_TLS_PORT;
use vw_core::transport::StealthTransport;
use vw_core::{redact, Result, VwError};

use crate::http1::{http_date_now, http_date_unix, parse_head, read_head, Head};
use crate::sockopt::tcp_socket;
use crate::tls::{client_config, server_config, server_name};
use crate::{closed, terr, with_timeout, ConnectOptions, PeerHandle, ServerTransport};

/// Chrome stable major version used in the User-Agent (bump with releases).
pub const CHROME_MAJOR: u32 = 148;
/// Largest WebSocket message accepted (a WireGuard datagram is ≤ 64 KiB).
const MAX_MESSAGE: usize = 64 * 1024;
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

const DECOY_INDEX: &str = include_str!("../assets/decoy/index.html");
const DECOY_CSS: &str = include_str!("../assets/decoy/style.css");
const DECOY_404: &str = include_str!("../assets/decoy/404.html");
/// Fixed "deploy time" of the decoy site (Last-Modified / ETag).
const DECOY_MTIME: u64 = 1_760_356_800;

fn ws_config() -> WebSocketConfig {
    WebSocketConfig::default()
        .max_message_size(Some(MAX_MESSAGE))
        .max_frame_size(Some(MAX_MESSAGE))
}

fn user_agent() -> String {
    let platform = if cfg!(target_os = "windows") {
        "Windows NT 10.0; Win64; x64"
    } else if cfg!(target_os = "linux") {
        "X11; Linux x86_64"
    } else {
        "Macintosh; Intel Mac OS X 10_15_7"
    };
    format!(
        "Mozilla/5.0 ({platform}) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{CHROME_MAJOR}.0.0.0 Safari/537.36"
    )
}

fn secret_path(token: Option<&str>) -> String {
    format!("/{}", token.unwrap_or("").trim_matches('/'))
}

/// The browser-like Upgrade request (Chrome's header order and casing).
fn upgrade_request(host: &str, path: &str, key: &str) -> String {
    format!(
        "GET {path} HTTP/1.1\r\n\
         Host: {host}\r\n\
         Connection: Upgrade\r\n\
         Pragma: no-cache\r\n\
         Cache-Control: no-cache\r\n\
         User-Agent: {ua}\r\n\
         Upgrade: websocket\r\n\
         Origin: https://{host}\r\n\
         Sec-WebSocket-Version: 13\r\n\
         Accept-Encoding: gzip, deflate, br, zstd\r\n\
         Accept-Language: en-US,en;q=0.9\r\n\
         Sec-WebSocket-Key: {key}\r\n\
         Sec-WebSocket-Extensions: permessage-deflate; client_max_window_bits\r\n\
         \r\n",
        ua = user_agent()
    )
}

type ClientWs = WebSocketStream<tokio_rustls::client::TlsStream<TcpStream>>;

struct WsConn {
    sink: Mutex<SplitSink<ClientWs, Message>>,
    stream: Mutex<SplitStream<ClientWs>>,
}

/// Client side of TLS-WebSocket.
pub struct TlsWsTransport {
    endpoint: Endpoint,
    remote: SocketAddr,
    opts: ConnectOptions,
    /// Current connection, `None` once closed; `rebind` swaps in a new one.
    current: watch::Sender<Option<Arc<WsConn>>>,
}

impl TlsWsTransport {
    pub async fn connect(
        endpoint: &Endpoint,
        remote: SocketAddr,
        opts: &ConnectOptions,
    ) -> Result<Self> {
        let conn = Self::establish(endpoint, remote, opts).await?;
        let (current, _) = watch::channel(Some(Arc::new(conn)));
        Ok(Self {
            endpoint: endpoint.clone(),
            remote,
            opts: opts.clone(),
            current,
        })
    }

    async fn establish(
        endpoint: &Endpoint,
        remote: SocketAddr,
        opts: &ConnectOptions,
    ) -> Result<WsConn> {
        with_timeout(opts.connect_timeout, async {
            let tcp = tcp_socket(&remote, &opts.socket)?.connect(remote).await?;
            debug!(remote = %redact::sock(&remote), "tls-ws: tcp connected");
            let tls_cfg = client_config(endpoint.cert_sha256.as_deref(), &[b"h2", b"http/1.1"])?;
            let mut tls = TlsConnector::from(Arc::new(tls_cfg))
                .connect(server_name(endpoint)?, tcp)
                .await?;
            if tls.get_ref().1.alpn_protocol() == Some(b"h2") {
                return Err(VwError::Transport("TLS-WS server negotiated h2".into()));
            }

            let name = endpoint.sni.as_deref().unwrap_or(&endpoint.host);
            let host = if endpoint.port == DEFAULT_TLS_PORT {
                name.to_string()
            } else {
                format!("{name}:{}", endpoint.port)
            };
            let key = generate_key();
            let req = upgrade_request(&host, &secret_path(endpoint.path.as_deref()), &key);
            tls.write_all(req.as_bytes()).await?;
            tls.flush().await?;

            let (head, rest) = read_head(&mut tls).await?;
            let resp = parse_head(&head)
                .ok_or_else(|| VwError::Transport("malformed TLS-WS handshake response".into()))?;
            if resp.line.1 != "101" {
                return Err(VwError::Transport(format!(
                    "TLS-WS upgrade refused (HTTP {})",
                    resp.line.1
                )));
            }
            let accept_ok = resp
                .header("sec-websocket-accept")
                .is_some_and(|a| a == derive_accept_key(key.as_bytes()));
            if !accept_ok
                || !resp.header_has_token("upgrade", "websocket")
                || resp.header("sec-websocket-extensions").is_some()
            {
                return Err(VwError::Transport("invalid TLS-WS upgrade response".into()));
            }
            let ws =
                WebSocketStream::from_partially_read(tls, rest, Role::Client, Some(ws_config()))
                    .await;
            let (sink, stream) = ws.split();
            Ok(WsConn {
                sink: Mutex::new(sink),
                stream: Mutex::new(stream),
            })
        })
        .await
    }

    fn conn(&self) -> Result<Arc<WsConn>> {
        self.current.borrow().clone().ok_or_else(closed)
    }
}

#[async_trait]
impl StealthTransport for TlsWsTransport {
    async fn send(&self, datagram: &[u8]) -> Result<()> {
        let conn = self.conn()?;
        let mut sink = conn.sink.lock().await;
        sink.send(Message::Binary(Bytes::copy_from_slice(datagram)))
            .await
            .map_err(terr)
    }

    async fn recv(&self, buf: &mut [u8]) -> Result<usize> {
        let mut rx = self.current.subscribe();
        loop {
            let conn = rx.borrow_and_update().clone().ok_or_else(closed)?;
            let mut stream = tokio::select! {
                s = conn.stream.lock() => s,
                c = rx.changed() => {
                    c.map_err(|_| closed())?;
                    continue;
                }
            };
            loop {
                let msg = tokio::select! {
                    m = stream.next() => m,
                    c = rx.changed() => {
                        c.map_err(|_| closed())?;
                        break;
                    }
                };
                match msg {
                    Some(Ok(Message::Binary(d))) if d.len() <= buf.len() => {
                        buf[..d.len()].copy_from_slice(&d);
                        return Ok(d.len());
                    }
                    Some(Ok(Message::Close(_))) | None => return Err(closed()),
                    Some(Ok(_)) => continue,
                    Some(Err(e)) => return Err(terr(e)),
                }
            }
        }
    }

    fn kind(&self) -> TransportKind {
        TransportKind::TlsWebsocket
    }

    fn remote_addr(&self) -> SocketAddr {
        self.remote
    }

    /// TCP cannot migrate: re-establish TCP + TLS + WebSocket and swap it in.
    async fn rebind(&self) -> Result<()> {
        let old = self.conn()?;
        let new = Self::establish(&self.endpoint, self.remote, &self.opts).await?;
        self.current.send_replace(Some(Arc::new(new)));
        let _ = old.sink.lock().await.close().await;
        Ok(())
    }

    async fn close(&self) -> Result<()> {
        if let Some(old) = self.current.send_replace(None) {
            let _ = old.sink.lock().await.close().await;
        }
        Ok(())
    }
}

// ===================================================================== server

type ServerTls = tokio_rustls::server::TlsStream<TcpStream>;
type ServerSink = SplitSink<WebSocketStream<ServerTls>, Message>;

struct Shared {
    token: String,
    conns: StdMutex<HashMap<u64, Arc<Mutex<ServerSink>>>>,
    next_id: AtomicU64,
    tx: mpsc::Sender<(Bytes, PeerHandle)>,
}

/// Server side of TLS-WebSocket with a decoy website for everything else.
pub struct TlsWsListener {
    local: SocketAddr,
    shared: Arc<Shared>,
    rx: Mutex<mpsc::Receiver<(Bytes, PeerHandle)>>,
    accept_task: JoinHandle<()>,
}

impl TlsWsListener {
    /// Listen on `addr` with a node certificate; `token` is the secret path
    /// (`/<token>`) and must be non-empty.
    pub async fn bind(
        addr: SocketAddr,
        cert_der: &[u8],
        key_der: &[u8],
        token: &str,
    ) -> Result<Self> {
        let token = token.trim_matches('/').to_string();
        if token.is_empty() {
            return Err(VwError::Config(
                "TLS-WS listener requires a secret path token".into(),
            ));
        }
        let acceptor =
            TlsAcceptor::from(Arc::new(server_config(cert_der, key_der, &[b"http/1.1"])?));
        let listener = TcpListener::bind(addr).await?;
        let local = listener.local_addr()?;
        let (tx, rx) = mpsc::channel(4096);
        let shared = Arc::new(Shared {
            token,
            conns: StdMutex::new(HashMap::new()),
            next_id: AtomicU64::new(1),
            tx,
        });
        let sh = shared.clone();
        let accept_task = tokio::spawn(async move {
            loop {
                let (tcp, peer) = match listener.accept().await {
                    Ok(x) => x,
                    Err(e) => {
                        debug!("tls-ws: accept failed: {e}");
                        tokio::time::sleep(Duration::from_millis(50)).await;
                        continue;
                    }
                };
                let _ = tcp.set_nodelay(true);
                let acceptor = acceptor.clone();
                let sh = sh.clone();
                tokio::spawn(async move {
                    if let Err(e) = serve_connection(tcp, peer, acceptor, sh).await {
                        debug!(peer = %redact::sock(&peer), "tls-ws: connection ended: {e}");
                    }
                });
            }
        });
        Ok(Self {
            local,
            shared,
            rx: Mutex::new(rx),
            accept_task,
        })
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.local
    }

    /// Number of upgraded WebSocket tunnels.
    pub fn tunnel_count(&self) -> usize {
        self.shared.conns.lock().map(|c| c.len()).unwrap_or(0)
    }
}

impl Drop for TlsWsListener {
    fn drop(&mut self) {
        self.accept_task.abort();
    }
}

fn is_upgrade(req: &Head, token: &str) -> bool {
    let path_ok = req.line.1.strip_prefix('/').is_some_and(|p| {
        p.len() == token.len() && bool::from(p.as_bytes().ct_eq(token.as_bytes()))
    });
    req.line.0 == "GET"
        && req.line.2 == "HTTP/1.1"
        && path_ok
        && req.header_has_token("upgrade", "websocket")
        && req.header_has_token("connection", "upgrade")
        && req.header("sec-websocket-version") == Some("13")
        && req.header("sec-websocket-key").is_some()
}

async fn serve_connection(
    tcp: TcpStream,
    peer: SocketAddr,
    acceptor: TlsAcceptor,
    sh: Arc<Shared>,
) -> Result<()> {
    let (mut tls, head, rest) = with_timeout(HANDSHAKE_TIMEOUT, async {
        let mut tls = acceptor.accept(tcp).await?;
        let (head, rest) = read_head(&mut tls).await?;
        Ok((tls, head, rest))
    })
    .await?;
    let req = match parse_head(&head) {
        Some(r) if is_upgrade(&r, &sh.token) => r,
        parsed => return serve_decoy(&mut tls, parsed.as_ref()).await,
    };

    let key = req.header("sec-websocket-key").unwrap_or_default();
    let resp = format!(
        "HTTP/1.1 101 Switching Protocols\r\n\
         Server: nginx\r\n\
         Date: {}\r\n\
         Connection: upgrade\r\n\
         Upgrade: websocket\r\n\
         Sec-WebSocket-Accept: {}\r\n\r\n",
        http_date_now(),
        derive_accept_key(key.as_bytes())
    );
    tls.write_all(resp.as_bytes()).await?;
    tls.flush().await?;
    let ws = WebSocketStream::from_partially_read(tls, rest, Role::Server, Some(ws_config())).await;
    let (sink, mut stream) = ws.split();

    let id = sh.next_id.fetch_add(1, Ordering::Relaxed);
    let handle = PeerHandle::conn(TransportKind::TlsWebsocket, id, peer);
    if let Ok(mut c) = sh.conns.lock() {
        c.insert(id, Arc::new(Mutex::new(sink)));
    }
    debug!(peer = %redact::sock(&peer), "tls-ws: tunnel upgraded");
    while let Some(msg) = stream.next().await {
        match msg {
            Ok(Message::Binary(d)) => {
                if sh.tx.send((d, handle)).await.is_err() {
                    break;
                }
            }
            Ok(Message::Close(_)) | Err(_) => break,
            Ok(_) => continue,
        }
    }
    if let Ok(mut c) = sh.conns.lock() {
        c.remove(&id);
    }
    Ok(())
}

fn status_text(code: u16) -> &'static str {
    match code {
        200 => "OK",
        400 => "Bad Request",
        404 => "Not Found",
        405 => "Not Allowed",
        _ => "Error",
    }
}

fn nginx_error_page(code: u16) -> String {
    format!(
        "<html>\r\n<head><title>{code} {t}</title></head>\r\n<body>\r\n<center><h1>{code} {t}</h1></center>\r\n<hr><center>nginx</center>\r\n</body>\r\n</html>\r\n",
        t = status_text(code)
    )
}

/// Build the decoy response for a request (or `None` for an unparsable one).
fn decoy_response(req: Option<&Head>) -> Vec<u8> {
    let (code, ctype, body, cacheable): (u16, &str, std::borrow::Cow<'static, str>, bool) =
        match req {
            None => (400, "text/html", nginx_error_page(400).into(), false),
            Some(r) if r.line.0 != "GET" && r.line.0 != "HEAD" => {
                (405, "text/html", nginx_error_page(405).into(), false)
            }
            Some(r) => {
                let path = r.line.1.split(['?', '#']).next().unwrap_or("/");
                match path {
                    "/" | "/index.html" => {
                        (200, "text/html; charset=utf-8", DECOY_INDEX.into(), true)
                    }
                    "/style.css" => (200, "text/css", DECOY_CSS.into(), true),
                    _ => (404, "text/html", DECOY_404.into(), false),
                }
            }
        };
    let head_only = req.is_some_and(|r| r.line.0 == "HEAD");
    let mut out = format!(
        "HTTP/1.1 {code} {}\r\nServer: nginx\r\nDate: {}\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\n",
        status_text(code),
        http_date_now(),
        body.len()
    );
    if cacheable {
        out.push_str(&format!(
            "Last-Modified: {}\r\nETag: \"{:x}-{:x}\"\r\nAccept-Ranges: bytes\r\n",
            http_date_unix(DECOY_MTIME),
            DECOY_MTIME,
            body.len()
        ));
    }
    out.push_str("Connection: close\r\n\r\n");
    let mut bytes = out.into_bytes();
    if !head_only {
        bytes.extend_from_slice(body.as_bytes());
    }
    bytes
}

async fn serve_decoy<S: AsyncRead + AsyncWrite + Unpin>(
    tls: &mut S,
    req: Option<&Head>,
) -> Result<()> {
    tls.write_all(&decoy_response(req)).await?;
    tls.flush().await?;
    let _ = tls.shutdown().await;
    debug!("tls-ws: served decoy");
    Ok(())
}

#[async_trait]
impl ServerTransport for TlsWsListener {
    async fn recv_from(&self, buf: &mut [u8]) -> Result<(usize, PeerHandle)> {
        let mut rx = self.rx.lock().await;
        loop {
            let (d, peer) = rx.recv().await.ok_or_else(closed)?;
            if d.len() <= buf.len() {
                buf[..d.len()].copy_from_slice(&d);
                return Ok((d.len(), peer));
            }
        }
    }

    async fn send_to(&self, datagram: &[u8], peer: &PeerHandle) -> Result<()> {
        let sink = {
            let c = self
                .shared
                .conns
                .lock()
                .map_err(|_| VwError::Transport("connection table poisoned".into()))?;
            peer.conn_id()
                .and_then(|id| c.get(&id).cloned())
                .ok_or_else(|| VwError::Transport("unknown TLS-WS peer".into()))?
        };
        let mut sink = sink.lock().await;
        sink.send(Message::Binary(Bytes::copy_from_slice(datagram)))
            .await
            .map_err(terr)
    }

    fn kind(&self) -> TransportKind {
        TransportKind::TlsWebsocket
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tls::generate_node_cert;
    use tokio::io::AsyncReadExt;

    const SNI: &str = "cdn.voidwire.test";

    async fn server() -> (TlsWsListener, String) {
        let (cert, key, pin) = generate_node_cert(SNI).unwrap();
        let l = TlsWsListener::bind("127.0.0.1:0".parse().unwrap(), &cert, &key, "s3cret-path")
            .await
            .unwrap();
        (l, pin)
    }

    fn endpoint(port: u16, path: &str, pin: &str) -> Endpoint {
        Endpoint {
            transport: TransportKind::TlsWebsocket,
            host: "127.0.0.1".into(),
            port,
            sni: Some(SNI.into()),
            path: Some(path.into()),
            cert_sha256: Some(pin.into()),
        }
    }

    async fn raw_get(addr: SocketAddr, pin: &str, request: &str) -> String {
        let cfg = client_config(Some(pin), &[b"http/1.1"]).unwrap();
        let tcp = TcpStream::connect(addr).await.unwrap();
        let mut tls = TlsConnector::from(Arc::new(cfg))
            .connect(rustls::pki_types::ServerName::try_from(SNI).unwrap(), tcp)
            .await
            .unwrap();
        tls.write_all(request.as_bytes()).await.unwrap();
        let mut out = Vec::new();
        let _ = tls.read_to_end(&mut out).await;
        String::from_utf8(out).unwrap()
    }

    #[tokio::test]
    async fn loopback_round_trip_and_rebind() {
        let (srv, pin) = server().await;
        let addr = srv.local_addr();
        let ep = endpoint(addr.port(), "s3cret-path", &pin);
        let client = TlsWsTransport::connect(&ep, addr, &ConnectOptions::default())
            .await
            .unwrap();
        let mut buf = [0u8; 2048];
        for i in 0..10u8 {
            let msg = vec![i; 60 + i as usize];
            client.send(&msg).await.unwrap();
            let (n, peer) = tokio::time::timeout(Duration::from_secs(5), srv.recv_from(&mut buf))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(&buf[..n], &msg[..]);
            srv.send_to(&msg[..5], &peer).await.unwrap();
            let n = client.recv(&mut buf).await.unwrap();
            assert_eq!(&buf[..n], &msg[..5]);
        }

        client.rebind().await.unwrap();
        client.send(b"again").await.unwrap();
        let (n, peer) = tokio::time::timeout(Duration::from_secs(5), srv.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&buf[..n], b"again");
        srv.send_to(b"pong", &peer).await.unwrap();
        let n = tokio::time::timeout(Duration::from_secs(5), client.recv(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&buf[..n], b"pong");

        client.close().await.unwrap();
        assert!(client.send(b"x").await.is_err());
    }

    #[tokio::test]
    async fn decoy_on_root_and_wrong_path() {
        let (srv, pin) = server().await;
        let addr = srv.local_addr();

        let root = raw_get(
            addr,
            &pin,
            &format!("GET / HTTP/1.1\r\nHost: {SNI}\r\n\r\n"),
        )
        .await;
        assert!(root.starts_with("HTTP/1.1 200 OK\r\n"), "{root}");
        assert!(root.contains("\r\nServer: nginx\r\n"));
        assert!(root.contains("\r\nContent-Type: text/html; charset=utf-8\r\n"));
        assert!(root.contains(&format!("\r\nContent-Length: {}\r\n", DECOY_INDEX.len())));
        assert!(root.contains("\r\nDate: "));
        assert!(root.ends_with(DECOY_INDEX));

        let css = raw_get(addr, &pin, "GET /style.css HTTP/1.1\r\nHost: x\r\n\r\n").await;
        assert!(css.contains("Content-Type: text/css") && css.ends_with(DECOY_CSS));

        // A well-formed WebSocket upgrade on the wrong path is just a 404.
        let req = upgrade_request(SNI, "/not-the-path", &generate_key());
        let wrong = raw_get(addr, &pin, &req).await;
        assert!(wrong.starts_with("HTTP/1.1 404 Not Found\r\n"), "{wrong}");
        assert!(wrong.ends_with(DECOY_404));

        let post = raw_get(
            addr,
            &pin,
            "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\n\r\n",
        )
        .await;
        assert!(post.starts_with("HTTP/1.1 405 Not Allowed\r\n"));

        let head = raw_get(addr, &pin, "HEAD / HTTP/1.1\r\nHost: x\r\n\r\n").await;
        assert!(head.starts_with("HTTP/1.1 200 OK\r\n") && head.ends_with("\r\n\r\n"));
        assert_eq!(srv.tunnel_count(), 0);

        // The client transport reports the refusal.
        let ep = endpoint(addr.port(), "wrong", &pin);
        let err = TlsWsTransport::connect(&ep, addr, &ConnectOptions::default())
            .await
            .err()
            .expect("wrong path must fail");
        assert!(err.to_string().contains("404"), "{err}");
    }

    #[tokio::test]
    async fn wrong_pin_fails() {
        let (srv, _pin) = server().await;
        let (_, _, other) = generate_node_cert("other.test").unwrap();
        let ep = endpoint(srv.local_addr().port(), "s3cret-path", &other);
        assert!(
            TlsWsTransport::connect(&ep, srv.local_addr(), &ConnectOptions::default())
                .await
                .is_err()
        );
    }

    #[test]
    fn headers_look_like_chrome() {
        let r = upgrade_request("example.org", "/p", "dGhlIHNhbXBsZSBub25jZQ==");
        assert!(r.starts_with("GET /p HTTP/1.1\r\nHost: example.org\r\nConnection: Upgrade\r\n"));
        assert!(r.contains(&format!("Chrome/{CHROME_MAJOR}.0.0.0 Safari/537.36\r\n")));
        assert!(r.contains("Origin: https://example.org\r\n"));
        assert!(r.contains("Sec-WebSocket-Version: 13\r\n"));
        assert!(r.contains("Accept-Language: "));
        assert!(r.ends_with("\r\n\r\n"));
    }
}
