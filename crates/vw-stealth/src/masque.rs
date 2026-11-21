//! MASQUE: HTTP/3 CONNECT-UDP (RFC 9298) over QUIC v1 with datagrams
//! (RFC 9221 / RFC 9297), using quinn + rustls (TLS 1.3, ALPN `h3`).
//!
//! # Request
//! The client opens its H3 control stream (SETTINGS: QPACK table 0, blocked
//! streams 0, `SETTINGS_H3_DATAGRAM = 1`), waits for the server's SETTINGS
//! (which must carry `SETTINGS_ENABLE_CONNECT_PROTOCOL = 1` and
//! `SETTINGS_H3_DATAGRAM = 1`), then sends an extended CONNECT:
//!
//! ```text
//! :method = CONNECT   :protocol = connect-udp   :scheme = https
//! :authority = <sni>[:port]   capsule-protocol = ?1
//! :path = /<token>/.well-known/masque/udp/<target host>/<target port>/
//! ```
//!
//! `<token>` is the node's secret path token (`Endpoint.path`); it is a
//! prefix segment in front of the standard RFC 9298 default template so that
//! a node only answers clients that know it (everything else gets a 404,
//! like any HTTP/3 origin). Without a token the plain default template is
//! used, which is what third-party MASQUE proxies expect.
//!
//! # Datagrams
//! `quarter_stream_id varint · context_id varint (= 0) · WireGuard datagram`
//! in QUIC DATAGRAM frames. Datagrams for other streams or contexts are dropped.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;

use async_trait::async_trait;
use bytes::{BufMut, Bytes, BytesMut};
use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use quinn::{Connection, RecvStream, SendStream, VarInt};
use subtle::ConstantTimeEq;
use tokio::sync::{mpsc, Mutex};
use tokio::task::JoinHandle;
use tracing::debug;
use vw_core::config::{Endpoint, TransportKind};
use vw_core::consts::{DEFAULT_MASQUE_PORT, DEFAULT_NODE_UDP_PORT};
use vw_core::transport::StealthTransport;
use vw_core::{redact, Result, VwError};

use crate::h3::{self, Field};
use crate::sockopt::{udp_socket, SocketOptions};
use crate::tls::{client_config, server_config};
use crate::{closed, terr, with_timeout, ConnectOptions, PeerHandle, ServerTransport};

const ALPN_H3: &[u8] = b"h3";
const WELL_KNOWN: &str = ".well-known/masque/udp/";
const IDLE_TIMEOUT: Duration = Duration::from_secs(60);
const KEEPALIVE: Duration = Duration::from_secs(15);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

/// RFC 6570 simple-string expansion: percent-encode everything but unreserved.
fn uri_var(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

fn clean_token(t: Option<&str>) -> &str {
    t.unwrap_or("").trim_matches('/')
}

/// The CONNECT-UDP `:path` for a target.
pub fn connect_udp_path(token: Option<&str>, target_host: &str, target_port: u16) -> String {
    let token = clean_token(token);
    let host = uri_var(target_host.trim_start_matches('[').trim_end_matches(']'));
    if token.is_empty() {
        format!("/{WELL_KNOWN}{host}/{target_port}/")
    } else {
        format!("/{token}/{WELL_KNOWN}{host}/{target_port}/")
    }
}

/// Validate a CONNECT-UDP path against the configured token (constant time
/// in the token) and the RFC 9298 default template.
fn path_ok(path: &str, token: &str) -> bool {
    let rest = if token.is_empty() {
        path.strip_prefix('/')
    } else {
        let Some(p) = path.strip_prefix('/') else {
            return false;
        };
        let (seg, rest) = p.split_once('/').unwrap_or((p, ""));
        let eq = seg.len() == token.len() && bool::from(seg.as_bytes().ct_eq(token.as_bytes()));
        if !eq {
            return false;
        }
        Some(rest)
    };
    let Some(target) = rest.and_then(|r| r.strip_prefix(WELL_KNOWN)) else {
        return false;
    };
    let mut parts = target.split('/');
    match (parts.next(), parts.next(), parts.next(), parts.next()) {
        (Some(h), Some(p), Some(""), None) => !h.is_empty() && p.parse::<u16>().is_ok(),
        _ => false,
    }
}

fn datagram_prefix(quarter: u64) -> Vec<u8> {
    let mut p = Vec::with_capacity(9);
    h3::put_varint(quarter, &mut p);
    h3::put_varint(0, &mut p);
    p
}

/// Split a CONNECT-UDP datagram into `(quarter stream id, UDP payload)`;
/// `None` for non-zero context ids or malformed input.
fn split_datagram(d: &[u8]) -> Option<(u64, &[u8])> {
    let (q, a) = h3::get_varint(d)?;
    let (ctx, b) = h3::get_varint(&d[a..])?;
    (ctx == 0).then(|| (q, &d[a + b..]))
}

fn framed(prefix: &[u8], payload: &[u8]) -> Bytes {
    let mut b = BytesMut::with_capacity(prefix.len() + payload.len());
    b.put_slice(prefix);
    b.put_slice(payload);
    b.freeze()
}

fn transport_config(client: bool) -> quinn::TransportConfig {
    let mut t = quinn::TransportConfig::default();
    t.max_idle_timeout(Some(
        IDLE_TIMEOUT.try_into().expect("idle timeout fits a VarInt"),
    ));
    if client {
        t.keep_alive_interval(Some(KEEPALIVE));
    }
    t.datagram_receive_buffer_size(Some(2 * 1024 * 1024));
    t
}

async fn write_control_stream(conn: &Connection, server: bool) -> Result<SendStream> {
    let mut s = conn.open_uni().await.map_err(terr)?;
    let mut settings = vec![
        (h3::SETTINGS_QPACK_MAX_TABLE_CAPACITY, 0),
        (h3::SETTINGS_QPACK_BLOCKED_STREAMS, 0),
        (h3::SETTINGS_H3_DATAGRAM, 1),
    ];
    if server {
        settings.push((h3::SETTINGS_ENABLE_CONNECT_PROTOCOL, 1));
    }
    let mut buf = Vec::new();
    h3::put_varint(h3::STREAM_CONTROL, &mut buf);
    buf.extend(h3::settings_frame(&settings));
    s.write_all(&buf).await.map_err(terr)?;
    Ok(s)
}

/// Discard everything on a stream until it ends.
async fn drain(mut r: RecvStream) {
    let mut buf = [0u8; 2048];
    while let Ok(Some(_)) = r.read(&mut buf).await {}
}

/// Accept the peer's unidirectional streams; return the settings found on its
/// control stream, draining every other stream type.
async fn read_peer_settings(conn: &Connection) -> Result<Vec<(u64, u64)>> {
    loop {
        let mut r = conn.accept_uni().await.map_err(terr)?;
        let ty = h3::read_varint(&mut r).await.map_err(terr)?;
        if ty != h3::STREAM_CONTROL {
            tokio::spawn(drain(r));
            continue;
        }
        let settings = match h3::read_frame(&mut r).await.map_err(terr)? {
            Some((h3::FRAME_SETTINGS, p)) => h3::parse_settings(&p)
                .ok_or_else(|| VwError::Transport("malformed h3 SETTINGS".into()))?,
            _ => {
                return Err(VwError::Transport(
                    "h3 control stream must start with SETTINGS".into(),
                ))
            }
        };
        tokio::spawn(drain(r));
        return Ok(settings);
    }
}

async fn drain_uni_streams(conn: Connection) {
    while let Ok(r) = conn.accept_uni().await {
        tokio::spawn(drain(r));
    }
}

fn setting(settings: &[(u64, u64)], id: u64) -> Option<u64> {
    settings.iter().find(|(k, _)| *k == id).map(|(_, v)| *v)
}

// ===================================================================== client

/// Client side of MASQUE CONNECT-UDP.
pub struct MasqueTransport {
    endpoint: quinn::Endpoint,
    conn: Connection,
    quarter: u64,
    prefix: Vec<u8>,
    remote: SocketAddr,
    socket_opts: SocketOptions,
    /// Control and request streams must stay open for the tunnel's lifetime.
    _streams: Mutex<(SendStream, SendStream)>,
    tasks: Vec<JoinHandle<()>>,
}

impl MasqueTransport {
    /// Connect to `endpoint` at the already-resolved `remote` address.
    pub async fn connect(
        endpoint: &Endpoint,
        remote: SocketAddr,
        opts: &ConnectOptions,
    ) -> Result<Self> {
        with_timeout(
            opts.connect_timeout,
            Self::establish(endpoint, remote, opts),
        )
        .await
    }

    async fn establish(
        endpoint: &Endpoint,
        remote: SocketAddr,
        opts: &ConnectOptions,
    ) -> Result<Self> {
        let tls = client_config(endpoint.cert_sha256.as_deref(), &[ALPN_H3])?;
        let quic = QuicClientConfig::try_from(tls).map_err(terr)?;
        let mut cfg = quinn::ClientConfig::new(Arc::new(quic));
        cfg.transport_config(Arc::new(transport_config(true)));

        let runtime = quinn::default_runtime()
            .ok_or_else(|| VwError::Transport("no async runtime for QUIC".into()))?;
        let socket = udp_socket(&remote, &opts.socket)?;
        let qep = quinn::Endpoint::new(quinn::EndpointConfig::default(), None, socket, runtime)?;

        let sni = endpoint
            .sni
            .as_deref()
            .unwrap_or(&endpoint.host)
            .trim_start_matches('[')
            .trim_end_matches(']')
            .to_string();
        debug!(remote = %redact::sock(&remote), sni = %redact::name(&sni), "masque: quic connect");
        let conn = qep
            .connect_with(cfg, remote, &sni)
            .map_err(terr)?
            .await
            .map_err(terr)?;
        if conn.max_datagram_size().is_none() {
            return Err(VwError::Transport(
                "MASQUE server does not support QUIC datagrams".into(),
            ));
        }

        let control = write_control_stream(&conn, false).await?;
        let settings = read_peer_settings(&conn).await?;
        if setting(&settings, h3::SETTINGS_ENABLE_CONNECT_PROTOCOL) != Some(1)
            || setting(&settings, h3::SETTINGS_H3_DATAGRAM) != Some(1)
        {
            return Err(VwError::Transport(
                "MASQUE server lacks extended CONNECT or HTTP datagrams".into(),
            ));
        }
        let mut tasks = vec![tokio::spawn(drain_uni_streams(conn.clone()))];

        let (mut send, mut recv) = conn.open_bi().await.map_err(terr)?;
        let authority = if endpoint.port == DEFAULT_MASQUE_PORT {
            sni.clone()
        } else if sni.contains(':') {
            format!("[{sni}]:{}", endpoint.port)
        } else {
            format!("{sni}:{}", endpoint.port)
        };
        let (thost, tport) = opts
            .masque_target
            .clone()
            .unwrap_or_else(|| (endpoint.host.clone(), DEFAULT_NODE_UDP_PORT));
        let path = connect_udp_path(endpoint.path.as_deref(), &thost, tport);
        let block = h3::qpack_encode(&[
            (":method", "CONNECT"),
            (":protocol", "connect-udp"),
            (":scheme", "https"),
            (":authority", &authority),
            (":path", &path),
            ("capsule-protocol", "?1"),
        ]);
        send.write_all(&h3::frame(h3::FRAME_HEADERS, &block))
            .await
            .map_err(terr)?;

        loop {
            let hdr = h3::read_headers(&mut recv)
                .await
                .map_err(terr)?
                .ok_or_else(|| VwError::Transport("MASQUE request stream closed".into()))?;
            let fields = h3::qpack_decode(&hdr)
                .ok_or_else(|| VwError::Transport("undecodable MASQUE response".into()))?;
            let status: u16 = h3::field(&fields, ":status")
                .and_then(|s| s.parse().ok())
                .ok_or_else(|| VwError::Transport("MASQUE response without :status".into()))?;
            match status {
                100..=199 => continue,
                200..=299 => break,
                s => {
                    return Err(VwError::Transport(format!(
                        "MASQUE CONNECT rejected (HTTP {s})"
                    )))
                }
            }
        }

        let quarter = u64::from(send.id()) / 4;
        // When the server ends the tunnel stream, tear the connection down so
        // that pending receives fail instead of hanging.
        let c = conn.clone();
        tasks.push(tokio::spawn(async move {
            drain(recv).await;
            c.close(VarInt::from_u32(h3::H3_NO_ERROR), b"");
        }));

        Ok(Self {
            endpoint: qep,
            conn,
            quarter,
            prefix: datagram_prefix(quarter),
            remote,
            socket_opts: opts.socket.clone(),
            _streams: Mutex::new((control, send)),
            tasks,
        })
    }

    /// Largest WireGuard datagram that currently fits in one QUIC datagram.
    pub fn max_payload(&self) -> Option<usize> {
        self.conn
            .max_datagram_size()
            .map(|m| m.saturating_sub(self.prefix.len()))
    }

    pub fn local_addr(&self) -> Result<SocketAddr> {
        Ok(self.endpoint.local_addr()?)
    }
}

impl Drop for MasqueTransport {
    fn drop(&mut self) {
        for t in &self.tasks {
            t.abort();
        }
    }
}

#[async_trait]
impl StealthTransport for MasqueTransport {
    async fn send(&self, datagram: &[u8]) -> Result<()> {
        self.conn
            .send_datagram(framed(&self.prefix, datagram))
            .map_err(terr)
    }

    async fn recv(&self, buf: &mut [u8]) -> Result<usize> {
        loop {
            let d = self.conn.read_datagram().await.map_err(terr)?;
            match split_datagram(&d) {
                Some((q, payload)) if q == self.quarter && payload.len() <= buf.len() => {
                    buf[..payload.len()].copy_from_slice(payload);
                    return Ok(payload.len());
                }
                _ => continue,
            }
        }
    }

    fn kind(&self) -> TransportKind {
        TransportKind::MasqueQuic
    }

    fn remote_addr(&self) -> SocketAddr {
        self.remote
    }

    /// Move the QUIC connection to a fresh UDP socket (connection migration,
    /// e.g. Wi-Fi ↔ cellular); the tunnel and stream survive.
    async fn rebind(&self) -> Result<()> {
        if self.conn.close_reason().is_some() {
            return Err(closed());
        }
        let socket = udp_socket(&self.remote, &self.socket_opts)?;
        self.endpoint.rebind(socket)?;
        Ok(())
    }

    async fn close(&self) -> Result<()> {
        self.conn.close(VarInt::from_u32(h3::H3_NO_ERROR), b"");
        for t in &self.tasks {
            t.abort();
        }
        Ok(())
    }
}

// ===================================================================== server

struct Tunnel {
    conn: Connection,
    prefix: Vec<u8>,
}

struct Shared {
    token: String,
    tunnels: StdMutex<HashMap<u64, Tunnel>>,
    next_id: AtomicU64,
    tx: mpsc::Sender<(Bytes, PeerHandle)>,
}

/// Server side: a QUIC endpoint answering CONNECT-UDP on the secret path and
/// exposing tunnel datagrams as a [`ServerTransport`]
/// (`PeerHandle` = connection + request stream).
pub struct MasqueListener {
    endpoint: quinn::Endpoint,
    shared: Arc<Shared>,
    rx: Mutex<mpsc::Receiver<(Bytes, PeerHandle)>>,
    accept_task: JoinHandle<()>,
}

impl MasqueListener {
    /// Listen on `addr` with a node certificate (DER, PKCS#8 key). `token` is
    /// the secret first path segment (`None`/empty = plain RFC 9298 template).
    pub fn bind(
        addr: SocketAddr,
        cert_der: &[u8],
        key_der: &[u8],
        token: Option<&str>,
    ) -> Result<Self> {
        let tls = server_config(cert_der, key_der, &[ALPN_H3])?;
        let quic = QuicServerConfig::try_from(tls).map_err(terr)?;
        let mut cfg = quinn::ServerConfig::with_crypto(Arc::new(quic));
        cfg.transport_config(Arc::new(transport_config(false)));
        let endpoint = quinn::Endpoint::server(cfg, addr)?;

        let (tx, rx) = mpsc::channel(4096);
        let shared = Arc::new(Shared {
            token: clean_token(token).to_string(),
            tunnels: StdMutex::new(HashMap::new()),
            next_id: AtomicU64::new(1),
            tx,
        });
        let ep = endpoint.clone();
        let sh = shared.clone();
        let accept_task = tokio::spawn(async move {
            while let Some(incoming) = ep.accept().await {
                let sh = sh.clone();
                tokio::spawn(async move {
                    match incoming.await {
                        Ok(conn) => serve_connection(conn, sh).await,
                        Err(e) => debug!("masque: quic handshake failed: {e}"),
                    }
                });
            }
        });
        Ok(Self {
            endpoint,
            shared,
            rx: Mutex::new(rx),
            accept_task,
        })
    }

    pub fn local_addr(&self) -> Result<SocketAddr> {
        Ok(self.endpoint.local_addr()?)
    }

    /// Number of open CONNECT-UDP tunnels.
    pub fn tunnel_count(&self) -> usize {
        self.shared.tunnels.lock().map(|t| t.len()).unwrap_or(0)
    }
}

impl Drop for MasqueListener {
    fn drop(&mut self) {
        self.accept_task.abort();
        self.endpoint.close(VarInt::from_u32(h3::H3_NO_ERROR), b"");
    }
}

async fn serve_connection(conn: Connection, sh: Arc<Shared>) {
    let remote = conn.remote_address();
    debug!(peer = %redact::sock(&remote), "masque: connection accepted");
    let control = match write_control_stream(&conn, true).await {
        Ok(s) => s,
        Err(_) => return,
    };
    let uni = tokio::spawn(drain_uni_streams(conn.clone()));
    // quarter stream id -> peer, for this connection only.
    let local: Arc<StdMutex<HashMap<u64, PeerHandle>>> = Arc::default();

    let dgram = {
        let conn = conn.clone();
        let local = local.clone();
        let tx = sh.tx.clone();
        tokio::spawn(async move {
            while let Ok(d) = conn.read_datagram().await {
                let Some((q, payload)) = split_datagram(&d) else {
                    continue;
                };
                let peer = local.lock().ok().and_then(|m| m.get(&q).copied());
                if let Some(peer) = peer {
                    let off = d.len() - payload.len();
                    // Datagrams are lossy: drop rather than stall when full.
                    let _ = tx.try_send((d.slice(off..), peer));
                }
            }
        })
    };

    while let Ok((send, recv)) = conn.accept_bi().await {
        let conn = conn.clone();
        let sh = sh.clone();
        let local = local.clone();
        tokio::spawn(async move {
            serve_request(conn, send, recv, sh, local).await;
        });
    }

    dgram.abort();
    uni.abort();
    drop(control);
    if let Ok(mut t) = sh.tunnels.lock() {
        t.retain(|_, tun| tun.conn.stable_id() != conn.stable_id());
    }
}

fn respond(status: &str) -> Vec<u8> {
    let mut fields = vec![(":status", status)];
    if status == "200" {
        fields.push(("capsule-protocol", "?1"));
    } else {
        fields.push(("content-length", "0"));
    }
    h3::frame(h3::FRAME_HEADERS, &h3::qpack_encode(&fields))
}

fn is_connect_udp(fields: &[Field], token: &str) -> bool {
    h3::field(fields, ":method") == Some("CONNECT")
        && h3::field(fields, ":protocol") == Some("connect-udp")
        && h3::field(fields, ":scheme") == Some("https")
        && h3::field(fields, ":authority").is_some_and(|a| !a.is_empty())
        && h3::field(fields, ":path").is_some_and(|p| path_ok(p, token))
}

async fn serve_request(
    conn: Connection,
    mut send: SendStream,
    mut recv: RecvStream,
    sh: Arc<Shared>,
    local: Arc<StdMutex<HashMap<u64, PeerHandle>>>,
) {
    let hdr = match tokio::time::timeout(REQUEST_TIMEOUT, h3::read_headers(&mut recv)).await {
        Ok(Ok(Some(h))) => h,
        _ => {
            let _ = send.reset(VarInt::from_u32(h3::H3_GENERAL_PROTOCOL_ERROR));
            return;
        }
    };
    let ok = h3::qpack_decode(&hdr).is_some_and(|f| is_connect_udp(&f, &sh.token));
    if !ok {
        debug!("masque: rejected request (404)");
        let _ = send.write_all(&respond("404")).await;
        let _ = send.finish();
        let _ = send.stopped().await;
        return;
    }

    let quarter = u64::from(recv.id()) / 4;
    let id = sh.next_id.fetch_add(1, Ordering::Relaxed);
    let peer = PeerHandle::conn(TransportKind::MasqueQuic, id, conn.remote_address());
    if let Ok(mut t) = sh.tunnels.lock() {
        t.insert(
            id,
            Tunnel {
                conn: conn.clone(),
                prefix: datagram_prefix(quarter),
            },
        );
    }
    if let Ok(mut m) = local.lock() {
        m.insert(quarter, peer);
    }
    if send.write_all(&respond("200")).await.is_ok() {
        // Capsules (none defined for us) are ignored; the stream's end ends the tunnel.
        drain(recv).await;
    }
    if let Ok(mut m) = local.lock() {
        m.remove(&quarter);
    }
    if let Ok(mut t) = sh.tunnels.lock() {
        t.remove(&id);
    }
    let _ = send.finish();
    debug!("masque: tunnel closed");
}

#[async_trait]
impl ServerTransport for MasqueListener {
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
        let (conn, prefix) = {
            let t = self
                .shared
                .tunnels
                .lock()
                .map_err(|_| VwError::Transport("tunnel table poisoned".into()))?;
            let tun = peer
                .conn_id()
                .and_then(|id| t.get(&id))
                .ok_or_else(|| VwError::Transport("unknown MASQUE peer".into()))?;
            (tun.conn.clone(), tun.prefix.clone())
        };
        conn.send_datagram(framed(&prefix, datagram)).map_err(terr)
    }

    fn kind(&self) -> TransportKind {
        TransportKind::MasqueQuic
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tls::generate_node_cert;

    #[test]
    fn paths() {
        assert_eq!(
            connect_udp_path(Some("s3cr3t"), "192.0.2.6", 443),
            "/s3cr3t/.well-known/masque/udp/192.0.2.6/443/"
        );
        assert_eq!(
            connect_udp_path(None, "2001:db8::42", 51820),
            "/.well-known/masque/udp/2001%3Adb8%3A%3A42/51820/"
        );
        assert!(path_ok("/s3cr3t/.well-known/masque/udp/h/1/", "s3cr3t"));
        assert!(!path_ok("/s3cr3x/.well-known/masque/udp/h/1/", "s3cr3t"));
        assert!(!path_ok("/s3cr3t/.well-known/masque/udp/h/x/", "s3cr3t"));
        assert!(!path_ok("/s3cr3t/.well-known/masque/udp//1/", "s3cr3t"));
        assert!(!path_ok("/.well-known/masque/udp/h/1/", "s3cr3t"));
        assert!(path_ok("/.well-known/masque/udp/h/1/", ""));
        assert!(!path_ok("/", ""));
    }

    #[test]
    fn datagram_framing() {
        let f = framed(&datagram_prefix(1234), b"wg");
        assert_eq!(split_datagram(&f), Some((1234, &b"wg"[..])));
        let mut bad = Vec::new();
        h3::put_varint(0, &mut bad);
        h3::put_varint(2, &mut bad);
        assert_eq!(split_datagram(&bad), None);
    }

    fn endpoint(port: u16, token: &str, pin: &str) -> Endpoint {
        Endpoint {
            transport: TransportKind::MasqueQuic,
            host: "127.0.0.1".into(),
            port,
            sni: Some("node.voidwire.test".into()),
            path: Some(token.into()),
            cert_sha256: Some(pin.into()),
        }
    }

    async fn server(token: &str) -> (MasqueListener, SocketAddr, String) {
        let (cert, key, pin) = generate_node_cert("node.voidwire.test").unwrap();
        let l =
            MasqueListener::bind("127.0.0.1:0".parse().unwrap(), &cert, &key, Some(token)).unwrap();
        let addr = l.local_addr().unwrap();
        (l, addr, pin)
    }

    #[tokio::test]
    async fn loopback_round_trip() {
        let (srv, addr, pin) = server("tok3n").await;
        let ep = endpoint(addr.port(), "tok3n", &pin);
        let client = MasqueTransport::connect(&ep, addr, &ConnectOptions::default())
            .await
            .unwrap();
        assert_eq!(client.kind(), TransportKind::MasqueQuic);
        assert!(client.max_payload().unwrap() > 1000);

        let mut buf = [0u8; 2048];
        for i in 0..20u8 {
            let msg = vec![i; 100 + i as usize];
            client.send(&msg).await.unwrap();
            let (n, peer) = tokio::time::timeout(Duration::from_secs(5), srv.recv_from(&mut buf))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(&buf[..n], &msg[..]);
            assert_eq!(peer.kind(), TransportKind::MasqueQuic);
            srv.send_to(&msg[..10], &peer).await.unwrap();
            let n = tokio::time::timeout(Duration::from_secs(5), client.recv(&mut buf))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(&buf[..n], &msg[..10]);
        }
        assert_eq!(srv.tunnel_count(), 1);

        // Connection migration to a new local socket keeps the tunnel.
        let before = client.local_addr().unwrap();
        client.rebind().await.unwrap();
        assert_ne!(client.local_addr().unwrap(), before);
        client.send(b"after-rebind").await.unwrap();
        let (n, peer) = tokio::time::timeout(Duration::from_secs(5), srv.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&buf[..n], b"after-rebind");
        srv.send_to(b"ok", &peer).await.unwrap();
        let n = tokio::time::timeout(Duration::from_secs(5), client.recv(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&buf[..n], b"ok");

        client.close().await.unwrap();
        assert!(client.recv(&mut buf).await.is_err());
    }

    #[tokio::test]
    async fn wrong_token_gets_404() {
        let (_srv, addr, pin) = server("right").await;
        let ep = endpoint(addr.port(), "wrong", &pin);
        let err = MasqueTransport::connect(&ep, addr, &ConnectOptions::default())
            .await
            .err()
            .expect("must be rejected");
        assert!(err.to_string().contains("404"), "{err}");
    }

    #[tokio::test]
    async fn wrong_pin_rejected() {
        let (_srv, addr, _pin) = server("tok").await;
        let (_, _, other_pin) = generate_node_cert("other.test").unwrap();
        let ep = endpoint(addr.port(), "tok", &other_pin);
        assert!(
            MasqueTransport::connect(&ep, addr, &ConnectOptions::default())
                .await
                .is_err()
        );
    }
}
