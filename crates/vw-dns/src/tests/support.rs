use std::future::Future;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering::SeqCst};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;
use hickory_proto::op::{Edns, Message, ResponseCode};
use hickory_proto::rr::rdata::{A, AAAA, CNAME};
use hickory_proto::rr::{Name, RData, Record, RecordType};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

use crate::error::{DnsError, Result};
use crate::message::response_for;
use crate::tls::{Bootstrap, TlsTrust};
use crate::upstream::{Upstream, UpstreamOptions};

pub struct TestCert {
    pub cert: CertificateDer<'static>,
    key: Vec<u8>,
}

impl TestCert {
    pub fn new() -> Self {
        let ck = rcgen::generate_simple_self_signed(vec![
            "localhost".to_string(),
            "127.0.0.1".to_string(),
            "dot.test".to_string(),
        ])
        .unwrap();
        Self {
            cert: ck.cert.der().clone(),
            key: ck.signing_key.serialize_der(),
        }
    }

    pub fn acceptor(&self, alpn: &[&[u8]]) -> TlsAcceptor {
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(self.key.clone()));
        let mut cfg = rustls::ServerConfig::builder_with_provider(crate::tls::provider())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![self.cert.clone()], key)
            .unwrap();
        cfg.alpn_protocols = alpn.iter().map(|a| a.to_vec()).collect();
        TlsAcceptor::from(Arc::new(cfg))
    }

    pub fn options(&self) -> UpstreamOptions {
        UpstreamOptions {
            trust: TlsTrust::only(vec![self.cert.clone()]),
            bootstrap: Bootstrap::static_only([(
                "localhost".to_string(),
                vec![std::net::IpAddr::V4(Ipv4Addr::LOCALHOST)],
            )]),
            timeout: Duration::from_secs(5),
        }
    }
}

pub type Handler = Arc<
    dyn Fn(http::Request<Bytes>) -> Pin<Box<dyn Future<Output = http::Response<Bytes>> + Send>>
        + Send
        + Sync,
>;

/// HTTP/2-only (ALPN `h2`) HTTPS server on 127.0.0.1.
pub async fn spawn_h2(cert: &TestCert, handler: Handler) -> SocketAddr {
    let acceptor = cert.acceptor(&[b"h2"]);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((tcp, _)) = listener.accept().await else {
                continue;
            };
            let (acceptor, handler) = (acceptor.clone(), handler.clone());
            tokio::spawn(async move {
                let Ok(tls) = acceptor.accept(tcp).await else {
                    return;
                };
                assert_eq!(tls.get_ref().1.alpn_protocol(), Some(&b"h2"[..]));
                let Ok(mut conn) = h2::server::handshake(tls).await else {
                    return;
                };
                while let Some(Ok((req, mut respond))) = conn.accept().await {
                    let handler = handler.clone();
                    tokio::spawn(async move {
                        let (parts, mut body) = req.into_parts();
                        let mut data = Vec::new();
                        while let Some(Ok(chunk)) = body.data().await {
                            let _ = body.flow_control().release_capacity(chunk.len());
                            data.extend_from_slice(&chunk);
                        }
                        let resp =
                            handler(http::Request::from_parts(parts, Bytes::from(data))).await;
                        let (p, b) = resp.into_parts();
                        let Ok(mut send) =
                            respond.send_response(http::Response::from_parts(p, ()), b.is_empty())
                        else {
                            return;
                        };
                        if !b.is_empty() {
                            let _ = send.send_data(b, true);
                        }
                    });
                }
            });
        }
    });
    addr
}

pub fn http_response(status: u16, ct: &str, body: Vec<u8>) -> http::Response<Bytes> {
    http::Response::builder()
        .status(status)
        .header("content-type", ct)
        .body(Bytes::from(body))
        .unwrap()
}

/// Recorded request metadata.
#[derive(Debug, Clone)]
pub struct Seen {
    pub method: http::Method,
    pub version: http::Version,
    pub path_and_query: String,
    pub content_type: String,
    pub accept: String,
    pub body: Vec<u8>,
}

impl Seen {
    pub fn of(req: &http::Request<Bytes>) -> Self {
        let h = |n: &str| {
            req.headers()
                .get(n)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .to_string()
        };
        Self {
            method: req.method().clone(),
            version: req.version(),
            path_and_query: req
                .uri()
                .path_and_query()
                .map(|p| p.to_string())
                .unwrap_or_default(),
            content_type: h("content-type"),
            accept: h("accept"),
            body: req.body().to_vec(),
        }
    }
}

/// Mock authoritative data:
/// * `example.com` A 93.184.216.34 / AAAA 2606:2800:220:1::248 (TTL 300)
/// * `cloaked.shop.example` CNAME `metrics.google-analytics.com.` (a tracker) + A
/// * `clean.shop.example` CNAME `cdn.example.net.` + A
/// * `signed.example` A with the AD flag
/// * `many.example` 120 A records (for truncation)
/// * everything else NXDOMAIN
pub fn authoritative(query: &[u8]) -> Vec<u8> {
    let q = Message::from_vec(query).unwrap();
    let question = q.queries()[0].clone();
    let qname = question.name().to_ascii().to_ascii_lowercase();
    let qtype = question.query_type();
    let mut r = response_for(&q, ResponseCode::NoError);
    r.set_authoritative(false);
    if let Some(e) = q.extensions() {
        let mut edns = Edns::new();
        edns.set_max_payload(1232);
        edns.set_dnssec_ok(e.flags().dnssec_ok);
        r.set_edns(edns);
    }
    let n = |s: &str| Name::from_ascii(s).unwrap();
    let a = |name: &str, ip: [u8; 4], ttl| {
        Record::from_rdata(n(name), ttl, RData::A(A::new(ip[0], ip[1], ip[2], ip[3])))
    };
    match (qname.as_str(), qtype) {
        ("example.com.", RecordType::A) => {
            r.add_answer(a("example.com.", [93, 184, 216, 34], 300));
        }
        ("example.com.", RecordType::AAAA) => {
            r.add_answer(Record::from_rdata(
                n("example.com."),
                300,
                RData::AAAA(AAAA::from(
                    "2606:2800:220:1::248".parse::<Ipv6Addr>().unwrap(),
                )),
            ));
        }
        ("cloaked.shop.example.", _) => {
            r.add_answer(Record::from_rdata(
                n("cloaked.shop.example."),
                300,
                RData::CNAME(CNAME(n("metrics.google-analytics.com."))),
            ));
            r.add_answer(a("metrics.google-analytics.com.", [192, 0, 2, 66], 300));
        }
        ("clean.shop.example.", _) => {
            r.add_answer(Record::from_rdata(
                n("clean.shop.example."),
                300,
                RData::CNAME(CNAME(n("cdn.example.net."))),
            ));
            r.add_answer(a("cdn.example.net.", [192, 0, 2, 80], 300));
        }
        ("signed.example.", _) => {
            r.set_authentic_data(true);
            r.add_answer(a("signed.example.", [192, 0, 2, 5], 300));
        }
        ("many.example.", _) => {
            for i in 0..120u8 {
                r.add_answer(a("many.example.", [10, 0, 0, i], 300));
            }
        }
        _ => {
            r.set_response_code(ResponseCode::NXDomain);
        }
    }
    r.to_vec().unwrap()
}

/// In-process upstream backed by [`authoritative`], recording queries.
#[derive(Default)]
pub struct MockUpstream {
    pub seen: Mutex<Vec<Vec<u8>>>,
    pub calls: AtomicUsize,
    pub fail: AtomicBool,
}

#[async_trait]
impl Upstream for MockUpstream {
    async fn query(&self, wire: &[u8]) -> Result<Vec<u8>> {
        self.calls.fetch_add(1, SeqCst);
        self.seen.lock().unwrap().push(wire.to_vec());
        if self.fail.load(SeqCst) {
            return Err(DnsError::upstream("mock", "down"));
        }
        Ok(authoritative(wire))
    }
    fn name(&self) -> &'static str {
        "mock"
    }
}

/// DoT server; closes each connection after `per_conn` queries.
pub async fn spawn_dot(cert: &TestCert, per_conn: usize) -> (SocketAddr, Arc<AtomicUsize>) {
    let acceptor = cert.acceptor(&[b"dot"]);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let conns = Arc::new(AtomicUsize::new(0));
    let c2 = conns.clone();
    tokio::spawn(async move {
        loop {
            let Ok((tcp, _)) = listener.accept().await else {
                continue;
            };
            c2.fetch_add(1, SeqCst);
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let Ok(mut tls) = acceptor.accept(tcp).await else {
                    return;
                };
                for _ in 0..per_conn {
                    let mut lb = [0u8; 2];
                    if tls.read_exact(&mut lb).await.is_err() {
                        return;
                    }
                    let mut q = vec![0u8; u16::from_be_bytes(lb) as usize];
                    if tls.read_exact(&mut q).await.is_err() {
                        return;
                    }
                    let r = authoritative(&q);
                    let mut f = (r.len() as u16).to_be_bytes().to_vec();
                    f.extend_from_slice(&r);
                    if tls.write_all(&f).await.is_err() {
                        return;
                    }
                }
                let _ = tls.shutdown().await;
            });
        }
    });
    (addr, conns)
}

pub fn first_a(wire: &[u8]) -> Option<Ipv4Addr> {
    Message::from_vec(wire)
        .ok()?
        .answers()
        .iter()
        .find_map(|r| match r.data() {
            RData::A(a) => Some(a.0),
            _ => None,
        })
}
