use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};
use std::sync::{Arc, Mutex};

use hickory_proto::op::Message;
use hickory_proto::rr::RecordType;
use vw_core::config::ShieldCategory;

use super::support::*;
use crate::message::testutil::query;
use crate::shield::{BlocklistSource, BlocklistUpdater, Shield};
use crate::upstream::odoh::target::TestTarget;
use crate::upstream::odoh::{encode_configs, ODOH_MESSAGE};
use crate::upstream::{DohUpstream, DotUpstream, FailoverUpstream, OdohUpstream, Upstream};

#[tokio::test]
async fn doh_posts_dns_message_over_http2() {
    let cert = TestCert::new();
    let seen = Arc::new(Mutex::new(Vec::<Seen>::new()));
    let s2 = seen.clone();
    let addr = spawn_h2(
        &cert,
        Arc::new(move |req| {
            let s = Seen::of(&req);
            s2.lock().unwrap().push(s);
            Box::pin(async move {
                if req.uri().path() != "/dns-query" {
                    return http_response(404, "text/plain", vec![]);
                }
                http_response(200, "application/dns-message", authoritative(req.body()))
            })
        }),
    )
    .await;
    let doh = DohUpstream::with_options(
        &format!("https://127.0.0.1:{}/dns-query", addr.port()),
        &cert.options(),
    )
    .unwrap();
    let r = doh
        .query(&query("example.com.", RecordType::A, 0x1234, true))
        .await
        .unwrap();
    assert_eq!(&r[0..2], &[0x12, 0x34], "client id restored");
    assert_eq!(first_a(&r), Some(Ipv4Addr::new(93, 184, 216, 34)));
    let s = seen.lock().unwrap()[0].clone();
    assert_eq!(s.method, http::Method::POST);
    assert_eq!(s.version, http::Version::HTTP_2);
    assert_eq!(s.content_type, "application/dns-message");
    assert_eq!(s.accept, "application/dns-message");
    assert_eq!(&s.body[0..2], &[0, 0], "RFC 8484 id 0 on the wire");

    // localhost via the bootstrap table works too; a 404 path is an error.
    let bad = DohUpstream::with_options(
        &format!("https://localhost:{}/nope", addr.port()),
        &cert.options(),
    )
    .unwrap();
    assert!(bad
        .query(&query("example.com.", RecordType::A, 1, false))
        .await
        .is_err());
    // Untrusted certificate is rejected.
    let other = TestCert::new();
    let untrusted = DohUpstream::with_options(
        &format!("https://127.0.0.1:{}/dns-query", addr.port()),
        &other.options(),
    )
    .unwrap();
    assert!(untrusted
        .query(&query("example.com.", RecordType::A, 1, false))
        .await
        .is_err());
    assert!(DohUpstream::with_options("http://127.0.0.1/dns-query", &cert.options()).is_err());
}

#[tokio::test]
async fn dot_reuses_and_reconnects() {
    let cert = TestCert::new();
    let (addr, conns) = spawn_dot(&cert, 3).await;
    let dot = DotUpstream::with_options("dot.test", addr, &cert.options()).unwrap();
    for i in 0..7u16 {
        let r = dot
            .query(&query("example.com.", RecordType::A, 100 + i, false))
            .await
            .unwrap();
        assert_eq!(u16::from_be_bytes([r[0], r[1]]), 100 + i);
        assert_eq!(first_a(&r), Some(Ipv4Addr::new(93, 184, 216, 34)));
    }
    // 7 queries, server closes after 3 per connection → 3 connections.
    assert_eq!(conns.load(SeqCst), 3);
    assert!(dot.idle_connections().await <= 4);
    // Wrong certificate name is rejected.
    let wrong = DotUpstream::with_options("wrong.test", addr, &cert.options()).unwrap();
    assert!(wrong
        .query(&query("example.com.", RecordType::A, 1, false))
        .await
        .is_err());
}

struct OdohWorld {
    proxy: std::net::SocketAddr,
    target: std::net::SocketAddr,
    keys: Arc<Mutex<Arc<TestTarget>>>,
    config_fetches: Arc<AtomicUsize>,
    proxy_seen: Arc<Mutex<Vec<Seen>>>,
}

async fn odoh_world(cert: &TestCert) -> OdohWorld {
    let keys = Arc::new(Mutex::new(Arc::new(TestTarget::generate())));
    let config_fetches = Arc::new(AtomicUsize::new(0));
    let (k2, f2) = (keys.clone(), config_fetches.clone());
    let target = spawn_h2(
        cert,
        Arc::new(move |req| {
            let t = k2.lock().unwrap().clone();
            let f = f2.clone();
            Box::pin(async move {
                match (req.method().as_str(), req.uri().path()) {
                    ("GET", "/.well-known/odohconfigs") => {
                        f.fetch_add(1, SeqCst);
                        http_response(
                            200,
                            "application/octet-stream",
                            encode_configs(std::slice::from_ref(&t.config)),
                        )
                    }
                    ("POST", "/dns-query") => {
                        let ct = req
                            .headers()
                            .get("content-type")
                            .and_then(|v| v.to_str().ok())
                            .unwrap_or("");
                        if ct != ODOH_MESSAGE {
                            return http_response(415, "text/plain", vec![]);
                        }
                        match t.handle(req.body(), authoritative) {
                            Ok(r) => http_response(200, ODOH_MESSAGE, r),
                            Err(_) => http_response(400, "text/plain", vec![]),
                        }
                    }
                    _ => http_response(404, "text/plain", vec![]),
                }
            })
        }),
    )
    .await;

    // The proxy forwards to https://{targethost}{targetpath}, like a real relay.
    let relay_client = reqwest::Client::builder()
        .tls_backend_preconfigured(
            crate::tls::TlsTrust::only(vec![cert.cert.clone()])
                .client_config(&[b"h2"])
                .unwrap(),
        )
        .http2_prior_knowledge()
        .build()
        .unwrap();
    let proxy_seen = Arc::new(Mutex::new(Vec::<Seen>::new()));
    let ps = proxy_seen.clone();
    let proxy = spawn_h2(
        cert,
        Arc::new(move |req| {
            ps.lock().unwrap().push(Seen::of(&req));
            let client = relay_client.clone();
            Box::pin(async move {
                let q = req.uri().query().unwrap_or("").to_string();
                let get = |k: &str| {
                    q.split('&')
                        .find_map(|kv| kv.strip_prefix(&format!("{k}=")))
                        .map(|v| v.replace("%2F", "/").replace("%3A", ":"))
                };
                let (Some(host), Some(path)) = (get("targethost"), get("targetpath")) else {
                    return http_response(400, "text/plain", vec![]);
                };
                let resp = client
                    .post(format!("https://{host}{path}"))
                    .header("content-type", ODOH_MESSAGE)
                    .body(req.body().to_vec())
                    .send()
                    .await
                    .unwrap();
                let status = resp.status().as_u16();
                let body = resp.bytes().await.unwrap().to_vec();
                http_response(status, ODOH_MESSAGE, body)
            })
        }),
    )
    .await;
    OdohWorld {
        proxy,
        target,
        keys,
        config_fetches,
        proxy_seen,
    }
}

#[tokio::test]
async fn odoh_through_proxy_with_key_rotation() {
    let cert = TestCert::new();
    let w = odoh_world(&cert).await;
    let target_host = format!("127.0.0.1:{}", w.target.port());
    let odoh = OdohUpstream::with_options(
        &format!("https://127.0.0.1:{}/proxy", w.proxy.port()),
        &target_host,
        "/dns-query",
        &cert.options(),
    )
    .unwrap();

    let r = odoh
        .query(&query("example.com.", RecordType::A, 0xbeef, true))
        .await
        .unwrap();
    assert_eq!(&r[0..2], &[0xbe, 0xef]);
    assert_eq!(first_a(&r), Some(Ipv4Addr::new(93, 184, 216, 34)));
    assert_eq!(w.config_fetches.load(SeqCst), 1);

    // Proxy saw an opaque message with the right metadata, never the name.
    let s = w.proxy_seen.lock().unwrap()[0].clone();
    assert_eq!(s.method, http::Method::POST);
    assert_eq!(s.content_type, ODOH_MESSAGE);
    assert!(s.path_and_query.starts_with("/proxy?targethost="));
    assert!(s.path_and_query.contains("targetpath=%2Fdns-query"));
    assert!(!s
        .body
        .windows(7)
        .any(|w| w.eq_ignore_ascii_case(b"example")));

    // Config is cached for the next query.
    odoh.query(&query("example.com.", RecordType::A, 2, false))
        .await
        .unwrap();
    assert_eq!(w.config_fetches.load(SeqCst), 1);

    // Target rotates its key: the client refreshes the config and retries.
    *w.keys.lock().unwrap() = Arc::new(TestTarget::generate());
    let r = odoh
        .query(&query("example.com.", RecordType::A, 3, false))
        .await
        .unwrap();
    assert_eq!(first_a(&r), Some(Ipv4Addr::new(93, 184, 216, 34)));
    assert_eq!(w.config_fetches.load(SeqCst), 2);
}

#[tokio::test]
async fn failover_skips_dead_upstream() {
    let cert = TestCert::new();
    let (addr, _) = spawn_dot(&cert, 100).await;
    // Port 9 on localhost: nothing listens → connection refused.
    let dead = DohUpstream::with_options("https://127.0.0.1:9/dns-query", &cert.options()).unwrap();
    let dot = DotUpstream::with_options("dot.test", addr, &cert.options()).unwrap();
    let f = FailoverUpstream::new(
        vec![Arc::new(dead), Arc::new(dot)],
        std::time::Duration::from_secs(3),
    );
    for i in 0..3 {
        let r = f
            .query(&query("example.com.", RecordType::A, i, false))
            .await
            .unwrap();
        assert_eq!(first_a(&r), Some(Ipv4Addr::new(93, 184, 216, 34)));
    }
    let h = f.health();
    assert!(!h[0].healthy);
    assert!(h[1].healthy);
}

#[tokio::test]
async fn blocklist_updater_downloads_into_ram() {
    let cert = TestCert::new();
    let addr = spawn_h2(
        &cert,
        Arc::new(|req| {
            Box::pin(async move {
                match req.uri().path() {
                    "/hosts.txt" => http_response(
                        200,
                        "text/plain",
                        b"# test\n0.0.0.0 remote-ads.example\n127.0.0.1 localhost\n0.0.0.0 com\n"
                            .to_vec(),
                    ),
                    "/domains.txt" => {
                        http_response(200, "text/plain", b"evil-remote.example\n".to_vec())
                    }
                    "/huge.txt" => http_response(200, "text/plain", vec![b'a'; 4096]),
                    _ => http_response(404, "text/plain", vec![]),
                }
            })
        }),
    )
    .await;
    let base = format!("https://127.0.0.1:{}", addr.port());
    let opts = cert.options();
    let src = |p: &str, c| BlocklistSource {
        url: format!("{base}{p}"),
        category: c,
    };
    let up = BlocklistUpdater::with_tls(
        vec![
            src("/hosts.txt", ShieldCategory::Ads),
            src("/domains.txt", ShieldCategory::Malware),
            src("/missing.txt", ShieldCategory::Ads),
            src("/huge.txt", ShieldCategory::Ads),
        ],
        &opts.trust,
        opts.bootstrap.clone(),
    )
    .unwrap()
    .with_limits(1024, 1000);
    let shield = Shield::new(&vw_core::config::ShieldSettings::default());
    let report = up.update(&shield).await;
    assert_eq!(report.sources_ok, 2);
    assert_eq!(report.sources_failed, 2);
    assert_eq!(
        shield.check("x.remote-ads.example"),
        Some(ShieldCategory::Ads)
    );
    assert_eq!(
        shield.check("evil-remote.example"),
        Some(ShieldCategory::Malware)
    );
    assert_eq!(shield.check("localhost"), None);
    assert_eq!(shield.check("anything.com"), None, "TLD entries rejected");
    // Plain http sources are refused.
    let http = BlocklistUpdater::with_tls(
        vec![BlocklistSource {
            url: format!("http://127.0.0.1:{}/hosts.txt", addr.port()),
            category: ShieldCategory::Ads,
        }],
        &opts.trust,
        opts.bootstrap.clone(),
    )
    .unwrap();
    assert!(http.fetch(&http.sources()[0].clone()).await.is_err());
}

#[test]
fn dnssec_ad_flag_reader() {
    let mut m = Message::from_vec(&authoritative(&query(
        "signed.example.",
        RecordType::A,
        1,
        true,
    )))
    .unwrap();
    assert!(crate::message::ad_flag(&m.to_vec().unwrap()));
    m.set_authentic_data(false);
    assert!(!crate::message::ad_flag(&m.to_vec().unwrap()));
}
