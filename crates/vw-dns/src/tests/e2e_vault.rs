use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::Ordering::{Relaxed, SeqCst};
use std::sync::Arc;

use hickory_proto::op::{Message, ResponseCode};
use hickory_proto::rr::rdata::opt::{ClientSubnet, EdnsCode, EdnsOption};
use hickory_proto::rr::{RData, RecordType};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use vw_core::config::{BlockMode, DnsSettings, ShieldCategory};
use vw_core::telemetry::Counters;

use super::support::*;
use crate::message::testutil::query;
use crate::upstream::DohUpstream;
use crate::vault::{serve_tcp, serve_udp, Disposition, DnsVault};

fn vault_with(mode: BlockMode) -> (Arc<DnsVault>, Arc<MockUpstream>, Arc<Counters>) {
    let mut s = DnsSettings::default();
    s.shield.block_mode = mode;
    let up = Arc::new(MockUpstream::default());
    let counters = Arc::new(Counters::default());
    (
        Arc::new(DnsVault::new(s, up.clone(), counters.clone())),
        up,
        counters,
    )
}

#[tokio::test]
async fn forwards_with_do_bit_and_without_ecs() {
    let (v, up, _) = vault_with(BlockMode::ZeroIp);
    let mut q = Message::from_vec(&query("example.com.", RecordType::A, 77, true)).unwrap();
    q.extensions_mut()
        .as_mut()
        .unwrap()
        .options_mut()
        .insert(EdnsOption::Subnet(ClientSubnet::new(
            "198.51.100.0".parse().unwrap(),
            24,
            0,
        )));
    let res = v.resolve_detailed(&q.to_vec().unwrap()).await;
    assert_eq!(res.disposition, Disposition::Forwarded);
    let m = Message::from_vec(&res.response).unwrap();
    assert_eq!(m.id(), 77);
    assert_eq!(
        first_a(&res.response),
        Some(Ipv4Addr::new(93, 184, 216, 34))
    );
    let sent = Message::from_vec(&up.seen.lock().unwrap()[0]).unwrap();
    let e = sent.extensions().as_ref().unwrap();
    assert!(e.flags().dnssec_ok, "DO bit set upstream");
    assert!(e.option(EdnsCode::Subnet).is_none(), "ECS stripped");
    assert_ne!(sent.id(), 77, "upstream id is independent");
}

#[tokio::test]
async fn caches_and_flushes() {
    let (v, up, _) = vault_with(BlockMode::ZeroIp);
    let q = query("example.com.", RecordType::A, 1, false);
    v.resolve(&q).await;
    let res = v
        .resolve_detailed(&query("EXAMPLE.com.", RecordType::A, 2, false))
        .await;
    assert_eq!(res.disposition, Disposition::Cached);
    assert_eq!(Message::from_vec(&res.response).unwrap().id(), 2);
    assert_eq!(up.calls.load(SeqCst), 1);
    v.flush();
    assert_eq!(v.cache_len(), 0);
    v.resolve(&q).await;
    assert_eq!(up.calls.load(SeqCst), 2);
}

#[tokio::test]
async fn shield_blocks_question_per_mode() {
    for mode in [BlockMode::ZeroIp, BlockMode::Nxdomain] {
        let (v, up, c) = vault_with(mode);
        let res = v
            .resolve_detailed(&query("ad.doubleclick.net.", RecordType::A, 5, false))
            .await;
        assert_eq!(res.disposition, Disposition::Blocked(ShieldCategory::Ads));
        let m = Message::from_vec(&res.response).unwrap();
        assert_eq!(m.id(), 5);
        assert_eq!(m.queries()[0].name().to_ascii(), "ad.doubleclick.net.");
        match mode {
            BlockMode::ZeroIp => {
                assert_eq!(first_a(&res.response), Some(Ipv4Addr::UNSPECIFIED));
            }
            BlockMode::Nxdomain => assert_eq!(m.response_code(), ResponseCode::NXDomain),
        }
        assert_eq!(
            up.calls.load(SeqCst),
            0,
            "blocked names never leave the host"
        );
        assert_eq!(c.shield_ads.load(Relaxed), 1);
    }
}

#[tokio::test]
async fn uncloaks_cname_tracker_and_counts() {
    let (v, _, c) = vault_with(BlockMode::ZeroIp);
    let res = v
        .resolve_detailed(&query("cloaked.shop.example.", RecordType::A, 9, false))
        .await;
    assert_eq!(
        res.disposition,
        Disposition::Uncloaked(ShieldCategory::Trackers)
    );
    assert_eq!(first_a(&res.response), Some(Ipv4Addr::UNSPECIFIED));
    assert_eq!(c.shield_cname_uncloaked.load(Relaxed), 1);
    assert_eq!(c.shield_trackers.load(Relaxed), 1);
    // Served from cache it is still uncloaked (and counted).
    let res = v
        .resolve_detailed(&query("cloaked.shop.example.", RecordType::A, 10, false))
        .await;
    assert_eq!(
        res.disposition,
        Disposition::Uncloaked(ShieldCategory::Trackers)
    );
    assert_eq!(Message::from_vec(&res.response).unwrap().id(), 10);
    assert_eq!(c.shield_cname_uncloaked.load(Relaxed), 2);
    // A clean CNAME chain passes.
    let res = v
        .resolve_detailed(&query("clean.shop.example.", RecordType::A, 11, false))
        .await;
    assert_eq!(res.disposition, Disposition::Forwarded);
}

#[tokio::test]
async fn local_names_and_canary_never_forwarded() {
    let (v, up, _) = vault_with(BlockMode::ZeroIp);
    for name in [
        "printer.local.",
        "nas.lan.",
        "router.home.arpa.",
        "use-application-dns.net.",
        "1.0.168.192.in-addr.arpa.",
        "1.0.64.100.in-addr.arpa.",
        "5.20.172.in-addr.arpa.",
    ] {
        let res = v
            .resolve_detailed(&query(name, RecordType::A, 3, false))
            .await;
        assert_eq!(res.disposition, Disposition::Local, "{name}");
        let m = Message::from_vec(&res.response).unwrap();
        assert_eq!(m.response_code(), ResponseCode::NXDomain, "{name}");
    }
    let res = v
        .resolve(&query("localhost.", RecordType::A, 3, false))
        .await;
    assert_eq!(first_a(&res), Some(Ipv4Addr::LOCALHOST));
    // Lookalikes are forwarded normally.
    v.resolve(&query("local.example.com.", RecordType::A, 3, false))
        .await;
    v.resolve(&query("notlan.", RecordType::A, 3, false)).await;
    assert_eq!(up.calls.load(SeqCst), 2);
}

#[tokio::test]
async fn servfail_and_formerr_always_well_formed() {
    let (v, up, _) = vault_with(BlockMode::ZeroIp);
    up.fail.store(true, SeqCst);
    let res = v
        .resolve_detailed(&query("example.com.", RecordType::A, 44, false))
        .await;
    assert_eq!(res.disposition, Disposition::Failed);
    let m = Message::from_vec(&res.response).unwrap();
    assert_eq!(m.response_code(), ResponseCode::ServFail);
    assert_eq!(m.id(), 44);
    for garbage in [&[][..], &[1, 2][..], &[0xff; 40][..]] {
        let r = v.resolve(garbage).await;
        assert!(Message::from_vec(&r).is_ok());
    }
}

#[tokio::test]
async fn dnssec_flag_reported_and_hidden_from_plain_clients() {
    let (v, _, _) = vault_with(BlockMode::ZeroIp);
    let res = v
        .resolve_detailed(&query("signed.example.", RecordType::A, 1, false))
        .await;
    assert!(res.dnssec_validated);
    // Client without DO/AD does not get AD (RFC 6840 §5.8).
    assert!(!Message::from_vec(&res.response).unwrap().authentic_data());
    let mut q = Message::from_vec(&query("signed.example.", RecordType::A, 1, true)).unwrap();
    q.extensions_mut().as_mut().unwrap().set_dnssec_ok(true);
    v.flush();
    let res = v.resolve_detailed(&q.to_vec().unwrap()).await;
    assert!(Message::from_vec(&res.response).unwrap().authentic_data());
    let res = v
        .resolve_detailed(&query("example.com.", RecordType::A, 1, false))
        .await;
    assert!(!res.dnssec_validated);
}

#[tokio::test]
async fn inspector_only_when_enabled() {
    let (v, _, _) = vault_with(BlockMode::ZeroIp);
    let mut rx = v.subscribe();
    v.resolve(&query("ad.doubleclick.net.", RecordType::A, 1, false))
        .await;
    assert!(rx.try_recv().is_err(), "disabled inspector emits nothing");
    v.set_inspector(true);
    v.resolve(&query("ad.doubleclick.net.", RecordType::A, 1, false))
        .await;
    let ev = rx.try_recv().unwrap();
    assert_eq!(ev.name, "ad.doubleclick.net");
    assert_eq!(ev.category, Some(ShieldCategory::Ads));
    assert!(ev.blocked);
    v.resolve(&query("example.com.", RecordType::A, 1, false))
        .await;
    let ev = rx.try_recv().unwrap();
    assert!(!ev.blocked && ev.category.is_none());
}

#[tokio::test]
async fn udp_truncation_respects_client_size() {
    let (v, _, _) = vault_with(BlockMode::ZeroIp);
    let r = v
        .resolve_udp(&query("many.example.", RecordType::A, 1, false), 1232)
        .await;
    assert!(r.len() <= 512);
    assert!(Message::from_vec(&r).unwrap().truncated());
    let full = v
        .resolve(&query("many.example.", RecordType::A, 1, false))
        .await;
    assert_eq!(Message::from_vec(&full).unwrap().answers().len(), 120);
}

#[tokio::test]
async fn socket_servers_answer_udp_and_tcp() {
    let (v, _, _) = vault_with(BlockMode::Nxdomain);
    let local: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let udp = serve_udp(v.clone(), local).await.unwrap();
    let tcp = serve_tcp(v.clone(), local).await.unwrap();

    let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    sock.send_to(
        &query("example.com.", RecordType::A, 321, true),
        udp.local_addr(),
    )
    .await
    .unwrap();
    let mut buf = [0u8; 2048];
    let (n, _) = tokio::time::timeout(std::time::Duration::from_secs(5), sock.recv_from(&mut buf))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(first_a(&buf[..n]), Some(Ipv4Addr::new(93, 184, 216, 34)));
    assert_eq!(u16::from_be_bytes([buf[0], buf[1]]), 321);

    let mut s = tokio::net::TcpStream::connect(tcp.local_addr())
        .await
        .unwrap();
    for (i, name) in ["example.com.", "ad.doubleclick.net."].iter().enumerate() {
        let q = query(name, RecordType::A, i as u16, false);
        let mut f = (q.len() as u16).to_be_bytes().to_vec();
        f.extend_from_slice(&q);
        s.write_all(&f).await.unwrap();
        let mut lb = [0u8; 2];
        s.read_exact(&mut lb).await.unwrap();
        let mut r = vec![0u8; u16::from_be_bytes(lb) as usize];
        s.read_exact(&mut r).await.unwrap();
        let m = Message::from_vec(&r).unwrap();
        assert_eq!(m.id(), i as u16);
        if i == 1 {
            assert_eq!(m.response_code(), ResponseCode::NXDomain);
        }
    }
    udp.shutdown();
    drop(tcp);
}

#[tokio::test]
async fn vault_over_real_doh_upstream_uncloaks() {
    // Same flow, but through the production DoH client and a local HTTPS server.
    let cert = TestCert::new();
    let addr = spawn_h2(
        &cert,
        Arc::new(|req| {
            Box::pin(async move {
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
    let mut s = DnsSettings::default();
    s.shield.block_mode = BlockMode::Nxdomain;
    let v = DnsVault::new(s, Arc::new(doh), Arc::new(Counters::default()));
    let r = v
        .resolve(&query("cloaked.shop.example.", RecordType::AAAA, 8, false))
        .await;
    let m = Message::from_vec(&r).unwrap();
    assert_eq!(m.response_code(), ResponseCode::NXDomain);
    assert_eq!(m.id(), 8);
    let r = v
        .resolve(&query("example.com.", RecordType::AAAA, 9, false))
        .await;
    let m = Message::from_vec(&r).unwrap();
    assert!(matches!(m.answers()[0].data(), RData::AAAA(_)));
}
