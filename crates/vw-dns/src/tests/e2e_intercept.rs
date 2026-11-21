use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::Ordering::Relaxed;
use std::sync::Arc;

use hickory_proto::op::{Message, ResponseCode};
use hickory_proto::rr::{RData, RecordType};
use vw_core::config::{BlockMode, DnsSettings};
use vw_core::packet::{build_tcp_syn, build_udp, checksum, verify_l4_checksum, IpView};
use vw_core::telemetry::Counters;

use super::support::*;
use crate::intercept::{intercept, InterceptVerdict};
use crate::message::testutil::query;
use crate::vault::DnsVault;

fn vault(mode: BlockMode) -> (DnsVault, Arc<Counters>) {
    let mut s = DnsSettings::default();
    s.shield.block_mode = mode;
    let c = Arc::new(Counters::default());
    (
        DnsVault::new(s, Arc::new(MockUpstream::default()), c.clone()),
        c,
    )
}

/// Send a query packet, return the DNS payload of the response and check
/// addresses, ports and checksums.
async fn ask(v: &DnsVault, client: SocketAddr, server: SocketAddr, dns: &[u8]) -> Vec<u8> {
    let pkt = build_udp(client, server, dns, 64).unwrap();
    let InterceptVerdict::Respond(resp) = intercept(v, &pkt).await else {
        panic!("expected a response");
    };
    let view = IpView::parse(&resp).unwrap();
    assert_eq!(
        view.src_sock(&resp),
        Some(server),
        "source = original destination"
    );
    assert_eq!(
        view.dst_sock(&resp),
        Some(client),
        "destination = original source"
    );
    assert!(verify_l4_checksum(&resp));
    if view.version == 4 {
        assert_eq!(checksum(&resp[..20]), 0, "ipv4 header checksum");
    }
    view.udp_payload(&resp).unwrap().to_vec()
}

#[tokio::test]
async fn hijacks_hardcoded_resolvers_v4_and_v6() {
    let (v, c) = vault(BlockMode::ZeroIp);
    let client: SocketAddr = "100.96.0.2:53111".parse().unwrap();
    let google: SocketAddr = "8.8.8.8:53".parse().unwrap();
    let dns = ask(
        &v,
        client,
        google,
        &query("example.com.", RecordType::A, 0x0a0b, false),
    )
    .await;
    assert_eq!(first_a(&dns), Some(Ipv4Addr::new(93, 184, 216, 34)));
    assert_eq!(u16::from_be_bytes([dns[0], dns[1]]), 0x0a0b);

    let client6: SocketAddr = "[fd00:564f:4944:1::2]:40000".parse().unwrap();
    let google6: SocketAddr = "[2001:4860:4860::8888]:53".parse().unwrap();
    let dns = ask(
        &v,
        client6,
        google6,
        &query("example.com.", RecordType::AAAA, 7, true),
    )
    .await;
    let m = Message::from_vec(&dns).unwrap();
    match m.answers()[0].data() {
        RData::AAAA(a) => assert_eq!(a.0, "2606:2800:220:1::248".parse::<Ipv6Addr>().unwrap()),
        other => panic!("unexpected {other:?}"),
    }

    // The vault address itself is answered the same way.
    let vault4 = SocketAddr::new(vw_core::consts::DNS_VAULT_V4.into(), 53);
    let dns = ask(
        &v,
        client,
        vault4,
        &query("example.com.", RecordType::A, 1, false),
    )
    .await;
    assert!(first_a(&dns).is_some());
    assert_eq!(c.dns_intercepted.load(Relaxed), 3);
}

#[tokio::test]
async fn blocked_and_cloaked_names_per_mode() {
    let client: SocketAddr = "100.96.0.2:5353".parse().unwrap();
    let cf: SocketAddr = "1.1.1.1:53".parse().unwrap();
    let (v, c) = vault(BlockMode::ZeroIp);
    for name in ["ad.doubleclick.net.", "cloaked.shop.example."] {
        let dns = ask(&v, client, cf, &query(name, RecordType::A, 3, false)).await;
        assert_eq!(first_a(&dns), Some(Ipv4Addr::UNSPECIFIED), "{name}");
    }
    assert_eq!(c.shield_cname_uncloaked.load(Relaxed), 1);

    let (v, _) = vault(BlockMode::Nxdomain);
    for name in ["ad.doubleclick.net.", "cloaked.shop.example."] {
        let dns = ask(&v, client, cf, &query(name, RecordType::A, 3, false)).await;
        let m = Message::from_vec(&dns).unwrap();
        assert_eq!(m.response_code(), ResponseCode::NXDomain, "{name}");
        assert_eq!(m.queries()[0].name().to_ascii(), name);
    }
}

#[tokio::test]
async fn foreign_dot_dropped_vault_dot_passes() {
    let (v, c) = vault(BlockMode::ZeroIp);
    let client: SocketAddr = "100.96.0.2:40001".parse().unwrap();
    let dot: SocketAddr = "1.1.1.1:853".parse().unwrap();
    let pkt = build_tcp_syn(client, dot, 1000, &[], 64).unwrap();
    assert_eq!(intercept(&v, &pkt).await, InterceptVerdict::Drop);
    let pkt = build_udp(client, dot, b"doq", 64).unwrap();
    assert_eq!(intercept(&v, &pkt).await, InterceptVerdict::Drop);
    assert_eq!(c.dot_blocked.load(Relaxed), 2);
    let vault_dot = SocketAddr::new(vw_core::consts::DNS_VAULT_V4.into(), 853);
    let pkt = build_tcp_syn(client, vault_dot, 1, &[], 64).unwrap();
    assert_eq!(intercept(&v, &pkt).await, InterceptVerdict::NotDns);
    let https: SocketAddr = "1.1.1.1:443".parse().unwrap();
    let pkt = build_tcp_syn(client, https, 1, &[], 64).unwrap();
    assert_eq!(intercept(&v, &pkt).await, InterceptVerdict::NotDns);
    assert_eq!(intercept(&v, &[0x45, 0, 0]).await, InterceptVerdict::NotDns);
}

#[tokio::test]
async fn tcp_dns_gets_valid_rst() {
    let (v, _) = vault(BlockMode::ZeroIp);
    for (client, server) in [
        ("100.96.0.2:40002", "8.8.4.4:53"),
        ("[fd00:564f:4944:1::2]:40003", "[2606:4700:4700::1111]:53"),
    ] {
        let client: SocketAddr = client.parse().unwrap();
        let server: SocketAddr = server.parse().unwrap();
        let seq = 0xdead_beefu32;
        let syn = build_tcp_syn(client, server, seq, &[2, 4, 5, 0xb4], 64).unwrap();
        let InterceptVerdict::Respond(rst) = intercept(&v, &syn).await else {
            panic!("expected RST");
        };
        let view = IpView::parse(&rst).unwrap();
        assert_eq!(view.protocol, vw_core::packet::PROTO_TCP);
        assert_eq!(view.src_sock(&rst), Some(server));
        assert_eq!(view.dst_sock(&rst), Some(client));
        assert!(verify_l4_checksum(&rst));
        let t = &rst[view.l4_offset..];
        assert_eq!(t[13], 0x14, "RST|ACK");
        assert_eq!(u32::from_be_bytes([t[4], t[5], t[6], t[7]]), 0);
        assert_eq!(
            u32::from_be_bytes([t[8], t[9], t[10], t[11]]),
            seq.wrapping_add(1),
            "ack = SYN seq + 1"
        );
        // An RST is never answered.
        assert_eq!(intercept(&v, &rst).await, InterceptVerdict::NotDns);
    }
}
