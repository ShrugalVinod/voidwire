//! Interoperability with Cloudflare's independent `boringtun` implementation:
//! handshakes in both directions, data both ways, with and without a PSK,
//! and the cookie (under-load) flow in both directions.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use boringtun::noise::rate_limiter::RateLimiter;
use boringtun::noise::{Tunn, TunnResult};
use boringtun::x25519::{PublicKey, StaticSecret};
use rand::rngs::OsRng;
use vw_core::packet::build_udp;
use vw_core::secret::Key32;
use vw_wg::{generate_private_key, public_key, Admission, Decapsulated, Peer, Responder};

#[derive(Debug, Default)]
struct BtOut {
    net: Vec<Vec<u8>>,
    tun: Vec<Vec<u8>>,
}

fn bt_decap(t: &mut Tunn, src: Option<IpAddr>, d: &[u8]) -> BtOut {
    let mut out = BtOut::default();
    let mut buf = vec![0u8; 4096];
    match t.decapsulate(src, d, &mut buf) {
        TunnResult::WriteToNetwork(p) => {
            out.net.push(p.to_vec());
            loop {
                let mut b = vec![0u8; 4096];
                match t.decapsulate(None, &[], &mut b) {
                    TunnResult::WriteToNetwork(p) => out.net.push(p.to_vec()),
                    _ => break,
                }
            }
        }
        TunnResult::WriteToTunnelV4(p, _) | TunnResult::WriteToTunnelV6(p, _) => {
            out.tun.push(p.to_vec())
        }
        TunnResult::Done => {}
        TunnResult::Err(e) => panic!("boringtun rejected datagram: {e:?}"),
    }
    out
}

fn bt_encap(t: &mut Tunn, pkt: &[u8]) -> Vec<u8> {
    let mut buf = vec![0u8; pkt.len() + 64];
    match t.encapsulate(pkt, &mut buf) {
        TunnResult::WriteToNetwork(p) => p.to_vec(),
        other => panic!("boringtun encapsulate: {other:?}"),
    }
}

fn bt_init(t: &mut Tunn, force: bool) -> Vec<u8> {
    let mut buf = vec![0u8; 256];
    match t.format_handshake_initiation(&mut buf, force) {
        TunnResult::WriteToNetwork(p) => p.to_vec(),
        other => panic!("boringtun initiation: {other:?}"),
    }
}

fn packets() -> Vec<Vec<u8>> {
    let v4a: SocketAddr = "100.96.0.2:5000".parse().unwrap();
    let v4b: SocketAddr = "203.0.113.99:53".parse().unwrap();
    let v6a: SocketAddr = "[fd00:564f:4944:1::2]:5000".parse().unwrap();
    let v6b: SocketAddr = "[2001:db8::1]:443".parse().unwrap();
    vec![
        build_udp(v4a, v4b, b"hello boringtun", 64).unwrap(),
        build_udp(v4a, v4b, &[0xAB; 1200], 64).unwrap(),
        build_udp(v6a, v6b, &[7u8; 33], 64).unwrap(),
        build_udp(v4a, v4b, &[], 64).unwrap(),
    ]
}

fn bt_keys() -> (StaticSecret, [u8; 32]) {
    let s = StaticSecret::random_from_rng(OsRng);
    let p = PublicKey::from(&s).to_bytes();
    (s, p)
}

fn ours_initiates(psk: Option<[u8; 32]>) {
    let ours_sk = generate_private_key();
    let (bt_sk, bt_pub) = bt_keys();
    let mut ours = Peer::new_initiator(ours_sk.clone(), bt_pub, psk.map(Key32::new), [0; 3]);
    let mut bt = Tunn::new(
        bt_sk,
        PublicKey::from(public_key(&ours_sk)),
        psk,
        None,
        1,
        None,
    );
    let now = Instant::now();
    let pkts = packets();

    let out = ours.encapsulate(&pkts[0], now);
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].len(), 148);
    let r = bt_decap(&mut bt, None, &out[0]);
    assert_eq!(r.net.len(), 1);
    assert_eq!(r.net[0].len(), 92);
    let Decapsulated::Network(data) = ours.decapsulate(&r.net[0], now).unwrap() else {
        panic!("expected queued data after response");
    };
    assert_eq!(data.len(), 1);
    assert!(ours.session_established());
    assert_eq!(bt_decap(&mut bt, None, &data[0]).tun, vec![pkts[0].clone()]);

    for p in &pkts {
        // ours -> boringtun
        let d = ours.encapsulate(p, now);
        assert_eq!(d.len(), 1);
        assert_eq!(&bt_decap(&mut bt, None, &d[0]).tun, &vec![p.clone()]);
        // boringtun -> ours
        let d = bt_encap(&mut bt, p);
        assert_eq!(
            ours.decapsulate(&d, now).unwrap(),
            Decapsulated::Tunnel(p.clone())
        );
    }
    // Keepalives both ways.
    let k = ours.keepalive(now).unwrap();
    assert!(bt_decap(&mut bt, None, &k).tun.is_empty());
    let k = bt_encap(&mut bt, &[]);
    assert_eq!(ours.decapsulate(&k, now).unwrap(), Decapsulated::Keepalive);
}

fn boringtun_initiates(psk: Option<[u8; 32]>) {
    let server_sk = generate_private_key();
    let server_pub = public_key(&server_sk);
    let (bt_sk, bt_pub) = bt_keys();
    let mut r = match psk {
        None => Responder::new(server_sk, Admission::AcceptUnknown { max_unknown: 16 }),
        Some(k) => {
            let mut r = Responder::new(server_sk, Admission::KnownPeersOnly);
            r.add_peer(bt_pub, Some(Key32::new(k)), [0; 3]);
            r
        }
    };
    let mut bt = Tunn::new(bt_sk, PublicKey::from(server_pub), psk, None, 7, None);
    let now = Instant::now();
    let src: SocketAddr = "198.51.100.7:40000".parse().unwrap();

    let init = bt_init(&mut bt, false);
    let routed = r.decapsulate(Some(src), &init, now).unwrap();
    assert_eq!(routed.peer, Some(bt_pub));
    let Decapsulated::Network(resp) = routed.result else {
        panic!("expected response");
    };
    let out = bt_decap(&mut bt, None, &resp[0]);
    assert_eq!(out.net.len(), 1, "boringtun confirms with a keepalive");
    let routed = r.decapsulate(Some(src), &out.net[0], now).unwrap();
    assert_eq!(routed.result, Decapsulated::Keepalive);
    assert!(r.peer(&bt_pub).unwrap().session_established());

    for p in packets() {
        let d = bt_encap(&mut bt, &p);
        let routed = r.decapsulate(Some(src), &d, now).unwrap();
        assert_eq!(routed.result, Decapsulated::Tunnel(p.clone()));
        let d = r.encapsulate(&bt_pub, &p, now).unwrap();
        assert_eq!(d.len(), 1);
        assert_eq!(bt_decap(&mut bt, None, &d[0]).tun, vec![p]);
    }
}

#[test]
fn our_initiator_with_boringtun_responder() {
    ours_initiates(None);
}

#[test]
fn our_initiator_with_boringtun_responder_psk() {
    ours_initiates(Some([0x42; 32]));
}

#[test]
fn boringtun_initiator_with_our_responder() {
    boringtun_initiates(None);
}

#[test]
fn boringtun_initiator_with_our_responder_psk() {
    boringtun_initiates(Some([0x17; 32]));
}

#[test]
fn psk_mismatch_fails_against_boringtun() {
    let ours_sk = generate_private_key();
    let (bt_sk, bt_pub) = bt_keys();
    let mut ours = Peer::new_initiator(ours_sk.clone(), bt_pub, Some(Key32::new([1; 32])), [0; 3]);
    let mut bt = Tunn::new(
        bt_sk,
        PublicKey::from(public_key(&ours_sk)),
        Some([2; 32]),
        None,
        1,
        None,
    );
    let now = Instant::now();
    let init = ours.tick(now);
    let r = bt_decap(&mut bt, None, &init[0]);
    assert_eq!(
        ours.decapsulate(&r.net[0], now),
        Err(vw_wg::WgError::Decrypt)
    );
    assert!(!ours.session_established());
}

#[test]
fn cookie_flow_against_boringtun_under_load() {
    let ours_sk = generate_private_key();
    let (bt_sk, bt_pub) = bt_keys();
    let mut ours = Peer::new_initiator(ours_sk.clone(), bt_pub, None, [0; 3]);
    // limit 0: boringtun is permanently "under load" and demands mac2.
    let limiter = Arc::new(RateLimiter::new(&PublicKey::from(bt_pub), 0));
    let mut bt = Tunn::new(
        bt_sk,
        PublicKey::from(public_key(&ours_sk)),
        None,
        None,
        1,
        Some(limiter),
    );
    let src: IpAddr = "198.51.100.7".parse().unwrap();
    let t0 = Instant::now();
    let init = ours.tick(t0);
    let r = bt_decap(&mut bt, Some(src), &init[0]);
    assert_eq!(r.net.len(), 1);
    assert_eq!(r.net[0].len(), 64, "cookie reply");
    assert_eq!(ours.decapsulate(&r.net[0], t0).unwrap(), Decapsulated::None);
    // Retransmission after REKEY_TIMEOUT carries mac2 and is accepted.
    let t1 = t0 + Duration::from_secs(6);
    let init2 = ours.tick(t1);
    assert_eq!(init2.len(), 1);
    assert_ne!(&init2[0][132..148], &[0u8; 16], "mac2 present");
    let r = bt_decap(&mut bt, Some(src), &init2[0]);
    assert_eq!(r.net[0].len(), 92, "handshake response");
    let Decapsulated::Network(k) = ours.decapsulate(&r.net[0], t1).unwrap() else {
        panic!("expected keepalive");
    };
    bt_decap(&mut bt, Some(src), &k[0]);
    let p = &packets()[0];
    let d = bt_encap(&mut bt, p);
    assert_eq!(
        ours.decapsulate(&d, t1).unwrap(),
        Decapsulated::Tunnel(p.clone())
    );
}

#[test]
fn cookie_flow_boringtun_against_our_responder_under_load() {
    let server_sk = generate_private_key();
    let server_pub = public_key(&server_sk);
    let (bt_sk, bt_pub) = bt_keys();
    let mut r = Responder::new(server_sk, Admission::AcceptUnknown { max_unknown: 4 });
    r.set_under_load(Some(true));
    let mut bt = Tunn::new(bt_sk, PublicKey::from(server_pub), None, None, 3, None);
    let src: SocketAddr = "198.51.100.9:41000".parse().unwrap();
    let now = Instant::now();
    let init = bt_init(&mut bt, false);
    let routed = r.decapsulate(Some(src), &init, now).unwrap();
    assert_eq!(routed.peer, None);
    let Decapsulated::Network(cookie) = routed.result else {
        panic!("expected cookie reply");
    };
    assert_eq!(cookie[0].len(), 64);
    assert!(
        r.peers().is_empty(),
        "no state before the cookie round trip"
    );
    let out = bt_decap(&mut bt, Some(src.ip()), &cookie[0]);
    assert!(out.net.is_empty());
    let init = bt_init(&mut bt, true);
    let routed = r.decapsulate(Some(src), &init, now).unwrap();
    assert_eq!(routed.peer, Some(bt_pub));
    let Decapsulated::Network(resp) = routed.result else {
        panic!("expected response");
    };
    let out = bt_decap(&mut bt, Some(src.ip()), &resp[0]);
    assert_eq!(
        r.decapsulate(Some(src), &out.net[0], now).unwrap().result,
        Decapsulated::Keepalive
    );
}
