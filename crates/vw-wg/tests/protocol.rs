//! Protocol scenarios between our own initiator and responder: reserved
//! bytes, replay protection, timestamps, cookies under load, rekey and
//! expiry timers, PSK rotation with fallback, DAITA chaff and multi-peer
//! routing.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use vw_core::config::DaitaParams;
use vw_core::packet::build_udp;
use vw_core::secret::Key32;
use vw_core::transport::ChaffSource;
use vw_wg::{
    generate_private_key, pad_plaintext, public_key, Admission, Decapsulated, EngineChaff, Peer,
    Responder, WgError,
};

const SRC: &str = "198.51.100.7:40000";

fn src() -> SocketAddr {
    SRC.parse().unwrap()
}

fn ip(n: u8) -> Vec<u8> {
    build_udp(
        "100.96.0.2:5000".parse().unwrap(),
        "203.0.113.99:443".parse().unwrap(),
        &[n; 64],
        64,
    )
    .unwrap()
}

struct Pair {
    client: Peer,
    server: Responder,
    server_sk: Key32,
    client_pub: [u8; 32],
}

fn pair_with(psk: Option<Key32>, client_reserved: [u8; 3], server_reserved: [u8; 3]) -> Pair {
    let ck = generate_private_key();
    let sk = generate_private_key();
    let client_pub = public_key(&ck);
    let mut server = Responder::new(sk.clone(), Admission::KnownPeersOnly);
    server.add_peer(client_pub, psk.clone(), server_reserved);
    let client = Peer::new_initiator(ck, public_key(&sk), psk, client_reserved);
    Pair {
        client,
        server,
        server_sk: sk,
        client_pub,
    }
}

impl Pair {
    /// Deliver client datagrams to the server and replies back until quiet.
    /// Returns plaintext the server received.
    fn exchange(&mut self, mut to_server: Vec<Vec<u8>>, now: Instant) -> Vec<Vec<u8>> {
        let mut got = Vec::new();
        for _ in 0..8 {
            if to_server.is_empty() {
                break;
            }
            let mut to_client = Vec::new();
            for d in to_server.drain(..) {
                match self.server.decapsulate(Some(src()), &d, now) {
                    Ok(r) => match r.result {
                        Decapsulated::Network(v) => to_client.extend(v),
                        Decapsulated::Tunnel(p) => got.push(p),
                        _ => {}
                    },
                    Err(e) => panic!("server rejected datagram: {e}"),
                }
            }
            for (_, v) in self.server.tick(now) {
                to_client.extend(v);
            }
            for d in to_client {
                if let Ok(Decapsulated::Network(v)) = self.client.decapsulate(&d, now) {
                    to_server.extend(v);
                }
            }
            to_server.extend(self.client.drain_outbox());
        }
        got
    }

    fn connect(&mut self, now: Instant) {
        let init = self.client.tick(now);
        assert_eq!(init.len(), 1);
        self.exchange(init, now);
        assert!(self.client.session_established());
        assert!(self.server_peer().session_established());
    }

    fn server_peer(&self) -> &Peer {
        self.server.peer(&self.client_pub).unwrap()
    }

    fn server_peer_mut(&mut self) -> &mut Peer {
        self.server.peer_mut(&self.client_pub).unwrap()
    }

    fn roundtrip(&mut self, n: u8, now: Instant) {
        let d = self.client.encapsulate(&ip(n), now);
        assert_eq!(self.exchange(d, now), vec![ip(n)]);
        let d = self
            .server
            .encapsulate(&self.client_pub, &ip(n + 1), now)
            .unwrap();
        assert_eq!(d.len(), 1);
        assert_eq!(
            self.client.decapsulate(&d[0], now).unwrap(),
            Decapsulated::Tunnel(ip(n + 1))
        );
    }
}

#[test]
fn reserved_bytes_outside_mac_like_warp() {
    let mut p = pair_with(None, [0xc1, 0x1e, 0x47], [0x07, 0x08, 0x09]);
    let now = Instant::now();
    let init = p.client.tick(now);
    assert_eq!(&init[0][1..4], &[0xc1, 0x1e, 0x47]);
    let r = p.server.decapsulate(Some(src()), &init[0], now).unwrap();
    let Decapsulated::Network(resp) = r.result else {
        panic!("expected response");
    };
    assert_eq!(&resp[0][1..4], &[0x07, 0x08, 0x09]);
    let Decapsulated::Network(k) = p.client.decapsulate(&resp[0], now).unwrap() else {
        panic!("expected keepalive");
    };
    assert_eq!(&k[0][1..4], &[0xc1, 0x1e, 0x47]);
    p.server.decapsulate(Some(src()), &k[0], now).unwrap();
    let d = p.client.encapsulate(&ip(1), now);
    assert_eq!(&d[0][1..4], &[0xc1, 0x1e, 0x47]);
    let d2 = p.server.encapsulate(&p.client_pub, &ip(2), now).unwrap();
    assert_eq!(&d2[0][1..4], &[0x07, 0x08, 0x09]);
    // Receivers ignore the field entirely: rewriting it on a data packet
    // (outside the AEAD) still decrypts.
    let mut tampered = d2[0].clone();
    tampered[1..4].copy_from_slice(&[0xff; 3]);
    assert_eq!(
        p.client.decapsulate(&tampered, now).unwrap(),
        Decapsulated::Tunnel(ip(2))
    );
    // Handshake MACs treat the reserved bytes as zero (Cloudflare WARP
    // semantics), so rewriting them in transit does not invalidate mac1...
    let mut init = p.client.initiate_handshake(now).unwrap();
    init[2] ^= 1;
    assert!(!matches!(
        p.server.decapsulate(Some(src()), &init, now),
        Err(WgError::InvalidMac)
    ));
    // ...while every other header byte is still covered.
    let mut init = p
        .client
        .initiate_handshake(now + std::time::Duration::from_secs(1))
        .unwrap();
    init[5] ^= 1;
    assert_eq!(
        p.server
            .decapsulate(Some(src()), &init, now + std::time::Duration::from_secs(1)),
        Err(WgError::InvalidMac)
    );
}

#[test]
fn replay_rejected_and_window_enforced() {
    let mut p = pair_with(None, [0; 3], [0; 3]);
    let now = Instant::now();
    p.connect(now);
    let pkts: Vec<Vec<u8>> = (0..2100u32)
        .map(|i| p.client.encapsulate(&ip((i % 200) as u8), now).remove(0))
        .collect();
    let deliver =
        |p: &mut Pair, d: &[u8]| p.server.decapsulate(Some(src()), d, now).map(|r| r.result);
    assert!(matches!(
        deliver(&mut p, &pkts[5]),
        Ok(Decapsulated::Tunnel(_))
    ));
    assert_eq!(deliver(&mut p, &pkts[5]), Err(WgError::Replay));
    // Out-of-order within the window is fine, exactly once.
    assert!(matches!(
        deliver(&mut p, &pkts[3]),
        Ok(Decapsulated::Tunnel(_))
    ));
    assert_eq!(deliver(&mut p, &pkts[3]), Err(WgError::Replay));
    // Jump ahead 2099; counter 3..=51 are now outside the 2048 window.
    assert!(matches!(
        deliver(&mut p, &pkts[2099]),
        Ok(Decapsulated::Tunnel(_))
    ));
    assert_eq!(deliver(&mut p, &pkts[4]), Err(WgError::Replay));
    assert_eq!(deliver(&mut p, &pkts[51]), Err(WgError::Replay));
    assert!(matches!(
        deliver(&mut p, &pkts[52]),
        Ok(Decapsulated::Tunnel(_))
    ));
    // Tampered ciphertext fails authentication and does not burn the counter.
    let mut bad = pkts[100].clone();
    let last = bad.len() - 1;
    bad[last] ^= 1;
    assert_eq!(deliver(&mut p, &bad), Err(WgError::Decrypt));
    assert!(matches!(
        deliver(&mut p, &pkts[100]),
        Ok(Decapsulated::Tunnel(_))
    ));
}

#[test]
fn replayed_initiation_rejected_by_timestamp() {
    let mut p = pair_with(None, [0; 3], [0; 3]);
    let now = Instant::now();
    let init = p.client.tick(now);
    p.server.decapsulate(Some(src()), &init[0], now).unwrap();
    assert_eq!(
        p.server
            .decapsulate(Some(src()), &init[0], now + Duration::from_secs(1)),
        Err(WgError::StaleTimestamp)
    );
    // A fresh initiation (newer timestamp) is accepted.
    let init2 = p
        .client
        .initiate_handshake(now + Duration::from_secs(2))
        .unwrap();
    assert!(p
        .server
        .decapsulate(Some(src()), &init2, now + Duration::from_secs(2))
        .is_ok());
    // Initiations faster than 50/s are a flood.
    let init3 = p
        .client
        .initiate_handshake(now + Duration::from_millis(2005))
        .unwrap();
    assert_eq!(
        p.server
            .decapsulate(Some(src()), &init3, now + Duration::from_millis(2005)),
        Err(WgError::Flood)
    );
}

#[test]
fn cookie_flow_under_load() {
    let mut p = pair_with(None, [0; 3], [0; 3]);
    p.server.set_under_load(Some(true));
    let t0 = Instant::now();
    let init = p.client.tick(t0);
    let r = p.server.decapsulate(Some(src()), &init[0], t0).unwrap();
    let Decapsulated::Network(cookie) = r.result else {
        panic!("expected cookie reply");
    };
    assert_eq!(cookie[0].len(), 64);
    assert!(!p.server_peer().session_established());
    assert_eq!(
        p.client.decapsulate(&cookie[0], t0).unwrap(),
        Decapsulated::None
    );
    // The cookie is bound to the source address: another source is refused.
    let t1 = t0 + Duration::from_secs(6);
    let retry = p.client.tick(t1);
    assert_eq!(retry.len(), 1);
    let other: SocketAddr = "198.51.100.8:40000".parse().unwrap();
    let r = p.server.decapsulate(Some(other), &retry[0], t1).unwrap();
    assert!(matches!(r.result, Decapsulated::Network(ref v) if v[0].len() == 64));
    // From the right source, mac2 is valid and the handshake proceeds.
    let got = p.exchange(retry, t1);
    assert!(got.is_empty());
    assert!(p.client.session_established());
    p.server.set_under_load(None);
    p.roundtrip(10, t1);
}

#[test]
fn cookie_expires_after_two_minutes() {
    let mut p = pair_with(None, [0; 3], [0; 3]);
    p.server.set_under_load(Some(true));
    let t0 = Instant::now();
    let init = p.client.tick(t0);
    let r = p.server.decapsulate(Some(src()), &init[0], t0).unwrap();
    let Decapsulated::Network(cookie) = r.result else {
        panic!()
    };
    p.client.decapsulate(&cookie[0], t0).unwrap();
    let late = p
        .client
        .initiate_handshake(t0 + Duration::from_secs(121))
        .unwrap();
    assert_eq!(
        &late[132..148],
        &[0u8; 16],
        "stale cookie not used for mac2"
    );
}

#[test]
fn rekey_after_time_and_previous_session_still_decrypts() {
    let mut p = pair_with(None, [0; 3], [0; 3]);
    let t0 = Instant::now();
    p.connect(t0);
    let in_flight = p.client.encapsulate(&ip(42), t0 + Duration::from_secs(119));
    assert_eq!(in_flight.len(), 1, "no rekey before 120 s");
    assert!(p.client.tick(t0 + Duration::from_secs(60)).is_empty());

    let t1 = t0 + Duration::from_secs(121);
    let init = p.client.tick(t1);
    assert_eq!(init.len(), 1);
    assert_eq!(init[0][0], 1, "handshake initiation");
    p.exchange(init, t1);
    assert_eq!(p.client.handshakes_completed(), 2);
    p.roundtrip(1, t1);
    // A packet encrypted on the old session before the rekey still arrives.
    let r = p
        .server
        .decapsulate(Some(src()), &in_flight[0], t1)
        .unwrap();
    assert_eq!(r.result, Decapsulated::Tunnel(ip(42)));
}

#[test]
fn rekey_on_send_after_time() {
    let ck = generate_private_key();
    let sk = generate_private_key();
    let mut client =
        Peer::new_initiator(ck.clone(), public_key(&sk), None, [0; 3]).with_auto_connect(false);
    let mut server = Peer::new_responder(sk, public_key(&ck), None, [0; 3]);
    let t0 = Instant::now();
    let init = client.encapsulate(&ip(1), t0);
    let Decapsulated::Network(resp) = server.decapsulate(&init[0], t0).unwrap() else {
        panic!()
    };
    let Decapsulated::Network(data) = client.decapsulate(&resp[0], t0).unwrap() else {
        panic!()
    };
    assert_eq!(
        server.decapsulate(&data[0], t0).unwrap(),
        Decapsulated::Tunnel(ip(1))
    );
    let out = client.encapsulate(&ip(2), t0 + Duration::from_secs(125));
    assert_eq!(
        out.len(),
        2,
        "data on the current session plus a new initiation"
    );
    assert_eq!(out[0][0], 4);
    assert_eq!(out[1][0], 1);
}

#[test]
fn sessions_rejected_after_reject_after_time() {
    let ck = generate_private_key();
    let sk = generate_private_key();
    let mut client = Peer::new_initiator(ck.clone(), public_key(&sk), None, [0; 3]);
    let mut server = Peer::new_responder(sk, public_key(&ck), None, [0; 3]);
    let t0 = Instant::now();
    let init = client.tick(t0);
    let Decapsulated::Network(resp) = server.decapsulate(&init[0], t0).unwrap() else {
        panic!()
    };
    let Decapsulated::Network(k) = client.decapsulate(&resp[0], t0).unwrap() else {
        panic!()
    };
    server.decapsulate(&k[0], t0).unwrap();
    let old = client.encapsulate(&ip(1), t0 + Duration::from_secs(170));
    assert_eq!(old[0][0], 4);
    let late = t0 + Duration::from_secs(181);
    assert_eq!(server.decapsulate(&old[0], late), Err(WgError::Expired));
    // The client cannot send on it either: it queues and handshakes.
    let out = client.encapsulate(&ip(2), late);
    assert!(out.iter().all(|d| d[0] == 1));
    assert_eq!(client.queued_packets(), 1);
    // Tick removes expired keypairs entirely.
    server.tick(late);
    assert!(!server.session_established());
}

#[test]
fn psk_swap_triggers_rehandshake_with_new_key() {
    let a = Key32::new([0xa1; 32]);
    let b = Key32::new([0xb2; 32]);
    let mut p = pair_with(Some(a.clone()), [0; 3], [0; 3]);
    let t0 = Instant::now();
    p.connect(t0);
    p.client.set_psk(b.clone());
    p.server_peer_mut().set_psk(b.clone());
    let init = p.client.tick(t0 + Duration::from_millis(100));
    assert_eq!(init.len(), 1, "immediate rehandshake after set_psk");
    p.exchange(init, t0 + Duration::from_millis(100));
    assert_eq!(p.client.handshakes_completed(), 2);
    p.roundtrip(5, t0 + Duration::from_millis(100));

    // The fallback was dropped once B was confirmed: a node holding only A
    // can no longer complete a handshake, a node holding only B can.
    let now = t0 + Duration::from_secs(1);
    let mut only_a = Responder::new(p.server_sk.clone(), Admission::KnownPeersOnly);
    only_a.add_peer(p.client_pub, Some(a), [0; 3]);
    let init = p.client.initiate_handshake(now).unwrap();
    let Decapsulated::Network(resp) = only_a.decapsulate(Some(src()), &init, now).unwrap().result
    else {
        panic!()
    };
    assert_eq!(p.client.decapsulate(&resp[0], now), Err(WgError::Decrypt));
    let mut only_b = Responder::new(p.server_sk.clone(), Admission::KnownPeersOnly);
    only_b.add_peer(p.client_pub, Some(b), [0; 3]);
    let init = p.client.initiate_handshake(now).unwrap();
    let Decapsulated::Network(resp) = only_b.decapsulate(Some(src()), &init, now).unwrap().result
    else {
        panic!()
    };
    assert!(matches!(
        p.client.decapsulate(&resp[0], now),
        Ok(Decapsulated::Network(_))
    ));
}

#[test]
fn initiator_falls_back_to_previous_psk_once() {
    let a = Key32::new([0xa1; 32]);
    let b = Key32::new([0xb2; 32]);
    let mut p = pair_with(Some(a), [0; 3], [0; 3]);
    let t0 = Instant::now();
    p.connect(t0);
    // Only the client rotates; the node still has A.
    p.client.set_psk(b);
    let t1 = t0 + Duration::from_millis(50);
    let init = p.client.tick(t1);
    p.exchange(init, t1);
    assert_eq!(p.client.handshakes_completed(), 2, "completed via fallback");
    p.roundtrip(3, t1);
    // A retry with the new PSK is scheduled; it fails until the node rotates.
    let t2 = t1 + Duration::from_secs(5);
    let retry = p.client.tick(t2);
    assert_eq!(retry.len(), 1);
    let r = p.server.decapsulate(Some(src()), &retry[0], t2).unwrap();
    let Decapsulated::Network(resp) = r.result else {
        panic!()
    };
    assert_eq!(p.client.decapsulate(&resp[0], t2), Err(WgError::Decrypt));
    // Existing session keeps working meanwhile.
    p.roundtrip(7, t2);
}

#[test]
fn responder_falls_back_to_previous_psk_once() {
    let a = Key32::new([0xa1; 32]);
    let b = Key32::new([0xb2; 32]);
    let mut p = pair_with(Some(a), [0; 3], [0; 3]);
    let t0 = Instant::now();
    p.connect(t0);
    // Only the node rotates; the client still has A.
    p.server_peer_mut().set_psk(b);
    let t1 = t0 + Duration::from_secs(1);
    let init = p.client.initiate_handshake(t1).unwrap();
    let r = p.server.decapsulate(Some(src()), &init, t1).unwrap();
    let Decapsulated::Network(resp) = r.result else {
        panic!()
    };
    assert_eq!(
        p.client.decapsulate(&resp[0], t1),
        Err(WgError::Decrypt),
        "first answer uses the new PSK"
    );
    let t2 = t1 + Duration::from_secs(6);
    let retry = p.client.tick(t2);
    assert_eq!(retry.len(), 1, "retransmission");
    p.exchange(retry, t2);
    assert_eq!(p.client.handshakes_completed(), 2, "fallback PSK accepted");
    p.roundtrip(9, t2);
}

#[test]
fn chaff_and_daita_padding() {
    let mut p = pair_with(None, [0; 3], [0; 3]);
    let now = Instant::now();
    p.connect(now);
    let chaff = p.client.make_chaff(300, now).unwrap();
    assert_eq!(chaff.len(), 16 + 304 + 16);
    assert_eq!(
        p.server
            .decapsulate(Some(src()), &chaff, now)
            .unwrap()
            .result,
        Decapsulated::Chaff
    );
    let params = DaitaParams {
        enabled: true,
        ..DaitaParams::default()
    };
    let mut padded = ip(1);
    pad_plaintext(&mut padded, &params);
    assert_eq!(padded.len(), 128);
    let d = p.client.encapsulate(&padded, now);
    assert_eq!(d[0].len(), 16 + 128 + 16);
    assert_eq!(p.exchange(d, now), vec![ip(1)], "padding stripped");

    // ChaffSource over a shared peer handle.
    let shared = Arc::new(Mutex::new(p.client));
    let src_chaff = EngineChaff(shared.clone());
    let c = src_chaff.make_chaff(64).unwrap();
    assert_eq!(
        p.server
            .decapsulate(Some(src()), &c, Instant::now())
            .unwrap()
            .result,
        Decapsulated::Chaff
    );
    let fresh = Arc::new(Mutex::new(Peer::new_initiator(
        generate_private_key(),
        [9; 32],
        None,
        [0; 3],
    )));
    assert!(
        EngineChaff(fresh).make_chaff(64).is_none(),
        "no session, no chaff"
    );
}

#[test]
fn responder_routes_many_peers() {
    let sk = generate_private_key();
    let spub = public_key(&sk);
    let mut server = Responder::new(sk, Admission::AcceptUnknown { max_unknown: 64 });
    let now = Instant::now();
    let mut clients: Vec<Peer> = (0..8)
        .map(|_| Peer::new_initiator(generate_private_key(), spub, None, [0; 3]))
        .collect();
    for c in clients.iter_mut() {
        let init = c.tick(now);
        let r = server.decapsulate(Some(src()), &init[0], now).unwrap();
        assert_eq!(r.peer, Some(*c.local_public()));
        let Decapsulated::Network(resp) = r.result else {
            panic!()
        };
        let Decapsulated::Network(k) = c.decapsulate(&resp[0], now).unwrap() else {
            panic!()
        };
        server.decapsulate(Some(src()), &k[0], now).unwrap();
    }
    for (i, c) in clients.iter_mut().enumerate() {
        let d = c.encapsulate(&ip(i as u8), now);
        let r = server.decapsulate(Some(src()), &d[0], now).unwrap();
        assert_eq!(r.peer, Some(*c.local_public()));
        assert_eq!(r.result, Decapsulated::Tunnel(ip(i as u8)));
        let back = server
            .encapsulate(c.local_public(), &ip(100 + i as u8), now)
            .unwrap();
        assert_eq!(
            c.decapsulate(&back[0], now).unwrap(),
            Decapsulated::Tunnel(ip(100 + i as u8))
        );
    }
    let handles = server.peers();
    assert_eq!(handles.len(), 8);
    assert!(handles.iter().all(|h| h.established && !h.known));
    // Garbage and unknown indices are rejected without panicking.
    assert_eq!(
        server.decapsulate(Some(src()), &[4u8; 40], now),
        Err(WgError::UnknownIndex)
    );
    assert_eq!(
        server.decapsulate(Some(src()), &[9u8; 10], now),
        Err(WgError::Malformed)
    );
}
