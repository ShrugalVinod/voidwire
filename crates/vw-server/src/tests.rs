//! End-to-end admission tests: a real `vw_wg` initiator + `vw_crypto`
//! VWCP client talking to the node core in memory, and over loopback UDP.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use vw_core::consts::{NODE_GATEWAY_V4, PROVISIONAL_V4, VWCP_PORT};
use vw_core::packet::{build_udp, IpView};
use vw_crypto::blind::{finalize, prepare_token, TokenIssuerKey};
use vw_crypto::identity::NodeIdentity;
use vw_crypto::invite::Invite;
use vw_crypto::vwcp::{
    error_code, ClientHandshake, ErrorMsg, Message, MsgType, PqSession, Reassembler, RedeemRequest,
    RedeemResponse,
};
use vw_crypto::CryptoError;
use vw_wg::{generate_private_key, public_key, Decapsulated, Peer};

use crate::admission::{Issuers, SpentLedger};
use crate::attestation::Facts;
use crate::icmp::tests::echo_v4;
use crate::node::{Action, AdmitKind, CoreConfig, NodeCore};

const UNIX_NOW: u64 = 1_800_000_000;

fn tier_der(t: u8) -> &'static [u8] {
    static KEYS: OnceLock<Vec<Vec<u8>>> = OnceLock::new();
    &KEYS.get_or_init(|| {
        (0..2u8)
            .map(|t| {
                TokenIssuerKey::generate(t)
                    .unwrap()
                    .to_der()
                    .unwrap()
                    .expose()
                    .to_vec()
            })
            .collect()
    })[t as usize]
}

fn facts() -> Facts {
    Facts {
        binary_blake3: "cd".repeat(32),
        swap_disabled: true,
        logging_off: true,
        ram_only: true,
        uptime_secs: 99,
    }
}

fn make_core<R: Clone>(owners: Vec<[u8; 32]>) -> NodeCore<R> {
    let issuers = Issuers::new(
        (0..2u8)
            .map(|t| TokenIssuerKey::from_der(t, tier_der(t)).unwrap())
            .collect(),
    );
    let mut c = NodeCore::new(
        CoreConfig {
            wg_key: generate_private_key(),
            identity: NodeIdentity::generate(),
            owners,
            issuers,
            ledger: SpentLedger::in_memory(),
            max_peers: 16,
        },
        Box::new(facts),
    );
    c.set_clock(|| UNIX_NOW);
    c
}

/// A client device: WireGuard initiator + inbox of decrypted packets.
struct Client {
    id: u32,
    peer: Peer,
    public: [u8; 32],
    inbox: Vec<Vec<u8>>,
    src: SocketAddr,
}

impl Client {
    fn new(id: u32, node_pub: [u8; 32]) -> Self {
        Self::with_key(id, generate_private_key(), node_pub)
    }

    fn with_key(id: u32, k: vw_core::secret::Key32, node_pub: [u8; 32]) -> Self {
        let public = public_key(&k);
        Self {
            id,
            peer: Peer::new_initiator(k, node_pub, None, [0; 3]),
            public,
            inbox: Vec::new(),
            src: SocketAddr::new(IpAddr::V4(PROVISIONAL_V4), 40_000 + id as u16),
        }
    }
}

struct World {
    core: NodeCore<u32>,
    now: Instant,
    tun_out: Vec<Vec<u8>>,
}

impl World {
    fn new(owners: Vec<[u8; 32]>) -> Self {
        Self {
            core: make_core(owners),
            now: Instant::now(),
            tun_out: Vec::new(),
        }
    }

    fn advance(&mut self, d: Duration) {
        self.now += d;
    }

    /// Deliver datagrams client→node and run the exchange to quiescence.
    fn deliver(&mut self, c: &mut Client, mut to_node: Vec<Vec<u8>>) {
        for _ in 0..64 {
            if to_node.is_empty() {
                return;
            }
            let mut to_client = Vec::new();
            for d in to_node.drain(..) {
                for a in self.core.on_datagram(c.id, None, &d, self.now) {
                    self.route(a, &mut to_client);
                }
            }
            for d in to_client {
                match c.peer.decapsulate(&d, self.now) {
                    Ok(Decapsulated::Network(ds)) => to_node.extend(ds),
                    Ok(Decapsulated::Tunnel(p)) => c.inbox.push(p),
                    _ => {}
                }
                to_node.extend(c.peer.drain_outbox());
            }
        }
        panic!("exchange did not settle");
    }

    fn route(&mut self, a: Action<u32>, to_client: &mut Vec<Vec<u8>>) {
        match a {
            Action::Send { datagram, .. } => to_client.push(datagram),
            Action::Tun(p) => self.tun_out.push(p),
        }
    }

    /// WireGuard handshake (or re-handshake) driven by the client's timers.
    fn connect(&mut self, c: &mut Client) {
        let d = c.peer.tick(self.now);
        self.deliver(c, d);
        assert!(c.peer.session_established());
    }

    fn send_ip(&mut self, c: &mut Client, pkt: &[u8]) {
        let d = c.peer.encapsulate(pkt, self.now);
        self.deliver(c, d);
    }

    fn inject_download(&mut self, c: &mut Client, pkt: &[u8]) {
        let mut to_client = Vec::new();
        for a in self.core.on_tun_packet(pkt, self.now) {
            self.route(a, &mut to_client);
        }
        for d in to_client {
            if let Ok(Decapsulated::Tunnel(p)) = c.peer.decapsulate(&d, self.now) {
                c.inbox.push(p);
            }
        }
    }

    /// Send VWCP datagrams and collect complete VWCP messages in reply.
    fn vwcp(&mut self, c: &mut Client, datagrams: Vec<Vec<u8>>) -> Vec<Message> {
        let gw = SocketAddr::new(IpAddr::V4(NODE_GATEWAY_V4), VWCP_PORT);
        c.inbox.clear();
        for d in datagrams {
            let pkt = build_udp(c.src, gw, &d, 64).unwrap();
            self.send_ip(c, &pkt);
        }
        let mut r = Reassembler::new();
        let mut out = Vec::new();
        for p in c.inbox.drain(..) {
            let v = IpView::parse(&p).unwrap();
            assert_eq!(v.src, IpAddr::V4(NODE_GATEWAY_V4));
            assert_eq!(
                v.dst_sock(&p),
                Some(c.src),
                "reply goes to the client socket"
            );
            if let Some(m) = r.push(v.udp_payload(&p).unwrap(), self.now).unwrap() {
                out.push(m);
            }
        }
        out
    }

    fn single(&mut self, c: &mut Client, d: Vec<Vec<u8>>) -> Message {
        let mut m = self.vwcp(c, d);
        assert_eq!(m.len(), 1, "expected exactly one VWCP reply");
        m.remove(0)
    }

    /// Full VWCP exchange presenting `token`; installs the PSK and re-handshakes.
    fn admit(
        &mut self,
        c: &mut Client,
        epoch: u32,
        token: Vec<u8>,
    ) -> Result<PqSession, CryptoError> {
        let node_id = self.core.identity().public();
        let (mut hs, ch) = ClientHandshake::start(node_id, epoch, token).unwrap();
        let sh = self.single(c, ch);
        if sh.ty == MsgType::Error {
            return Err(ErrorMsg::decode(&sh.body).unwrap().into_error());
        }
        assert_eq!(sh.ty, MsgType::ServerHello);
        let kem = hs.on_server_hello(&sh.body)?;
        let ack = self.single(c, kem);
        if ack.ty == MsgType::Error {
            return Err(ErrorMsg::decode(&ack.body).unwrap().into_error());
        }
        let sess = hs.on_server_ack(&ack.body)?;
        c.peer.set_psk(sess.psk.clone());
        self.advance(Duration::from_millis(50));
        self.connect(c);
        c.src = SocketAddr::new(IpAddr::V4(sess.v4), c.src.port());
        Ok(sess)
    }
}

fn token_rejected(e: &CryptoError) -> bool {
    matches!(e, CryptoError::Peer { code, .. } if *code == error_code::TOKEN_REJECTED)
}

fn udp_to(src: Ipv4Addr, dst: &str, payload: &[u8]) -> Vec<u8> {
    build_udp(
        SocketAddr::new(IpAddr::V4(src), 5555),
        dst.parse().unwrap(),
        payload,
        64,
    )
    .unwrap()
}

#[test]
fn owner_admission_forwarding_icmp_spoofing_and_rotation() {
    let k = generate_private_key();
    let mut w = World::new(vec![public_key(&k)]);
    let mut owner = Client::with_key(1, k, w.core.wg_public());
    w.connect(&mut owner);

    // Unadmitted: nothing is forwarded, ICMP to the gateway is not answered.
    let pkt = udp_to(PROVISIONAL_V4, "1.1.1.1:53", b"q");
    w.send_ip(&mut owner, &pkt);
    let ping = echo_v4(PROVISIONAL_V4, NODE_GATEWAY_V4, 1, 1, b"p");
    w.send_ip(&mut owner, &ping);
    assert!(w.tun_out.is_empty());
    assert!(owner.inbox.is_empty());
    assert_eq!(w.core.stats().unadmitted_dropped, 2);
    assert!(w.core.admission_of(&owner.public).is_none());

    // A stranger with an empty token is refused.
    let mut stranger = Client::new(2, w.core.wg_public());
    w.connect(&mut stranger);
    let err = w.admit(&mut stranger, 1, Vec::new()).unwrap_err();
    assert!(token_rejected(&err), "{err:?}");

    // Owner admission (empty token).
    let sess = w.admit(&mut owner, 1, Vec::new()).unwrap();
    assert_eq!(sess.v4, Ipv4Addr::new(100, 96, 0, 2));
    assert_eq!(sess.v4_prefix, 32);
    assert_eq!(w.core.admission_of(&owner.public), Some(AdmitKind::Owner));
    assert_eq!(
        w.core.grant_of(&owner.public),
        Some((crate::admission::OWNER_TIER, 0))
    );
    assert_eq!(w.core.assigned(&owner.public), Some((sess.v4, sess.v6)));
    assert_eq!(
        w.core
            .responder()
            .peer(&owner.public)
            .unwrap()
            .handshakes_completed(),
        2
    );

    // Forwarding with the assigned source.
    let up = udp_to(sess.v4, "1.1.1.1:53", b"hello");
    w.send_ip(&mut owner, &up);
    assert_eq!(w.tun_out, vec![up.clone()]);
    // Spoofed source and client-to-client are dropped.
    w.send_ip(
        &mut owner,
        &udp_to(Ipv4Addr::new(100, 96, 0, 77), "1.1.1.1:53", b"x"),
    );
    w.send_ip(&mut owner, &udp_to(sess.v4, "100.96.0.3:53", b"x"));
    assert_eq!(w.tun_out.len(), 1);
    assert_eq!(w.core.stats().spoofed_dropped, 1);
    assert_eq!(w.core.stats().client_to_client_dropped, 1);

    // Return traffic is routed to the owner of the destination address.
    let down = build_udp(
        "1.1.1.1:53".parse().unwrap(),
        SocketAddr::new(IpAddr::V4(sess.v4), 5555),
        b"answer",
        60,
    )
    .unwrap();
    w.inject_download(&mut owner, &down);
    assert_eq!(owner.inbox, vec![down]);
    owner.inbox.clear();
    w.inject_download(
        &mut owner,
        &udp_to(Ipv4Addr::new(1, 1, 1, 1), "100.96.0.200:1", b"x"),
    );
    assert_eq!(w.core.stats().no_route_dropped, 1);

    // ICMP echo to the gateway is answered with a correct reply.
    let ping = echo_v4(sess.v4, NODE_GATEWAY_V4, 0x77, 9, b"rtt-probe");
    w.send_ip(&mut owner, &ping);
    assert_eq!(owner.inbox.len(), 1);
    let rep = owner.inbox.remove(0);
    assert_eq!(crate::icmp::echo_reply(&ping).unwrap(), rep);
    assert_eq!(vw_core::packet::checksum(&rep[20..]), 0);

    // Rotation: epoch must advance once the new PSK was used; no token needed.
    w.advance(Duration::from_secs(120));
    let err = w.admit(&mut owner, 1, Vec::new()).unwrap_err();
    assert!(matches!(err, CryptoError::Peer { code, .. } if code == error_code::EPOCH_REJECTED));
    let s2 = w.admit(&mut owner, 2, Vec::new()).unwrap();
    assert_eq!(s2.v4, sess.v4, "address is stable across rotation");
    assert_ne!(s2.psk, sess.psk);
    assert_eq!(w.core.stats().rotations, 1);
    w.send_ip(&mut owner, &up);
    assert_eq!(w.tun_out.len(), 2, "traffic flows on the rotated PSK");
}

#[test]
fn invite_redeem_session_tokens_and_double_spend() {
    let mut w = World::new(Vec::new());
    let node_uri = {
        // Minimal valid node URI for the invite.
        let d = vw_core::config::NodeDescriptor {
            version: 1,
            name: "t".into(),
            kind: vw_core::config::NodeKind::Voidwire,
            role: vw_core::config::NodeRole::Both,
            wg_public_key: vw_core::config::Bytes32(w.core.wg_public()),
            identity_key: Some(w.core.identity().public()),
            endpoints: vec![vw_core::config::Endpoint {
                transport: vw_core::config::TransportKind::NativeUdp,
                host: "198.51.100.1".into(),
                port: 51820,
                sni: None,
                path: None,
                cert_sha256: None,
            }],
            amnezia: None,
            country: None,
            ipv6_exit: false,
            static_v4: None,
            static_v6: None,
            reserved: None,
            static_psk: None,
            token_keys: w.core.issuers().token_key_infos().unwrap(),
            client_private: None,
        };
        vw_core::uri::encode_node(&d).unwrap()
    };
    let (uri, tier) = w
        .core
        .create_invite(50_000_000, UNIX_NOW + 3600, &node_uri)
        .unwrap();
    assert_eq!(tier.id, 1);
    assert_eq!(w.core.outstanding_invites(), 1);
    let invite = Invite::from_uri(&uri, UNIX_NOW).unwrap();
    assert_eq!(invite.bandwidth_bps, 50_000_000);
    let mut inv_token = vec![0x02];
    inv_token.extend_from_slice(invite.invite_secret.expose());

    // Friend redeems the invite.
    let mut friend = Client::new(1, w.core.wg_public());
    w.connect(&mut friend);
    // A redemption before admission is refused.
    let pk = w.core.issuers().public(1).unwrap().clone();
    let (b0, _) = prepare_token(&pk).unwrap();
    let e = w.single(
        &mut friend,
        RedeemRequest { blinded: vec![b0] }.datagrams().unwrap(),
    );
    assert_eq!(e.ty, MsgType::Error);

    let sess = w.admit(&mut friend, 1, inv_token.clone()).unwrap();
    assert_eq!(w.core.admission_of(&friend.public), Some(AdmitKind::Invite));
    assert_eq!(w.core.grant_of(&friend.public), Some((1, 50_000_000)));
    assert_eq!(w.core.outstanding_invites(), 0, "invite is single-use");

    let mut pending = Vec::new();
    let mut blinded = Vec::new();
    for _ in 0..3 {
        let (b, p) = prepare_token(&pk).unwrap();
        blinded.push(b);
        pending.push(p);
    }
    let req = RedeemRequest { blinded }.datagrams().unwrap();
    let resp = w.single(&mut friend, req.clone());
    assert_eq!(resp.ty, MsgType::RedeemResponse);
    let resp = RedeemResponse::decode(&resp.body).unwrap();
    assert_eq!(resp.tier, 1);
    assert_eq!(resp.blind_sigs.len(), 3);
    // An identical retry gets the same answer; a different request is refused.
    let again = w.single(&mut friend, req);
    assert_eq!(RedeemResponse::decode(&again.body).unwrap(), resp);
    let (b1, _) = prepare_token(&pk).unwrap();
    let e = w.single(
        &mut friend,
        RedeemRequest { blinded: vec![b1] }.datagrams().unwrap(),
    );
    assert_eq!(e.ty, MsgType::Error);
    assert_eq!(
        ErrorMsg::decode(&e.body).unwrap().code,
        error_code::TOKEN_REJECTED
    );

    let tokens: Vec<_> = pending
        .into_iter()
        .zip(resp.blind_sigs.iter())
        .map(|(p, s)| finalize(p, s).unwrap())
        .collect();

    // The invite cannot be reused by another device.
    let mut thief = Client::new(2, w.core.wg_public());
    w.connect(&mut thief);
    assert!(token_rejected(
        &w.admit(&mut thief, 1, inv_token).unwrap_err()
    ));

    // Later, a fresh device key admits with an unlinkable session token.
    let mut later = Client::new(3, w.core.wg_public());
    w.connect(&mut later);
    let mut t0 = vec![0x01];
    t0.extend_from_slice(&tokens[0].encode());
    let s3 = w.admit(&mut later, 1, t0.clone()).unwrap();
    assert_ne!(s3.v4, sess.v4);
    assert_eq!(
        w.core.admission_of(&later.public),
        Some(AdmitKind::SessionToken)
    );
    assert_eq!(w.core.grant_of(&later.public), Some((1, 50_000_000)));
    // Session-token sessions cannot redeem.
    let (b2, _) = prepare_token(&pk).unwrap();
    let e = w.single(
        &mut later,
        RedeemRequest { blinded: vec![b2] }.datagrams().unwrap(),
    );
    assert_eq!(e.ty, MsgType::Error);

    // Double spend from another device is rejected.
    let mut copycat = Client::new(4, w.core.wg_public());
    w.connect(&mut copycat);
    assert!(token_rejected(&w.admit(&mut copycat, 1, t0).unwrap_err()));
    // A tampered token is rejected; an unused one works.
    let mut bad = vec![0x01];
    let mut tb = tokens[1].encode();
    tb[10] ^= 1;
    bad.extend_from_slice(&tb);
    assert!(token_rejected(&w.admit(&mut copycat, 1, bad).unwrap_err()));
    let mut t2 = vec![0x01];
    t2.extend_from_slice(&tokens[2].encode());
    w.admit(&mut copycat, 1, t2).unwrap();
    assert_eq!(w.core.admitted_count(), 3);

    // Bandwidth: tier 1 (50 Mbps) passes one 250 ms burst at a single instant.
    let before = w.tun_out.len();
    let pkt = udp_to(s3.v4, "1.1.1.1:9", &[0u8; 972]);
    assert_eq!(pkt.len(), 1000);
    for _ in 0..2000 {
        let d = later.peer.encapsulate(&pkt, w.now);
        for d in d {
            for a in w.core.on_datagram(later.id, None, &d, w.now) {
                if let Action::Tun(p) = a {
                    w.tun_out.push(p);
                }
            }
        }
    }
    assert_eq!(w.tun_out.len() - before, 1562);
    assert!(w.core.stats().rate_limited_dropped >= 438);
}

#[test]
fn attestation_over_vwcp_and_expired_invites() {
    let mut w = World::new(Vec::new());
    let mut c = Client::new(1, w.core.wg_public());
    w.connect(&mut c);
    let req = vw_crypto::vwcp::AttestRequest { nonce: [5; 32] };
    let m = w.single(&mut c, req.datagrams().unwrap());
    assert_eq!(m.ty, MsgType::AttestResponse);
    let a = vw_crypto::vwcp::AttestResponse::decode(&m.body)
        .unwrap()
        .attestation;
    let r = a.verify(&w.core.identity().public(), &[5; 32]).unwrap();
    assert!(r.ram_only && r.swap_disabled && r.logging_off);
    assert_eq!(r.unix_time, UNIX_NOW);
    assert_eq!(r.uptime_secs, 99);

    assert!(w
        .core
        .create_invite(1, UNIX_NOW, "voidwire://node/x")
        .is_err());
    let err = w
        .core
        .create_invite(200_000_000, UNIX_NOW + 10, "voidwire://node/x");
    assert!(err.is_err(), "tier 2 has no issuer key in this test");
}

mod loopback {
    use super::*;
    use std::sync::{Arc, Mutex};
    use tokio::sync::watch;
    use vw_core::config::AmneziaParams;
    use vw_core::transport::{StealthTransport, TunDevice};
    use vw_stealth::{AmneziaWgTransport, NativeUdpTransport, SocketOptions, UdpListener};
    use vw_wg::VirtualTunChannel;

    use crate::listeners::{serve, Listeners, Remote};

    async fn pump(
        t: &dyn StealthTransport,
        peer: &mut Peer,
        out: Vec<Vec<u8>>,
        want: impl Fn(&[u8]) -> bool,
    ) -> Vec<u8> {
        for d in out {
            t.send(&d).await.unwrap();
        }
        let mut buf = vec![0u8; 65_535];
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        loop {
            let n = tokio::time::timeout_at(deadline, t.recv(&mut buf))
                .await
                .expect("timed out waiting for the node")
                .unwrap();
            let now = Instant::now();
            match peer.decapsulate(&buf[..n], now) {
                Ok(Decapsulated::Tunnel(p)) if want(&p) => return p,
                Ok(Decapsulated::Network(ds)) => {
                    for d in ds {
                        t.send(&d).await.unwrap();
                    }
                }
                _ => {}
            }
            for d in peer.drain_outbox() {
                t.send(&d).await.unwrap();
            }
        }
    }

    /// Drive the client's handshake timers until one more handshake completes
    /// (retransmits cover the responder's initiation flood protection).
    async fn handshake(t: &dyn StealthTransport, peer: &mut Peer) {
        let before = peer.handshakes_completed();
        let deadline = Instant::now() + Duration::from_secs(20);
        let mut buf = vec![0u8; 65_535];
        while peer.handshakes_completed() == before {
            assert!(Instant::now() < deadline, "handshake timed out");
            let out = peer.tick(Instant::now());
            if !out.is_empty() {
                t.before_handshake().await.unwrap();
            }
            for d in out {
                t.send(&d).await.unwrap();
            }
            if let Ok(r) = tokio::time::timeout(Duration::from_millis(200), t.recv(&mut buf)).await
            {
                let n = r.unwrap();
                if let Ok(Decapsulated::Network(ds)) = peer.decapsulate(&buf[..n], Instant::now()) {
                    for d in ds {
                        t.send(&d).await.unwrap();
                    }
                }
            }
        }
    }

    fn is_vwcp_reply(p: &[u8]) -> bool {
        IpView::parse(p).is_ok_and(|v| v.src == IpAddr::V4(NODE_GATEWAY_V4))
    }

    async fn vwcp_msg(
        t: &dyn StealthTransport,
        peer: &mut Peer,
        src: SocketAddr,
        ds: Vec<Vec<u8>>,
    ) -> Message {
        let gw = SocketAddr::new(IpAddr::V4(NODE_GATEWAY_V4), VWCP_PORT);
        let mut out = Vec::new();
        for d in ds {
            out.extend(peer.encapsulate(&build_udp(src, gw, &d, 64).unwrap(), Instant::now()));
        }
        let mut r = Reassembler::new();
        let mut first = true;
        loop {
            let batch = if first {
                std::mem::take(&mut out)
            } else {
                Vec::new()
            };
            first = false;
            let p = pump(t, peer, batch, is_vwcp_reply).await;
            let v = IpView::parse(&p).unwrap();
            if let Some(m) = r.push(v.udp_payload(&p).unwrap(), Instant::now()).unwrap() {
                return m;
            }
        }
    }

    async fn owner_session(
        t: &dyn StealthTransport,
        peer: &mut Peer,
        node_id: vw_core::config::Bytes32,
        port: u16,
    ) -> PqSession {
        handshake(t, peer).await;
        let src = SocketAddr::new(IpAddr::V4(PROVISIONAL_V4), port);
        let (mut hs, ch) = ClientHandshake::start(node_id, 1, Vec::new()).unwrap();
        let sh = vwcp_msg(t, peer, src, ch).await;
        assert_eq!(sh.ty, MsgType::ServerHello);
        let kem = hs.on_server_hello(&sh.body).unwrap();
        let ack = vwcp_msg(t, peer, src, kem).await;
        let s = hs.on_server_ack(&ack.body).unwrap();
        peer.set_psk(s.psk.clone());
        handshake(t, peer).await;
        s
    }

    #[tokio::test]
    async fn shared_udp_port_plain_and_amnezia_end_to_end() {
        let k_awg = generate_private_key();
        let k_plain = generate_private_key();
        let core: NodeCore<Remote> = make_core(vec![public_key(&k_awg), public_key(&k_plain)]);
        let node_pub = core.wg_public();
        let node_id = core.identity().public();
        let core = Arc::new(Mutex::new(core));

        let params = AmneziaParams::random();
        let udp = UdpListener::bind("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let addr = udp.local_addr().unwrap();
        let listeners = Arc::new(Listeners::new(Some((udp, params)), Vec::new()).unwrap());
        let (node_tun, inet) = VirtualTunChannel::pair(1280);
        let node_tun: Arc<dyn TunDevice> = Arc::new(node_tun);
        let (tx, rx) = watch::channel(false);
        let server = tokio::spawn(serve(core.clone(), listeners, node_tun, rx));

        let opts = SocketOptions {
            fw_mark: false,
            interface_index: None,
        };
        let awg = AmneziaWgTransport::new(
            NativeUdpTransport::connect(addr, opts.clone())
                .await
                .unwrap(),
            params,
        )
        .unwrap();
        let plain = NativeUdpTransport::connect(addr, opts).await.unwrap();
        let mut p_awg = Peer::new_initiator(k_awg, node_pub, None, [0; 3]);
        let mut p_plain = Peer::new_initiator(k_plain, node_pub, None, [0; 3]);

        let s_awg = owner_session(&awg, &mut p_awg, node_id, 41_000).await;
        let s_plain = owner_session(&plain, &mut p_plain, node_id, 41_001).await;
        assert_ne!(s_awg.v4, s_plain.v4);

        // Both clients reach the "Internet" side of the TUN and get replies,
        // each in its own wire encoding.
        for (t, peer, s) in [
            (&awg as &dyn StealthTransport, &mut p_awg, &s_awg),
            (&plain as &dyn StealthTransport, &mut p_plain, &s_plain),
        ] {
            let up = udp_to(s.v4, "203.0.113.5:443", b"up");
            let d = peer.encapsulate(&up, Instant::now());
            for d in d {
                t.send(&d).await.unwrap();
            }
            let mut buf = vec![0u8; 2048];
            let n = tokio::time::timeout(Duration::from_secs(10), inet.read_packet(&mut buf))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(&buf[..n], &up[..]);
            let down = build_udp(
                "203.0.113.5:443".parse().unwrap(),
                SocketAddr::new(IpAddr::V4(s.v4), 5555),
                b"down",
                50,
            )
            .unwrap();
            inet.write_packet(&down).await.unwrap();
            let got = pump(t, peer, Vec::new(), |p| p == &down[..]).await;
            assert_eq!(got, down);

            let ping = echo_v4(s.v4, NODE_GATEWAY_V4, 3, 4, b"loop");
            let d = peer.encapsulate(&ping, Instant::now());
            let rep = pump(t, peer, d, is_vwcp_reply).await;
            assert_eq!(rep, crate::icmp::echo_reply(&ping).unwrap());
        }
        assert_eq!(core.lock().unwrap().admitted_count(), 2);

        tx.send(true).unwrap();
        server.await.unwrap().unwrap();
    }
}
