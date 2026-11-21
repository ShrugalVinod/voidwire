//! Multi-hop cascade over in-memory WireGuard nodes. Each node is a
//! `Responder`; a node that decrypts a UDP packet addressed to the next hop's
//! endpoint forwards its payload from its own egress address (NAT), exactly
//! like `voidwire-node` does.

use std::net::SocketAddr;
use std::time::Instant;

use vw_core::packet::{build_udp, IpView, PROTO_UDP};
use vw_wg::{
    generate_private_key, public_key, Admission, Cascade, CascadeHop, Decapsulated, Peer, Responder,
};

struct Net {
    servers: Vec<Responder>,
    /// The client's static public key at each hop (distinct per hop).
    client_keys: Vec<[u8; 32]>,
    /// Public WireGuard endpoint of each hop.
    endpoints: Vec<SocketAddr>,
    /// Source address each hop uses when forwarding (NAT egress).
    egress: Vec<SocketAddr>,
    /// The client's tunnel address inside each hop.
    tunnel_addr: Vec<SocketAddr>,
    /// Plaintext each hop decrypted, and the wire sources it saw.
    seen_plain: Vec<Vec<Vec<u8>>>,
    seen_src: Vec<Vec<SocketAddr>>,
    now: Instant,
}

const CLIENT_OUTER: &str = "198.51.100.7:40000";

fn client_outer() -> SocketAddr {
    CLIENT_OUTER.parse().unwrap()
}

impl Net {
    fn build(hops: usize) -> (Net, Cascade) {
        let mut servers = Vec::new();
        let mut client_keys = Vec::new();
        let mut cascade_hops = Vec::new();
        let endpoints: Vec<SocketAddr> = (0..hops)
            .map(|i| format!("203.0.113.{}:51820", 10 + i).parse().unwrap())
            .collect();
        let egress: Vec<SocketAddr> = (0..hops)
            .map(|i| format!("192.0.2.{}:50000", 10 + i).parse().unwrap())
            .collect();
        let tunnel_addr: Vec<SocketAddr> = (0..hops)
            .map(|i| format!("100.96.0.{}:41000", 2 + i).parse().unwrap())
            .collect();
        for i in 0..hops {
            let sk = generate_private_key();
            let ck = generate_private_key();
            client_keys.push(public_key(&ck));
            let peer = Peer::new_initiator(ck, public_key(&sk), None, [0; 3]);
            let via = if i == 0 {
                client_outer()
            } else {
                tunnel_addr[i - 1]
            };
            cascade_hops.push(CascadeHop::new(peer, endpoints[i], via));
            servers.push(Responder::new(
                sk,
                Admission::AcceptUnknown { max_unknown: 8 },
            ));
        }
        let net = Net {
            servers,
            client_keys,
            endpoints,
            egress,
            tunnel_addr,
            seen_plain: vec![Vec::new(); hops],
            seen_src: vec![Vec::new(); hops],
            now: Instant::now(),
        };
        (net, Cascade::new(cascade_hops).unwrap())
    }

    /// Deliver `d` to hop `i` from `src`; returns wire datagrams for the client.
    fn deliver_to_hop(&mut self, i: usize, src: SocketAddr, d: &[u8]) -> Vec<Vec<u8>> {
        self.seen_src[i].push(src);
        let r = self.servers[i]
            .decapsulate(Some(src), d, self.now)
            .expect("hop accepts datagram");
        match r.result {
            Decapsulated::Network(v) => self.back(i, v),
            Decapsulated::Tunnel(pkt) => {
                self.seen_plain[i].push(pkt.clone());
                let v = IpView::parse(&pkt).unwrap();
                if i + 1 < self.servers.len()
                    && v.protocol == PROTO_UDP
                    && v.dst_sock(&pkt) == Some(self.endpoints[i + 1])
                {
                    let payload = v.udp_payload(&pkt).unwrap().to_vec();
                    let egress = self.egress[i];
                    self.deliver_to_hop(i + 1, egress, &payload)
                } else {
                    Vec::new()
                }
            }
            _ => Vec::new(),
        }
    }

    /// Send datagrams produced by hop `i` (addressed to the client) back down.
    fn back(&mut self, i: usize, v: Vec<Vec<u8>>) -> Vec<Vec<u8>> {
        if i == 0 {
            return v;
        }
        let mut out = Vec::new();
        for d in v {
            let wrapped = build_udp(self.endpoints[i], self.tunnel_addr[i - 1], &d, 64).unwrap();
            let key = self.client_keys[i - 1];
            let enc = self.servers[i - 1]
                .encapsulate(&key, &wrapped, self.now)
                .unwrap();
            out.extend(self.back(i - 1, enc));
        }
        out
    }

    fn tick_servers(&mut self) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        for i in 0..self.servers.len() {
            let t = self.servers[i].tick(self.now);
            for (_, v) in t {
                out.extend(self.back(i, v));
            }
        }
        out
    }

    /// Run the client and network until quiet. Returns delivered plaintext.
    fn run(&mut self, client: &mut Cascade, mut to_net: Vec<Vec<u8>>) -> Vec<(usize, Vec<u8>)> {
        let mut delivered = Vec::new();
        for _ in 0..32 {
            let mut to_client = Vec::new();
            for d in to_net.drain(..) {
                to_client.extend(self.deliver_to_hop(0, client_outer(), &d));
            }
            to_client.extend(self.tick_servers());
            for d in to_client {
                let o = client.decapsulate(&d, self.now);
                assert_eq!(o.errors, 0);
                to_net.extend(o.network);
                delivered.extend(o.delivered);
            }
            to_net.extend(client.tick(self.now));
            if to_net.is_empty() {
                break;
            }
        }
        delivered
    }
}

fn user_packet(src: SocketAddr, n: u8) -> Vec<u8> {
    build_udp(src, "93.184.216.34:443".parse().unwrap(), &[n; 200], 64).unwrap()
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

#[test]
fn two_hop_split_trust() {
    let (mut net, mut client) = Net::build(2);
    let first = client.tick(net.now);
    net.run(&mut client, first);
    assert!(
        client.established(),
        "both hops handshake through the cascade"
    );

    // User traffic: source is the client's address inside Hop 2.
    let inner_src = net.tunnel_addr[1];
    for n in 0..5 {
        let d = client.encapsulate(&user_packet(inner_src, n), net.now);
        net.run(&mut client, d);
    }
    let dest = [93u8, 184, 216, 34];

    // Hop 1 only ever sees UDP to Hop 2's endpoint, never the destination.
    assert!(!net.seen_plain[0].is_empty());
    for pkt in &net.seen_plain[0] {
        let v = IpView::parse(pkt).unwrap();
        assert_eq!(v.protocol, PROTO_UDP);
        assert_eq!(v.dst_sock(pkt), Some(net.endpoints[1]));
        assert!(!contains(pkt, &dest));
    }
    // Hop 2 sees the destination but never the client's outer address.
    let at_hop2: Vec<_> = net.seen_plain[1]
        .iter()
        .filter(|p| IpView::parse(p).unwrap().dst.to_string() == "93.184.216.34")
        .collect();
    assert_eq!(at_hop2.len(), 5);
    for pkt in &net.seen_plain[1] {
        let v = IpView::parse(pkt).unwrap();
        assert_ne!(v.src, client_outer().ip());
        assert!(!contains(pkt, &[198, 51, 100, 7]));
    }
    assert!(net.seen_src[1].iter().all(|s| *s == net.egress[0]));
    assert!(!net.seen_src[1].contains(&client_outer()));

    // Return path: Hop 2 answers, the client receives it at the innermost hop.
    let reply = build_udp("93.184.216.34:443".parse().unwrap(), inner_src, b"pong", 64).unwrap();
    let key = net.client_keys[1];
    let enc = net.servers[1].encapsulate(&key, &reply, net.now).unwrap();
    let wire = net.back(1, enc);
    let mut delivered = Vec::new();
    for d in wire {
        delivered.extend(client.decapsulate(&d, net.now).delivered);
    }
    assert_eq!(delivered, vec![(1, reply)]);
}

#[test]
fn three_hops_and_hop_control_traffic() {
    let (mut net, mut client) = Net::build(3);
    let first = client.tick(net.now);
    net.run(&mut client, first);
    assert!(client.established());
    assert!(client.handshakes_completed() >= 3);

    let inner_src = net.tunnel_addr[2];
    let d = client.encapsulate(&user_packet(inner_src, 9), net.now);
    net.run(&mut client, d);
    assert!(net.seen_plain[2].contains(&user_packet(inner_src, 9)));
    for hop in 0..2 {
        for pkt in &net.seen_plain[hop] {
            let v = IpView::parse(pkt).unwrap();
            assert_eq!(v.dst_sock(pkt), Some(net.endpoints[hop + 1]));
        }
    }

    // Reply from the exit travels back through all three hops.
    let reply = build_udp("93.184.216.34:443".parse().unwrap(), inner_src, b"r", 64).unwrap();
    let key = net.client_keys[2];
    let enc = net.servers[2].encapsulate(&key, &reply, net.now).unwrap();
    let wire = net.back(2, enc);
    let got: Vec<_> = wire
        .iter()
        .flat_map(|d| client.decapsulate(d, net.now).delivered)
        .collect();
    assert_eq!(got, vec![(2, reply)]);

    // Control traffic for Hop 1's own gateway (e.g. VWCP) stops at Hop 1.
    let gw = build_udp(
        net.tunnel_addr[0],
        "100.96.0.1:51821".parse().unwrap(),
        b"VWCP",
        64,
    )
    .unwrap();
    let d = client.encapsulate_at(0, &gw, net.now);
    net.run(&mut client, d);
    assert!(net.seen_plain[0].contains(&gw));
    assert!(!net.seen_plain[1].contains(&gw));
    // And a gateway answer is delivered tagged with hop 0.
    let key = net.client_keys[0];
    let ans = build_udp(
        "100.96.0.1:51821".parse().unwrap(),
        net.tunnel_addr[0],
        b"ack",
        64,
    )
    .unwrap();
    let enc = net.servers[0].encapsulate(&key, &ans, net.now).unwrap();
    let got: Vec<_> = enc
        .iter()
        .flat_map(|d| client.decapsulate(d, net.now).delivered)
        .collect();
    assert_eq!(got, vec![(0, ans)]);
}

#[test]
fn empty_cascade_rejected() {
    assert!(Cascade::new(Vec::new()).is_err());
}
