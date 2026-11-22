//! In-memory test harness: mini VoidWire nodes (vw-wg `Responder` +
//! vw-crypto `ServerHandshake`), a channel transport, a test firewall
//! backend and a test platform. Nothing here touches the host network stack
//! beyond loopback sockets for the DNS vault.

#![allow(dead_code)]

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use tokio::sync::mpsc;
use vw_core::config::{
    Bytes32, Endpoint, NodeDescriptor, NodeKind, NodeRole, TransportKind, WarpAccount,
};
use vw_core::consts::{NODE_GATEWAY_V4, VWCP_PORT};
use vw_core::packet::{build_udp, IpView, PROTO_UDP};
use vw_core::secret::Key32;
use vw_core::transport::{StealthTransport, TunDevice};
use vw_core::{Result, VwError};
use vw_crypto::attest::AttestationReport;
use vw_crypto::identity::NodeIdentity;
use vw_crypto::vwcp::{
    fragment, Assignment, AttestRequest, AttestResponse, MsgType, Reassembler, ServerHandshake,
    TokenGrant,
};
use vw_daemon::platform::{ExecNamespace, NetworkIdentity, Platform};
use vw_dns::{DnsServer, DnsVault};
use vw_firewall::{FirewallBackend, FirewallStatus, LockdownPlan, TunnelIface};
use vw_leakaudit::canary::{EgressOutcome, EgressProbe};
use vw_stealth::{ConnectOptions, SocketOptions};
use vw_wg::{Admission, Decapsulated, Responder, Routed, VirtualTunChannel};

pub fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

// ───────────────────────────── transport ─────────────────────────────

pub struct ChanTransport {
    tx: mpsc::UnboundedSender<Vec<u8>>,
    rx: tokio::sync::Mutex<mpsc::UnboundedReceiver<Vec<u8>>>,
    remote: SocketAddr,
    kind: TransportKind,
}

#[async_trait]
impl StealthTransport for ChanTransport {
    async fn send(&self, d: &[u8]) -> Result<()> {
        self.tx
            .send(d.to_vec())
            .map_err(|_| VwError::Transport("closed".into()))
    }
    async fn recv(&self, buf: &mut [u8]) -> Result<usize> {
        let d = self
            .rx
            .lock()
            .await
            .recv()
            .await
            .ok_or_else(|| VwError::Transport("closed".into()))?;
        buf[..d.len()].copy_from_slice(&d);
        Ok(d.len())
    }
    fn kind(&self) -> TransportKind {
        self.kind
    }
    fn remote_addr(&self) -> SocketAddr {
        self.remote
    }
}

// ───────────────────────────── mini node ─────────────────────────────

pub type Sink = Arc<dyn Fn(Vec<u8>) + Send + Sync>;

struct NodeState {
    responder: Responder,
    reasm: HashMap<[u8; 32], Reassembler>,
    pending: HashMap<[u8; 32], ServerHandshake>,
    sinks: HashMap<[u8; 32], Sink>,
    next_ip: u8,
}

pub struct MiniNode {
    pub name: String,
    pub addr: SocketAddr,
    pub identity: NodeIdentity,
    pub wg_public: [u8; 32],
    state: Mutex<NodeState>,
    pub seen_user: Mutex<Vec<Vec<u8>>>,
    pub vwcp_sessions: AtomicUsize,
    pub attestations: AtomicUsize,
    pub killed: AtomicBool,
    pub kill_notify: tokio::sync::Notify,
    net: std::sync::Weak<Net>,
}

#[derive(Default)]
pub struct Net {
    pub nodes: Mutex<Vec<Arc<MiniNode>>>,
}

impl Net {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    pub fn add_node(self: &Arc<Self>, name: &str, last_octet: u8) -> Arc<MiniNode> {
        let key = vw_wg::generate_private_key();
        let n = Arc::new(MiniNode {
            name: name.into(),
            addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, last_octet)), 51820),
            identity: NodeIdentity::generate(),
            wg_public: vw_wg::public_key(&key),
            state: Mutex::new(NodeState {
                responder: Responder::new(key, Admission::AcceptUnknown { max_unknown: 16 }),
                reasm: HashMap::new(),
                pending: HashMap::new(),
                sinks: HashMap::new(),
                next_ip: 2,
            }),
            seen_user: Mutex::new(Vec::new()),
            vwcp_sessions: AtomicUsize::new(0),
            attestations: AtomicUsize::new(0),
            killed: AtomicBool::new(false),
            kill_notify: tokio::sync::Notify::new(),
            net: Arc::downgrade(self),
        });
        lock(&self.nodes).push(n.clone());
        let weak = Arc::downgrade(&n);
        tokio::spawn(async move {
            let mut iv = tokio::time::interval(Duration::from_millis(50));
            loop {
                iv.tick().await;
                let Some(n) = weak.upgrade() else { return };
                let mut st = lock(&n.state);
                let out = st.responder.tick(Instant::now());
                for (k, v) in out {
                    if let Some(s) = st.sinks.get(&k).cloned() {
                        for d in v {
                            s(d);
                        }
                    }
                }
            }
        });
        n
    }

    pub fn find(&self, addr: SocketAddr) -> Option<Arc<MiniNode>> {
        lock(&self.nodes).iter().find(|n| n.addr == addr).cloned()
    }
}

impl MiniNode {
    pub fn descriptor(&self) -> NodeDescriptor {
        NodeDescriptor {
            version: 1,
            name: self.name.clone(),
            kind: NodeKind::Voidwire,
            role: NodeRole::Both,
            wg_public_key: Bytes32(self.wg_public),
            identity_key: Some(self.identity.public()),
            endpoints: vec![Endpoint {
                transport: TransportKind::NativeUdp,
                host: self.addr.ip().to_string(),
                port: self.addr.port(),
                sni: None,
                path: None,
                cert_sha256: None,
            }],
            amnezia: None,
            country: Some("CH".into()),
            ipv6_exit: false,
            static_v4: None,
            static_v6: None,
            reserved: None,
            static_psk: None,
            token_keys: Vec::new(),
            client_private: None,
        }
    }

    pub fn kill(&self) {
        self.killed.store(true, Ordering::SeqCst);
        self.kill_notify.notify_waiters();
    }

    /// One WireGuard datagram from a client (or a forwarding hop).
    pub fn on_datagram(self: &Arc<Self>, d: Vec<u8>, sink: Sink) {
        let mut forwards = Vec::new();
        {
            let mut st = lock(&self.state);
            let now = Instant::now();
            match st.responder.decapsulate(None, &d, now) {
                Ok(Routed {
                    peer: Some(k),
                    result,
                }) => {
                    st.sinks.insert(k, sink.clone());
                    match result {
                        Decapsulated::Network(v) => v.into_iter().for_each(|x| sink(x)),
                        Decapsulated::Tunnel(pkt) => {
                            let (replies, fwd) = self.handle_ip(&mut st, k, pkt);
                            for r in replies {
                                if let Ok(enc) = st.responder.encapsulate(&k, &r, now) {
                                    enc.into_iter().for_each(|x| sink(x));
                                }
                            }
                            forwards.extend(fwd.into_iter().map(|f| (f.0, f.1, f.2, k)));
                        }
                        _ => {}
                    }
                }
                Ok(Routed {
                    peer: None,
                    result: Decapsulated::Network(v),
                }) => v.into_iter().for_each(|x| sink(x)),
                _ => {}
            }
        }
        for (target, payload, client_src, key) in forwards {
            let me = self.clone();
            let from = target.addr;
            let back: Sink = Arc::new(move |dgram: Vec<u8>| {
                let Ok(wrapped) = build_udp(from, client_src, &dgram, 64) else {
                    return;
                };
                let mut st = lock(&me.state);
                let sink = st.sinks.get(&key).cloned();
                let enc = st.responder.encapsulate(&key, &wrapped, Instant::now());
                drop(st);
                if let (Some(s), Ok(enc)) = (sink, enc) {
                    enc.into_iter().for_each(|x| s(x));
                }
            });
            target.on_datagram(payload, back);
        }
    }

    #[allow(clippy::type_complexity)]
    fn handle_ip(
        &self,
        st: &mut NodeState,
        key: [u8; 32],
        pkt: Vec<u8>,
    ) -> (Vec<Vec<u8>>, Vec<(Arc<MiniNode>, Vec<u8>, SocketAddr)>) {
        let Ok(v) = IpView::parse(&pkt) else {
            return (vec![], vec![]);
        };
        let gw = SocketAddr::new(IpAddr::V4(NODE_GATEWAY_V4), VWCP_PORT);
        if v.protocol == PROTO_UDP && v.dst_sock(&pkt) == Some(gw) {
            let src = v.src_sock(&pkt).expect("udp has ports");
            let payload = v.udp_payload(&pkt).unwrap_or_default().to_vec();
            let out = self.vwcp(st, key, &payload);
            return (
                out.into_iter()
                    .filter_map(|d| build_udp(gw, src, &d, 64).ok())
                    .collect(),
                vec![],
            );
        }
        if v.dst == IpAddr::V4(NODE_GATEWAY_V4) {
            return (
                vw_daemon::util::icmp_reply_for(&pkt).into_iter().collect(),
                vec![],
            );
        }
        if v.protocol == PROTO_UDP {
            if let Some(dst) = v.dst_sock(&pkt) {
                if let Some(next) = self.net.upgrade().and_then(|n| n.find(dst)) {
                    let src = v.src_sock(&pkt).expect("udp has ports");
                    let payload = v.udp_payload(&pkt).unwrap_or_default().to_vec();
                    return (vec![], vec![(next, payload, src)]);
                }
            }
        }
        lock(&self.seen_user).push(pkt);
        (vec![], vec![])
    }

    fn vwcp(&self, st: &mut NodeState, key: [u8; 32], d: &[u8]) -> Vec<Vec<u8>> {
        let msg = st.reasm.entry(key).or_default().push(d, Instant::now());
        let Ok(Some(m)) = msg else { return vec![] };
        match m.ty {
            MsgType::ClientHello => {
                match ServerHandshake::on_client_hello(&self.identity, &m.body, |_| {
                    Ok(TokenGrant {
                        tier: 0,
                        bandwidth_bps: 0,
                    })
                }) {
                    Ok((hs, dgs)) => {
                        st.pending.insert(key, hs);
                        dgs
                    }
                    Err(_) => vec![],
                }
            }
            MsgType::ClientKem => {
                let Some(hs) = st.pending.remove(&key) else {
                    return vec![];
                };
                let ip = Ipv4Addr::new(100, 96, 0, st.next_ip);
                st.next_ip = st.next_ip.wrapping_add(1).max(2);
                match hs.on_client_kem(&m.body, Assignment::host(ip, Ipv6Addr::UNSPECIFIED)) {
                    Ok((session, dgs)) => {
                        if let Some(p) = st.responder.peer_mut(&key) {
                            p.set_psk(session.psk.clone());
                        }
                        self.vwcp_sessions.fetch_add(1, Ordering::SeqCst);
                        dgs
                    }
                    Err(_) => vec![],
                }
            }
            MsgType::AttestRequest => {
                let Ok(req) = AttestRequest::decode(&m.body) else {
                    return vec![];
                };
                let r = AttestationReport {
                    binary_blake3: "a".repeat(64),
                    swap_disabled: true,
                    logging_off: true,
                    ram_only: true,
                    uptime_secs: 1,
                    unix_time: vw_daemon::util::unix_now(),
                    nonce: req.nonce,
                    node_identity: self.identity.public(),
                };
                self.attestations.fetch_add(1, Ordering::SeqCst);
                let att = r.sign(&self.identity).expect("sign");
                AttestResponse { attestation: att }
                    .datagrams()
                    .unwrap_or_default()
            }
            _ => fragment(MsgType::Error, &[0, 1, 0]).unwrap_or_default(),
        }
    }
}

// ───────────────────────────── firewall ─────────────────────────────

#[derive(Debug, Clone, PartialEq)]
pub enum FwOp {
    Arm(LockdownPlan),
    Update(LockdownPlan),
    Disarm,
}

pub struct TestFirewall {
    pub log: Arc<Mutex<Vec<String>>>,
    pub ops: Arc<Mutex<Vec<FwOp>>>,
    plan: Option<LockdownPlan>,
}

impl FirewallBackend for TestFirewall {
    fn name(&self) -> &'static str {
        "test"
    }
    fn arm(&mut self, plan: &LockdownPlan) -> Result<()> {
        plan.validate()?;
        lock(&self.log).push("fw-arm".into());
        lock(&self.ops).push(FwOp::Arm(plan.clone()));
        self.plan = Some(plan.clone());
        Ok(())
    }
    fn update(&mut self, plan: &LockdownPlan) -> Result<()> {
        plan.validate()?;
        assert!(self.plan.is_some(), "update before arm");
        lock(&self.log).push("fw-update".into());
        lock(&self.ops).push(FwOp::Update(plan.clone()));
        self.plan = Some(plan.clone());
        Ok(())
    }
    fn disarm(&mut self) -> Result<()> {
        lock(&self.log).push("fw-disarm".into());
        lock(&self.ops).push(FwOp::Disarm);
        self.plan = None;
        Ok(())
    }
    fn status(&self) -> Result<FirewallStatus> {
        Ok(FirewallStatus::from_plan(
            "test",
            self.plan.as_ref(),
            self.plan.is_some(),
            true,
        ))
    }
    fn is_armed_in_kernel(&self) -> Result<bool> {
        Ok(self.plan.is_some())
    }
}

// ───────────────────────────── platform ─────────────────────────────

pub struct TestPlatform {
    pub net: Arc<Net>,
    pub dir: PathBuf,
    pub log: Arc<Mutex<Vec<String>>>,
    pub fw_ops: Arc<Mutex<Vec<FwOp>>>,
    pub leak: AtomicBool,
    pub vault_addr: Mutex<Option<SocketAddr>>,
    pub tun_apps: Mutex<Vec<Arc<VirtualTunChannel>>>,
    pub routes: Mutex<Vec<String>>,
}

impl TestPlatform {
    pub fn new(net: Arc<Net>) -> Arc<Self> {
        let dir = std::env::temp_dir().join(format!(
            "vwd-test-{}",
            hex::encode(rand::random::<[u8; 6]>())
        ));
        std::fs::create_dir_all(&dir).unwrap();
        Arc::new(Self {
            net,
            dir,
            log: Arc::default(),
            fw_ops: Arc::default(),
            leak: AtomicBool::new(false),
            vault_addr: Mutex::new(None),
            tun_apps: Mutex::new(Vec::new()),
            routes: Mutex::new(Vec::new()),
        })
    }

    pub fn log(&self) -> Vec<String> {
        lock(&self.log).clone()
    }

    pub fn last_plan(&self) -> Option<LockdownPlan> {
        lock(&self.fw_ops).iter().rev().find_map(|o| match o {
            FwOp::Arm(p) | FwOp::Update(p) => Some(p.clone()),
            FwOp::Disarm => None,
        })
    }

    pub fn armed(&self) -> bool {
        matches!(
            lock(&self.fw_ops).last(),
            Some(FwOp::Arm(_) | FwOp::Update(_))
        )
    }

    pub fn app(&self) -> Arc<VirtualTunChannel> {
        lock(&self.tun_apps).last().cloned().expect("tun created")
    }
}

#[async_trait]
impl Platform for TestPlatform {
    fn label(&self) -> String {
        "test".into()
    }
    fn firewall(&self) -> Box<dyn FirewallBackend> {
        Box::new(TestFirewall {
            log: self.log.clone(),
            ops: self.fw_ops.clone(),
            plan: None,
        })
    }
    fn state_dir(&self) -> PathBuf {
        self.dir.clone()
    }
    fn daemon_exe(&self) -> Option<PathBuf> {
        None
    }
    async fn socket_options(&self) -> SocketOptions {
        SocketOptions::default()
    }
    async fn connect(
        &self,
        _ep: &Endpoint,
        opts: &ConnectOptions,
    ) -> Result<Box<dyn StealthTransport>> {
        let addr = opts
            .resolved
            .ok_or_else(|| VwError::Config("unresolved".into()))?;
        lock(&self.log).push("connect".into());
        let node = self
            .net
            .find(addr)
            .filter(|n| !n.killed.load(Ordering::SeqCst))
            .ok_or_else(|| VwError::Transport("unreachable".into()))?;
        let (to_node, mut node_rx) = mpsc::unbounded_channel::<Vec<u8>>();
        let (to_client, client_rx) = mpsc::unbounded_channel::<Vec<u8>>();
        let sink: Sink = {
            let tx = Mutex::new(Some(to_client));
            let n = node.clone();
            Arc::new(move |d| {
                let mut g = lock(&tx);
                if n.killed.load(Ordering::SeqCst) {
                    *g = None;
                }
                if let Some(t) = g.as_ref() {
                    let _ = t.send(d);
                }
            })
        };
        tokio::spawn(async move {
            loop {
                let d = tokio::select! {
                    d = node_rx.recv() => d,
                    _ = node.kill_notify.notified() => None,
                };
                match d {
                    Some(d) if !node.killed.load(Ordering::SeqCst) => {
                        node.on_datagram(d, sink.clone())
                    }
                    _ => {
                        // Drops the client-bound sender: the transport closes.
                        sink(Vec::new());
                        return;
                    }
                }
            }
        });
        Ok(Box::new(ChanTransport {
            tx: to_node,
            rx: tokio::sync::Mutex::new(client_rx),
            remote: addr,
            kind: TransportKind::NativeUdp,
        }))
    }
    async fn resolve(&self, _host: &str, _marked: bool) -> Result<Vec<IpAddr>> {
        Err(VwError::Dns("no resolver in tests".into()))
    }
    fn create_tun(&self, cfg: &vw_wg::OsTunConfig) -> Result<(Arc<dyn TunDevice>, TunnelIface)> {
        lock(&self.log).push("tun".into());
        let (app, dev) = VirtualTunChannel::pair(cfg.mtu);
        lock(&self.tun_apps).push(Arc::new(app));
        let mut iface = TunnelIface::new("vwtest0");
        iface.v4 = cfg.ipv4;
        iface.v6 = cfg.ipv6;
        Ok((Arc::new(dev), iface))
    }
    async fn install_routes(&self, tun: &TunnelIface, pinned: &[IpAddr], _v6: bool) -> Result<()> {
        lock(&self.log).push("routes".into());
        lock(&self.routes).push(format!("{} {:?}", tun.name, pinned));
        Ok(())
    }
    async fn restore_routes(&self) -> Result<()> {
        lock(&self.routes).clear();
        Ok(())
    }
    async fn apply_dns(&self, _tun: &TunnelIface) -> Result<()> {
        lock(&self.log).push("dns".into());
        Ok(())
    }
    async fn restore_dns(&self) -> Result<()> {
        lock(&self.log).push("dns-restore".into());
        Ok(())
    }
    async fn start_vault(
        &self,
        vault: Arc<DnsVault>,
        _tun: &TunnelIface,
    ) -> Result<Vec<DnsServer>> {
        let s = vw_dns::serve_udp(vault, "127.0.0.1:0".parse().unwrap()).await?;
        *lock(&self.vault_addr) = Some(s.local_addr());
        Ok(vec![s])
    }
    async fn flush_caches(&self) -> Result<()> {
        lock(&self.log).push("flush".into());
        Ok(())
    }
    async fn network_identity(&self, _probe: IpAddr) -> NetworkIdentity {
        NetworkIdentity {
            gateway: Some("192.168.1.1".parse().unwrap()),
            gateway_mac: Some("aa:bb:cc:dd:ee:ff".into()),
            ssid: Some("test".into()),
            interface: Some("en-test".into()),
            interface_index: Some(9),
        }
    }
    async fn egress_probe(&self, _probe: &EgressProbe) -> EgressOutcome {
        if self.leak.load(Ordering::SeqCst) {
            EgressOutcome::Reached(42)
        } else {
            EgressOutcome::Blocked("EPERM".into())
        }
    }
    async fn system_resolve(&self, name: &str) -> bool {
        // Stand-in for the OS resolver pointed at the vault.
        let Some(addr) = *lock(&self.vault_addr) else {
            return false;
        };
        let Ok(s) = tokio::net::UdpSocket::bind("127.0.0.1:0").await else {
            return false;
        };
        let q = vw_leakaudit::canary::dns_query(name, 7);
        if s.send_to(&q, addr).await.is_err() {
            return false;
        }
        let mut buf = [0u8; 1500];
        tokio::time::timeout(Duration::from_secs(2), s.recv_from(&mut buf))
            .await
            .is_ok()
    }
    async fn https_trace(&self, _marked: bool) -> Result<String> {
        Err(VwError::Transport("no internet in tests".into()))
    }
    async fn warp_register(&self, _pins: Vec<SocketAddr>, _marked: bool) -> Result<WarpAccount> {
        Err(VwError::Transport("no WARP in tests".into()))
    }
    async fn warp_delete(&self, _a: &WarpAccount, _p: Vec<SocketAddr>, _m: bool) -> Result<()> {
        Ok(())
    }
    async fn exec_namespace(
        &self,
        _id: &str,
        _v4: (Ipv4Addr, u8),
        _mtu: u16,
    ) -> Result<Option<ExecNamespace>> {
        Ok(None)
    }
}

/// A controller over the test platform with `nodes` imported.
pub async fn controller(
    platform: &Arc<TestPlatform>,
    nodes: &[Arc<MiniNode>],
) -> Arc<vw_daemon::controller::Controller> {
    let mut store = vw_daemon::store::Store::in_memory(&platform.dir.join("store.json"));
    for n in nodes {
        store.upsert_node(n.descriptor()).unwrap();
    }
    let c = vw_daemon::controller::Controller::new(platform.clone(), store);
    c.start().await.unwrap();
    c
}

pub fn key32() -> Key32 {
    Key32::random()
}

/// Read the next packet from a TUN app side with a timeout.
pub async fn read_tun(t: &VirtualTunChannel, ms: u64) -> Option<Vec<u8>> {
    let mut buf = vec![0u8; 2048];
    match tokio::time::timeout(Duration::from_millis(ms), t.read_packet(&mut buf)).await {
        Ok(Ok(n)) => Some(buf[..n].to_vec()),
        _ => None,
    }
}
