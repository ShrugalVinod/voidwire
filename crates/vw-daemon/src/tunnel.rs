//! Building and running one tunnel: transport → cascade → WireGuard
//! handshakes per hop → VWCP PQ handshake per VoidWire hop (inside that hop's
//! session) → PSK install + rehandshake. Also PQ rotation and teardown.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use vw_core::config::{Bytes32, DaitaParams, NodeKind, SanitizerSettings, TransportKind};
use vw_core::consts::{DEFAULT_NODE_UDP_PORT, PROVISIONAL_V4};
use vw_core::secret::Key32;
use vw_core::telemetry::Counters;
use vw_core::transport::{StealthTransport, TunDevice};
use vw_core::{Result, VwError};
use vw_crypto::vwcp::PqSession;
use vw_dns::{DnsServer, DnsVault};
use vw_firewall::TunnelIface;
use vw_stealth::{ConnectOptions, DaitaTransport, SocketOptions};
use vw_wg::{
    Cascade, CascadeHop, DriverConfig, DriverHandle, Engine, EngineChaff, Sanitizer, TunnelDriver,
};

use crate::link::{vwcp_handshake, TunnelLink};
use crate::optimizer::{peer_for, Candidate, Keys, RankedPath};
use crate::pipeline::{ControlBus, Gate, MuxTun, Pipeline};
use crate::platform::{ExecNamespace, Platform};
use crate::util::{ephemeral_port, unix_now};

/// Per-step timeout of the connect sequence.
pub const STEP_TIMEOUT: Duration = Duration::from_secs(10);
/// Persistent keepalive on the entry hop (NAT upkeep, liveness).
pub const ENTRY_KEEPALIVE: Duration = Duration::from_secs(10);

/// Everything needed to build a tunnel.
pub struct TunnelSpec {
    pub path: RankedPath,
    pub keys: Keys,
    pub mtu: u16,
    pub daita: Option<DaitaParams>,
    pub sanitizer: SanitizerSettings,
    pub block_stun: bool,
    pub vault: Option<Arc<DnsVault>>,
    pub socket: SocketOptions,
    /// VWCP token per hop (ignored for non-VoidWire hops).
    pub tokens: Vec<Vec<u8>>,
    /// PQ PSKs still installed at nodes from the tunnel being replaced
    /// (keyed by node WireGuard key), so their first handshake succeeds.
    pub known_psks: Vec<(Bytes32, Key32)>,
}

/// State of one hop.
#[derive(Debug, Clone)]
pub struct HopState {
    pub cand: Candidate,
    pub pq: Option<PqInfo>,
    pub src_port: u16,
    pub rtt_ms: Option<f64>,
    /// Current PQ PSK (zeroized on drop, redacted in Debug).
    pub psk: Option<Key32>,
}

/// Non-secret part of a VWCP session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PqInfo {
    pub epoch: u32,
    pub v4: Ipv4Addr,
    pub v4_prefix: u8,
    pub v6: Ipv6Addr,
    pub v6_prefix: u8,
    pub rotate_secs: u16,
}

impl From<&PqSession> for PqInfo {
    fn from(s: &PqSession) -> Self {
        Self {
            epoch: s.epoch,
            v4: s.v4,
            v4_prefix: s.v4_prefix,
            v6: s.v6,
            v6_prefix: s.v6_prefix,
            rotate_secs: s.rotate_secs,
        }
    }
}

/// A running tunnel.
pub struct ActiveTunnel {
    pub engine: Arc<Mutex<Cascade>>,
    pub transport: Arc<dyn StealthTransport>,
    pub mux: Arc<MuxTun>,
    pub pipeline: Arc<Pipeline>,
    pub bus: ControlBus,
    driver: Option<DriverHandle>,
    pub hops: Vec<HopState>,
    pub path: RankedPath,
    pub mtu: u16,
    pub daita: bool,
    pub tun_v4: (Ipv4Addr, u8),
    pub tun_v6: Option<(Ipv6Addr, u8)>,
    pub entry_addr: SocketAddr,
    pub iface: Option<TunnelIface>,
    pub os_tun: Option<Arc<dyn TunDevice>>,
    pub vault_servers: Vec<DnsServer>,
    pub exec: Vec<(usize, ExecNamespace)>,
    pub started: Instant,
    pub last_rotation: Option<Instant>,
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

/// Wait (polling the sans-IO engine) until `cond` holds or `timeout` passes.
pub async fn wait_engine(
    engine: &Arc<Mutex<Cascade>>,
    timeout: Duration,
    cond: impl Fn(&Cascade) -> bool,
) -> Result<()> {
    let deadline = tokio::time::Instant::now() + timeout;
    let mut iv = tokio::time::interval(Duration::from_millis(10));
    loop {
        if cond(&lock(engine)) {
            return Ok(());
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(VwError::Timeout);
        }
        iv.tick().await;
    }
}

/// UDP endpoint of an inner hop as reached from inside the previous hop.
fn inner_endpoint(c: &Candidate) -> SocketAddr {
    let addr = c.addr.expect("candidates are resolved before use");
    if c.transport() == TransportKind::NativeUdp {
        return addr;
    }
    let port = c
        .node
        .endpoint_for(TransportKind::NativeUdp)
        .map(|e| e.port)
        .unwrap_or(DEFAULT_NODE_UDP_PORT);
    SocketAddr::new(addr.ip(), port)
}

/// Our address inside hop `c` before VWCP assigns one.
fn initial_addr(c: &Candidate) -> Ipv4Addr {
    match c.node.kind {
        NodeKind::Voidwire => PROVISIONAL_V4,
        _ => c.node.static_v4.unwrap_or(PROVISIONAL_V4),
    }
}

/// Start epoch: wall-clock seconds, so a reconnect is always above the
/// node's last completed epoch for our key.
pub fn initial_epoch() -> u32 {
    (unix_now() & 0x7fff_ffff) as u32
}

impl ActiveTunnel {
    /// Connect the transport, build the cascade and complete every handshake.
    pub async fn establish(
        platform: &dyn Platform,
        spec: TunnelSpec,
        counters: Arc<Counters>,
        gate: Arc<Gate>,
    ) -> Result<Self> {
        let path = spec.path.clone();
        let entry = &path.hops[0];
        let entry_addr = entry
            .addr
            .ok_or_else(|| VwError::Config("entry endpoint unresolved".into()))?;
        let opts = ConnectOptions {
            amnezia: entry.node.amnezia,
            socket: spec.socket.clone(),
            resolved: Some(entry_addr),
            masque_target: None,
            connect_timeout: STEP_TIMEOUT,
        };
        let raw = tokio::time::timeout(STEP_TIMEOUT, platform.connect(&entry.endpoint, &opts))
            .await
            .map_err(|_| VwError::Timeout)??;

        let mut chops = Vec::new();
        let mut states = Vec::new();
        for (i, c) in path.hops.iter().enumerate() {
            let mut peer = peer_for(&c.node, &spec.keys).with_mtu(spec.mtu);
            if let Some((_, k)) = spec
                .known_psks
                .iter()
                .find(|(n, _)| *n == c.node.wg_public_key)
            {
                peer.set_psk(k.clone());
            }
            if i == 0 {
                peer = peer.with_persistent_keepalive(Some(ENTRY_KEEPALIVE));
            } else {
                peer = peer.with_auto_connect(false);
            }
            let via = if i == 0 {
                SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
            } else {
                SocketAddr::new(
                    IpAddr::V4(initial_addr(&path.hops[i - 1])),
                    ephemeral_port(),
                )
            };
            let endpoint = if i == 0 {
                entry_addr
            } else {
                inner_endpoint(c)
            };
            chops.push(CascadeHop::new(peer, endpoint, via));
            states.push(HopState {
                cand: c.clone(),
                pq: None,
                src_port: ephemeral_port(),
                rtt_ms: None,
                psk: None,
            });
        }
        let engine = Arc::new(Mutex::new(
            Cascade::new(chops).map_err(|e| VwError::Transport(e.to_string()))?,
        ));
        let raw: Arc<dyn StealthTransport> = Arc::from(raw);
        let transport: Arc<dyn StealthTransport> = match &spec.daita {
            Some(p) => Arc::new(DaitaTransport::new(
                raw,
                p.clone(),
                Arc::new(EngineChaff(engine.clone())),
                Some(counters.clone()),
            )),
            None => raw,
        };
        let exit = path.exit();
        let exit_v6 = exit.node.ipv6_exit;
        let mux = MuxTun::new(spec.mtu);
        let bus = ControlBus::new();
        let pipeline = Arc::new(Pipeline::new(
            gate,
            spec.block_stun,
            spec.vault.clone(),
            exit_v6,
            path.hops.len(),
            counters.clone(),
            bus.clone(),
        ));
        pipeline.set_tun(mux.clone());
        let driver = TunnelDriver::new(engine.clone(), mux.clone(), transport.clone(), counters)
            .with_filter(pipeline.clone())
            .with_config(DriverConfig {
                tick_interval: Duration::from_millis(100),
                sanitizer: Some(Sanitizer::new(spec.sanitizer, spec.mtu)),
                daita: spec.daita.clone(),
            })
            .spawn();
        let mut t = Self {
            engine,
            transport,
            mux,
            pipeline,
            bus,
            driver: Some(driver),
            hops: states,
            path,
            mtu: spec.mtu,
            daita: spec.daita.is_some(),
            tun_v4: (PROVISIONAL_V4, 32),
            tun_v6: None,
            entry_addr,
            iface: None,
            os_tun: None,
            vault_servers: Vec::new(),
            exec: Vec::new(),
            started: Instant::now(),
            last_rotation: None,
        };
        if let Err(e) = t.handshake_all(&spec.tokens).await {
            t.shutdown().await;
            return Err(e);
        }
        Ok(t)
    }

    async fn send_at(&self, hop: usize, pkt: &[u8]) -> Result<()> {
        let d = lock(&self.engine).outbound_at(hop, pkt, Instant::now());
        for x in d {
            if vw_wg::noise::is_handshake_initiation(&x) {
                self.transport.before_handshake().await?;
            }
            self.transport.send(&x).await?;
        }
        Ok(())
    }

    async fn handshake_all(&mut self, tokens: &[Vec<u8>]) -> Result<()> {
        for i in 0..self.hops.len() {
            let start = tokio::time::Instant::now();
            if i > 0 {
                // An empty plaintext queues a keepalive and starts the handshake.
                self.send_at(i, &[]).await?;
            }
            wait_engine(&self.engine, STEP_TIMEOUT, |c| {
                c.hops()[i].peer.session_established()
            })
            .await
            .map_err(|_| {
                VwError::Transport(format!("hop {} WireGuard handshake timed out", i + 1))
            })?;
            self.hops[i].rtt_ms = Some(start.elapsed().as_secs_f64() * 1000.0);
            if self.hops[i].cand.node.kind == NodeKind::Voidwire {
                let token = tokens.get(i).cloned().unwrap_or_default();
                self.pq_handshake(i, initial_epoch(), token).await?;
            }
            if i + 1 < self.hops.len() {
                let a = self.hop_addr(i);
                let mut e = lock(&self.engine);
                if let Some(h) = e.hop_mut(i + 1) {
                    h.via_src.set_ip(IpAddr::V4(a));
                }
            }
        }
        let last = self.hops.len() - 1;
        let exit = &self.hops[last];
        match (&exit.pq, exit.cand.node.kind) {
            (Some(pq), _) => {
                self.tun_v4 = (pq.v4, 32);
                self.tun_v6 =
                    (exit.cand.node.ipv6_exit && !pq.v6.is_unspecified()).then_some((pq.v6, 128));
            }
            (None, _) => {
                let n = &exit.cand.node;
                let v4 = n
                    .static_v4
                    .ok_or_else(|| VwError::Config("exit has no tunnel address".into()))?;
                self.tun_v4 = (v4, 32);
                self.tun_v6 = n.static_v6.filter(|_| n.ipv6_exit).map(|a| (a, 128));
            }
        }
        self.pipeline.set_exit_v6(self.tun_v6.is_some());
        Ok(())
    }

    /// Our address inside hop `i`.
    pub fn hop_addr(&self, i: usize) -> Ipv4Addr {
        self.hops[i]
            .pq
            .map(|p| p.v4)
            .unwrap_or_else(|| initial_addr(&self.hops[i].cand))
    }

    /// VWCP exchange on hop `i`, PSK install and the confirming rehandshake.
    async fn pq_handshake(&mut self, i: usize, epoch: u32, token: Vec<u8>) -> Result<()> {
        let identity = self.hops[i]
            .cand
            .node
            .identity_key
            .ok_or_else(|| VwError::Config("VoidWire node without identity".into()))?;
        let src = SocketAddr::new(IpAddr::V4(self.hop_addr(i)), self.hops[i].src_port);
        let mut link = TunnelLink::new(self.engine.clone(), self.transport.clone(), i, &self.bus);
        let session = vwcp_handshake(&mut link, src, identity, epoch, token, STEP_TIMEOUT).await?;
        let before = lock(&self.engine).hops()[i].peer.handshakes_completed();
        {
            let mut e = lock(&self.engine);
            let h = e
                .hop_mut(i)
                .ok_or_else(|| VwError::Config("hop vanished".into()))?;
            h.peer.set_psk(session.psk.clone());
        }
        self.hops[i].pq = Some(PqInfo::from(&session));
        self.hops[i].psk = Some(session.psk.clone());
        drop(session);
        wait_engine(&self.engine, STEP_TIMEOUT, |c| {
            c.hops()[i].peer.handshakes_completed() > before
        })
        .await
        .map_err(|_| VwError::Transport("rehandshake with the PQ key timed out".into()))
    }

    /// Rotate the PQ PSK on every VoidWire hop (`epoch + 1`).
    pub async fn rotate(&mut self, tokens: &[Vec<u8>]) -> Result<()> {
        for i in 0..self.hops.len() {
            if let Some(pq) = self.hops[i].pq {
                let token = tokens.get(i).cloned().unwrap_or_default();
                self.pq_handshake(i, pq.epoch.wrapping_add(1), token)
                    .await?;
            }
        }
        self.last_rotation = Some(Instant::now());
        Ok(())
    }

    /// PSKs currently installed per node (for a replacement tunnel).
    pub fn psks(&self) -> Vec<(Bytes32, Key32)> {
        self.hops
            .iter()
            .filter_map(|h| h.psk.clone().map(|k| (h.cand.node.wg_public_key, k)))
            .collect()
    }

    /// Smallest PQ rotation interval of the path (node-advertised).
    pub fn rotate_secs(&self, configured: u64) -> u64 {
        self.hops
            .iter()
            .filter_map(|h| h.pq.map(|p| p.rotate_secs as u64))
            .filter(|s| *s > 0)
            .chain(std::iter::once(configured.max(10)))
            .min()
            .unwrap_or(configured)
    }

    /// Create the OS TUN with the assigned address and attach it.
    pub fn attach_os_tun(&mut self, platform: &dyn Platform) -> Result<TunnelIface> {
        let cfg = vw_wg::OsTunConfig {
            mtu: self.mtu,
            ipv4: Some(self.tun_v4),
            ipv6: self.tun_v6,
        };
        let (dev, iface) = platform.create_tun(&cfg)?;
        self.mux.attach(dev.clone());
        self.os_tun = Some(dev);
        self.iface = Some(iface.clone());
        Ok(iface)
    }

    /// Last authenticated packet on the entry hop.
    pub fn last_rx(&self) -> Option<Instant> {
        lock(&self.engine).hops()[0].peer.last_received()
    }

    pub fn driver_finished(&self) -> bool {
        self.driver.as_ref().is_none_or(DriverHandle::is_finished)
    }

    /// Stop everything this tunnel owns.
    pub async fn shutdown(&mut self) {
        if let Some(d) = self.driver.take() {
            if let Err(e) = d.shutdown().await {
                tracing::debug!(error = %e, "driver stopped with error");
            }
        }
        self.vault_servers.clear();
        self.exec.clear();
        let _ = self.transport.close().await;
        self.os_tun = None;
    }
}
