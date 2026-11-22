//! Client packet pipeline (ARCHITECTURE.md §3) as a `vw_wg::PacketFilter`,
//! the multiplexing TUN device and the control-packet bus.
//!
//! Outbound order (after the driver's sanitizer, step 1):
//! gate → STUN filter → DNS interception → IPv6 policy → (driver: DAITA
//! padding, cascade encryption, transport + chaff).
//!
//! The gate drops everything (counting `pre_canary_dropped`) unless the Iron
//! Dome allows traffic, except flows the daemon registered for its own canary
//! probes. In-tunnel control traffic (VWCP from a hop gateway, ICMP echo
//! replies to daemon probes) is diverted to the [`ControlBus`] and never
//! reaches the TUN.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use tokio::sync::{broadcast, mpsc};
use tokio::task::JoinHandle;
use vw_core::consts::{DNS_PORT, DOT_PORT, NODE_GATEWAY_V4, VWCP_PORT};
use vw_core::packet::{IpView, PROTO_ICMP, PROTO_TCP, PROTO_UDP};
use vw_core::telemetry::Counters;
use vw_core::transport::TunDevice;
use vw_core::{Result, VwError};
use vw_dns::{DnsVault, InterceptVerdict};
use vw_firewall::{StunFilter, Verdict};
use vw_wg::{FilterVerdict, PacketFilter};

use crate::util::icmp_echo_fields;

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

/// A flow the daemon may send/receive while the gate is closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Permit {
    /// Our local port (TCP/UDP) or ICMP echo identifier.
    Local { proto: u8, port: u16 },
    /// A remote socket (e.g. the in-tunnel trace server).
    Remote { proto: u8, addr: SocketAddr },
}

/// Traffic gate shared by the controller and the pipeline.
#[derive(Debug, Default)]
pub struct Gate {
    open: AtomicBool,
    permits: Mutex<Vec<(Permit, Instant)>>,
}

impl Gate {
    pub fn set_open(&self, open: bool) {
        self.open.store(open, Ordering::SeqCst);
    }

    pub fn is_open(&self) -> bool {
        self.open.load(Ordering::SeqCst)
    }

    /// Allow a probe flow for `ttl`.
    pub fn permit(&self, p: Permit, ttl: Duration) {
        let mut v = lock(&self.permits);
        let now = Instant::now();
        v.retain(|(_, exp)| *exp > now);
        v.push((p, now + ttl));
    }

    pub fn revoke(&self, p: Permit) {
        lock(&self.permits).retain(|(x, _)| *x != p);
    }

    fn matches(&self, proto: u8, local: u16, remote: Option<SocketAddr>) -> bool {
        let now = Instant::now();
        lock(&self.permits).iter().any(|(p, exp)| {
            *exp > now
                && match p {
                    Permit::Local { proto: pp, port } => *pp == proto && *port == local,
                    Permit::Remote { proto: pp, addr } => *pp == proto && remote == Some(*addr),
                }
        })
    }

    fn permitted(&self, pkt: &[u8], outbound: bool) -> bool {
        let Ok(v) = IpView::parse(pkt) else {
            return false;
        };
        if v.protocol == PROTO_ICMP {
            return icmp_echo_fields(pkt)
                .is_some_and(|(_, id, _)| self.matches(PROTO_ICMP, id, None));
        }
        let Some((sp, dp)) = v.ports(pkt) else {
            return false;
        };
        if outbound {
            self.matches(v.protocol, sp, Some(SocketAddr::new(v.dst, dp)))
        } else {
            self.matches(v.protocol, dp, Some(SocketAddr::new(v.src, sp)))
        }
    }
}

/// In-tunnel control packets `(hop, ip_packet)`.
#[derive(Debug, Clone)]
pub struct ControlBus {
    tx: broadcast::Sender<(usize, Vec<u8>)>,
    icmp_ids: Arc<Mutex<Vec<u16>>>,
}

impl Default for ControlBus {
    fn default() -> Self {
        Self::new()
    }
}

impl ControlBus {
    pub fn new() -> Self {
        Self {
            tx: broadcast::channel(256).0,
            icmp_ids: Arc::default(),
        }
    }

    pub fn subscribe(&self) -> broadcast::Receiver<(usize, Vec<u8>)> {
        self.tx.subscribe()
    }

    /// Divert ICMP echo replies with this identifier to the bus.
    pub fn claim_icmp(&self, id: u16) {
        lock(&self.icmp_ids).push(id);
    }

    pub fn release_icmp(&self, id: u16) {
        lock(&self.icmp_ids).retain(|x| *x != id);
    }

    /// Divert if this is control traffic; returns true when consumed.
    pub fn offer(&self, hop: usize, pkt: &[u8]) -> bool {
        if is_vwcp_reply(pkt)
            || icmp_echo_fields(pkt)
                .is_some_and(|(ty, id, _)| ty == 0 && lock(&self.icmp_ids).contains(&id))
        {
            let _ = self.tx.send((hop, pkt.to_vec()));
            return true;
        }
        false
    }
}

/// UDP from `NODE_GATEWAY_V4:VWCP_PORT`.
pub fn is_vwcp_reply(pkt: &[u8]) -> bool {
    IpView::parse(pkt).is_ok_and(|v| {
        v.protocol == PROTO_UDP
            && v.src == IpAddr::V4(NODE_GATEWAY_V4)
            && v.ports(pkt).is_some_and(|(s, _)| s == VWCP_PORT)
    })
}

/// The daemon's `PacketFilter`.
pub struct Pipeline {
    gate: Arc<Gate>,
    stun: StunFilter,
    vault: Option<Arc<DnsVault>>,
    tun: OnceLock<Arc<dyn TunDevice>>,
    exit_v6: AtomicBool,
    last_hop: usize,
    counters: Arc<Counters>,
    bus: ControlBus,
}

impl Pipeline {
    pub fn new(
        gate: Arc<Gate>,
        block_stun: bool,
        vault: Option<Arc<DnsVault>>,
        exit_v6: bool,
        hops: usize,
        counters: Arc<Counters>,
        bus: ControlBus,
    ) -> Self {
        Self {
            gate,
            stun: StunFilter::new(block_stun, counters.clone()),
            vault,
            tun: OnceLock::new(),
            exit_v6: AtomicBool::new(exit_v6),
            last_hop: hops.saturating_sub(1),
            counters,
            bus,
        }
    }

    /// Device that receives local answers (DNS vault responses).
    pub fn set_tun(&self, tun: Arc<dyn TunDevice>) {
        let _ = self.tun.set(tun);
    }

    pub fn set_exit_v6(&self, v6: bool) {
        self.exit_v6.store(v6, Ordering::SeqCst);
    }

    fn drop_v6(&self, pkt: &[u8]) -> bool {
        pkt.first().is_some_and(|b| b >> 4 == 6) && !self.exit_v6.load(Ordering::SeqCst)
    }

    /// Pipeline step 3: DNS interception. The vault may need its upstream, so
    /// the answer is produced asynchronously and written to the TUN.
    fn intercept_dns(&self, pkt: &[u8]) -> Option<FilterVerdict> {
        let vault = self.vault.as_ref()?;
        let v = IpView::parse(pkt).ok()?;
        if !matches!(v.protocol, PROTO_TCP | PROTO_UDP) {
            return None;
        }
        let (_, dport) = v.ports(pkt)?;
        if dport != DNS_PORT && dport != DOT_PORT {
            return None;
        }
        let (vault, pkt) = (vault.clone(), pkt.to_vec());
        let tun = self.tun.get().cloned();
        match tokio::runtime::Handle::try_current() {
            Ok(h) => {
                h.spawn(async move {
                    if let InterceptVerdict::Respond(r) = vw_dns::intercept(&vault, &pkt).await {
                        if let Some(t) = tun {
                            if let Err(e) = t.write_packet(&r).await {
                                tracing::debug!(error = %e, "dns answer write failed");
                            }
                        }
                    }
                });
            }
            Err(_) => return Some(FilterVerdict::Drop),
        }
        Some(FilterVerdict::Drop)
    }
}

impl PacketFilter for Pipeline {
    fn outbound(&self, pkt: &mut Vec<u8>) -> FilterVerdict {
        if !self.gate.is_open() && !self.gate.permitted(pkt, true) {
            Counters::add(&self.counters.pre_canary_dropped, 1);
            return FilterVerdict::Drop;
        }
        if self.stun.inspect(pkt) == Verdict::Drop {
            return FilterVerdict::Drop;
        }
        if let Some(v) = self.intercept_dns(pkt) {
            return v;
        }
        if self.drop_v6(pkt) {
            Counters::add(&self.counters.ipv6_dropped, 1);
            return FilterVerdict::Drop;
        }
        FilterVerdict::Forward
    }

    fn inbound(&self, pkt: &mut Vec<u8>) -> FilterVerdict {
        if self.bus.offer(self.last_hop, pkt) {
            return FilterVerdict::Drop;
        }
        if !self.gate.is_open() && !self.gate.permitted(pkt, false) {
            Counters::add(&self.counters.pre_canary_dropped, 1);
            return FilterVerdict::Drop;
        }
        if self.drop_v6(pkt) {
            Counters::add(&self.counters.ipv6_dropped, 1);
            return FilterVerdict::Drop;
        }
        FilterVerdict::Forward
    }

    fn hop_control(&self, hop: usize, pkt: &mut Vec<u8>) -> FilterVerdict {
        self.bus.offer(hop, pkt);
        FilterVerdict::Drop
    }
}

// ───────────────────────────── MuxTun ─────────────────────────────

type FlowKey = (u8, u16, IpAddr, u16);

fn out_key(pkt: &[u8]) -> Option<FlowKey> {
    let v = IpView::parse(pkt).ok()?;
    if v.protocol == PROTO_ICMP {
        let (_, id, _) = icmp_echo_fields(pkt)?;
        return Some((PROTO_ICMP, id, v.dst, 0));
    }
    let (s, d) = v.ports(pkt)?;
    Some((v.protocol, s, v.dst, d))
}

fn in_key(pkt: &[u8]) -> Option<FlowKey> {
    let v = IpView::parse(pkt).ok()?;
    if v.protocol == PROTO_ICMP {
        let (_, id, _) = icmp_echo_fields(pkt)?;
        return Some((PROTO_ICMP, id, v.src, 0));
    }
    let (s, d) = v.ports(pkt)?;
    Some((v.protocol, d, v.src, s))
}

const FLOW_IDLE: Duration = Duration::from_secs(180);

/// A `TunDevice` multiplexing the OS TUN (slot 0), extra devices (Linux exec
/// namespaces) and daemon-injected probe packets into one driver.
///
/// Packets read from extra devices register their flow, so replies are
/// written back to the device that sent the request.
pub struct MuxTun {
    tx: mpsc::Sender<(usize, Vec<u8>)>,
    rx: tokio::sync::Mutex<mpsc::Receiver<(usize, Vec<u8>)>>,
    devices: Mutex<Vec<Option<Arc<dyn TunDevice>>>>,
    readers: Mutex<Vec<JoinHandle<()>>>,
    flows: Mutex<HashMap<FlowKey, (usize, Instant)>>,
    mtu: u16,
}

/// Slot used for daemon-injected packets.
pub const INJECT_SLOT: usize = usize::MAX;

impl MuxTun {
    pub fn new(mtu: u16) -> Arc<Self> {
        let (tx, rx) = mpsc::channel(1024);
        Arc::new(Self {
            tx,
            rx: tokio::sync::Mutex::new(rx),
            devices: Mutex::new(Vec::new()),
            readers: Mutex::new(Vec::new()),
            flows: Mutex::new(HashMap::new()),
            mtu,
        })
    }

    /// Attach a device; the first attached device is the primary (slot 0).
    pub fn attach(self: &Arc<Self>, dev: Arc<dyn TunDevice>) -> usize {
        let slot = {
            let mut d = lock(&self.devices);
            d.push(Some(dev.clone()));
            d.len() - 1
        };
        let tx = self.tx.clone();
        let h = tokio::spawn(async move {
            let mut buf = vec![0u8; 65_535];
            loop {
                match dev.read_packet(&mut buf).await {
                    Ok(n) => {
                        if tx.send((slot, buf[..n].to_vec())).await.is_err() {
                            break;
                        }
                    }
                    Err(e) => {
                        tracing::debug!(error = %e, slot, "tun reader stopped");
                        break;
                    }
                }
            }
        });
        lock(&self.readers).push(h);
        slot
    }

    /// Detach an extra device (its reader stops when the device closes).
    pub fn detach(&self, slot: usize) {
        if let Some(s) = lock(&self.devices).get_mut(slot) {
            *s = None;
        }
        lock(&self.flows).retain(|_, (s, _)| *s != slot);
    }

    /// Feed a packet into the outbound pipeline as if read from the TUN.
    pub async fn inject(&self, pkt: Vec<u8>) -> Result<()> {
        self.tx
            .send((INJECT_SLOT, pkt))
            .await
            .map_err(|_| VwError::Transport("tunnel stopped".into()))
    }

    pub fn primary(&self) -> Option<Arc<dyn TunDevice>> {
        lock(&self.devices).first().cloned().flatten()
    }
}

impl Drop for MuxTun {
    fn drop(&mut self) {
        for h in lock(&self.readers).drain(..) {
            h.abort();
        }
    }
}

#[async_trait]
impl TunDevice for MuxTun {
    async fn read_packet(&self, buf: &mut [u8]) -> Result<usize> {
        let (slot, pkt) = self
            .rx
            .lock()
            .await
            .recv()
            .await
            .ok_or_else(|| VwError::Transport("tun closed".into()))?;
        if slot != 0 && slot != INJECT_SLOT {
            if let Some(k) = out_key(&pkt) {
                let mut f = lock(&self.flows);
                let now = Instant::now();
                if f.len() > 4096 {
                    f.retain(|_, (_, t)| now.duration_since(*t) < FLOW_IDLE);
                }
                f.insert(k, (slot, now));
            }
        }
        if pkt.len() > buf.len() {
            return Err(VwError::Packet("tun packet larger than buffer"));
        }
        buf[..pkt.len()].copy_from_slice(&pkt);
        Ok(pkt.len())
    }

    async fn write_packet(&self, packet: &[u8]) -> Result<()> {
        let slot = in_key(packet)
            .and_then(|k| lock(&self.flows).get(&k).map(|(s, _)| *s))
            .unwrap_or(0);
        let dev = lock(&self.devices).get(slot).cloned().flatten();
        match dev {
            Some(d) => d.write_packet(packet).await,
            // No OS device yet (still handshaking): nothing local to deliver to.
            None => Ok(()),
        }
    }

    fn mtu(&self) -> u16 {
        self.mtu
    }

    fn name(&self) -> String {
        self.primary()
            .map(|d| d.name())
            .unwrap_or_else(|| vw_core::consts::TUN_NAME.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vw_core::packet::build_udp;
    use vw_wg::VirtualTunChannel;

    fn pipe(
        open: bool,
        v6: bool,
        vault: Option<Arc<DnsVault>>,
    ) -> (Pipeline, Arc<Gate>, Arc<Counters>, ControlBus) {
        let gate = Arc::new(Gate::default());
        gate.set_open(open);
        let c = Arc::new(Counters::default());
        let bus = ControlBus::new();
        (
            Pipeline::new(gate.clone(), true, vault, v6, 2, c.clone(), bus.clone()),
            gate,
            c,
            bus,
        )
    }

    fn udp(dst: &str, payload: &[u8]) -> Vec<u8> {
        build_udp(
            "100.96.0.2:40000".parse().unwrap(),
            dst.parse().unwrap(),
            payload,
            64,
        )
        .unwrap()
    }

    fn stun() -> Vec<u8> {
        let mut p = vec![0x00, 0x01, 0x00, 0x00];
        p.extend_from_slice(&vw_core::consts::STUN_MAGIC.to_be_bytes());
        p.extend_from_slice(&[9u8; 12]);
        p
    }

    #[test]
    fn gate_blocks_until_open_except_permits() {
        let (p, gate, c, _) = pipe(false, false, None);
        let mut a = udp("203.0.113.99:443", b"x");
        assert_eq!(p.outbound(&mut a), FilterVerdict::Drop);
        assert_eq!(p.inbound(&mut a.clone()), FilterVerdict::Drop);
        assert_eq!(c.snapshot().pre_canary_dropped, 2);
        gate.permit(
            Permit::Local {
                proto: PROTO_UDP,
                port: 40000,
            },
            Duration::from_secs(5),
        );
        assert_eq!(p.outbound(&mut a), FilterVerdict::Forward);
        gate.revoke(Permit::Local {
            proto: PROTO_UDP,
            port: 40000,
        });
        assert_eq!(p.outbound(&mut a), FilterVerdict::Drop);
        gate.set_open(true);
        assert_eq!(p.outbound(&mut a), FilterVerdict::Forward);
    }

    #[test]
    fn stun_and_ipv6_policy() {
        let (p, _, c, _) = pipe(true, false, None);
        assert_eq!(
            p.outbound(&mut udp("198.51.100.1:3478", &stun())),
            FilterVerdict::Drop
        );
        assert_eq!(c.snapshot().stun_blocked, 1);
        let mut v6 = build_udp(
            "[fd00:564f:4944:1::2]:1".parse().unwrap(),
            "[2001:db8::1]:443".parse().unwrap(),
            b"x",
            64,
        )
        .unwrap();
        assert_eq!(p.outbound(&mut v6), FilterVerdict::Drop);
        assert_eq!(p.inbound(&mut v6), FilterVerdict::Drop);
        assert_eq!(c.snapshot().ipv6_dropped, 2);
        let (p6, _, _, _) = pipe(true, true, None);
        assert_eq!(p6.outbound(&mut v6), FilterVerdict::Forward);
    }

    #[test]
    fn control_traffic_is_diverted() {
        let (p, _, _, bus) = pipe(false, false, None);
        let mut rx = bus.subscribe();
        let mut vwcp = build_udp(
            SocketAddr::new(IpAddr::V4(NODE_GATEWAY_V4), VWCP_PORT),
            "100.111.255.254:50000".parse().unwrap(),
            b"VWCP",
            64,
        )
        .unwrap();
        assert_eq!(p.inbound(&mut vwcp), FilterVerdict::Drop);
        assert_eq!(rx.try_recv().unwrap().0, 1);
        assert_eq!(p.hop_control(0, &mut vwcp), FilterVerdict::Drop);
        assert_eq!(rx.try_recv().unwrap().0, 0);
        let req = crate::util::icmp_echo("100.96.0.2".parse().unwrap(), NODE_GATEWAY_V4, 77, 1, 8);
        let mut rep = crate::util::icmp_reply_for(&req).unwrap();
        assert_eq!(p.inbound(&mut rep.clone()), FilterVerdict::Drop);
        assert!(
            rx.try_recv().is_err(),
            "unclaimed id is not control traffic"
        );
        bus.claim_icmp(77);
        assert_eq!(p.inbound(&mut rep), FilterVerdict::Drop);
        assert!(rx.try_recv().is_ok());
    }

    #[tokio::test]
    async fn dns_is_answered_by_the_vault() {
        struct Fail;
        #[async_trait]
        impl vw_dns::Upstream for Fail {
            async fn query(&self, _w: &[u8]) -> vw_dns::Result<Vec<u8>> {
                Err(vw_dns::DnsError::Config("offline".into()))
            }
            fn name(&self) -> &'static str {
                "fail"
            }
        }
        let c = Arc::new(Counters::default());
        let vault = Arc::new(DnsVault::new(Default::default(), Arc::new(Fail), c.clone()));
        let (p, _, _, _) = pipe(true, false, Some(vault));
        let mux = MuxTun::new(1280);
        let (app, dev) = VirtualTunChannel::pair(1280);
        mux.attach(Arc::new(dev));
        p.set_tun(mux.clone());
        let q = vw_leakaudit::canary::dns_query("x.home.arpa", 0x4242);
        let mut pkt = udp("8.8.8.8:53", &q);
        assert_eq!(p.outbound(&mut pkt), FilterVerdict::Drop);
        let mut buf = vec![0u8; 2048];
        let n = tokio::time::timeout(Duration::from_secs(5), app.read_packet(&mut buf))
            .await
            .unwrap()
            .unwrap();
        let v = IpView::parse(&buf[..n]).unwrap();
        assert_eq!(v.src_sock(&buf[..n]), Some("8.8.8.8:53".parse().unwrap()));
        assert_eq!(&v.udp_payload(&buf[..n]).unwrap()[..2], &[0x42, 0x42]);
        assert_eq!(c.snapshot().dns_intercepted, 1);
        let mut dot = udp("1.1.1.1:853", b"x");
        assert_eq!(p.outbound(&mut dot), FilterVerdict::Drop);
    }

    #[tokio::test]
    async fn mux_routes_replies_to_the_requesting_device() {
        let mux = MuxTun::new(1280);
        let (main_app, main_dev) = VirtualTunChannel::pair(1280);
        let (ns_app, ns_dev) = VirtualTunChannel::pair(1280);
        mux.attach(Arc::new(main_dev));
        let slot = mux.attach(Arc::new(ns_dev));
        assert_eq!(slot, 1);
        let req = udp("203.0.113.5:443", b"q");
        ns_app.write_packet(&req).await.unwrap();
        let mut buf = vec![0u8; 2048];
        let n = mux.read_packet(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], &req[..]);
        let reply = build_udp(
            "203.0.113.5:443".parse().unwrap(),
            "100.96.0.2:40000".parse().unwrap(),
            b"r",
            64,
        )
        .unwrap();
        mux.write_packet(&reply).await.unwrap();
        let n = ns_app.read_packet(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], &reply[..]);
        let other = build_udp(
            "203.0.113.6:443".parse().unwrap(),
            "100.96.0.2:40001".parse().unwrap(),
            b"o",
            64,
        )
        .unwrap();
        mux.write_packet(&other).await.unwrap();
        let n = main_app.read_packet(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], &other[..]);
        mux.inject(vec![0x45, 1]).await.unwrap();
        let n = mux.read_packet(&mut buf).await.unwrap();
        assert_eq!(n, 2);
    }
}
