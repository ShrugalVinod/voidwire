//! Async glue: pumps a [`TunDevice`] and a [`StealthTransport`] through an
//! [`Engine`] (a [`Peer`] or a [`Cascade`]), runs the timer loop and applies
//! the packet pipeline hooks (sanitizer → [`PacketFilter`] → DAITA padding).

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use tokio::sync::watch;
use tokio::task::{JoinHandle, JoinSet};
use vw_core::config::DaitaParams;
use vw_core::telemetry::Counters;
use vw_core::transport::{StealthTransport, TunDevice};
use vw_core::{Result, VwError};

use crate::cascade::Cascade;
use crate::daita::pad_plaintext;
use crate::noise::is_handshake_initiation;
use crate::peer::{Decapsulated, Peer};
use crate::sanitize::Sanitizer;

/// Everything one inbound datagram produced.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct EngineOutput {
    /// Datagrams to send on the transport.
    pub network: Vec<Vec<u8>>,
    /// User-traffic IP packets for the TUN device.
    pub tunnel: Vec<Vec<u8>>,
    /// Plaintext decrypted at an intermediate cascade hop: `(hop, packet)`.
    pub control: Vec<(usize, Vec<u8>)>,
    pub chaff: usize,
    pub errors: usize,
}

/// A sans-IO WireGuard engine the driver can pump.
pub trait Engine: Send + 'static {
    /// Encrypt user traffic.
    fn outbound(&mut self, plaintext: &[u8], now: Instant) -> Vec<Vec<u8>>;
    /// Encrypt traffic for a specific hop's network (cascades); single peers
    /// treat every hop as hop 0.
    fn outbound_at(&mut self, hop: usize, plaintext: &[u8], now: Instant) -> Vec<Vec<u8>> {
        let _ = hop;
        self.outbound(plaintext, now)
    }
    /// Process one datagram from the transport.
    fn inbound(&mut self, datagram: &[u8], now: Instant) -> EngineOutput;
    /// Run timers.
    fn tick(&mut self, now: Instant) -> Vec<Vec<u8>>;
    /// Encrypted DAITA chaff on the outermost session.
    fn chaff(&mut self, size: usize, now: Instant) -> Option<Vec<u8>>;
    fn established(&self) -> bool;
    fn handshakes_completed(&self) -> u64;
}

impl Engine for Peer {
    fn outbound(&mut self, plaintext: &[u8], now: Instant) -> Vec<Vec<u8>> {
        self.encapsulate(plaintext, now)
    }

    fn inbound(&mut self, datagram: &[u8], now: Instant) -> EngineOutput {
        let mut out = EngineOutput::default();
        match self.decapsulate(datagram, now) {
            Ok(Decapsulated::Network(d)) => out.network = d,
            Ok(Decapsulated::Tunnel(p)) => out.tunnel.push(p),
            Ok(Decapsulated::Chaff) => out.chaff = 1,
            Ok(Decapsulated::Keepalive | Decapsulated::None) => {}
            Err(e) => {
                tracing::trace!(error = %e, "datagram rejected");
                out.errors = 1;
            }
        }
        out.network.extend(self.drain_outbox());
        out
    }

    fn tick(&mut self, now: Instant) -> Vec<Vec<u8>> {
        Peer::tick(self, now)
    }

    fn chaff(&mut self, size: usize, now: Instant) -> Option<Vec<u8>> {
        self.make_chaff(size, now)
    }

    fn established(&self) -> bool {
        self.session_established()
    }

    fn handshakes_completed(&self) -> u64 {
        Peer::handshakes_completed(self)
    }
}

impl Engine for Cascade {
    fn outbound(&mut self, plaintext: &[u8], now: Instant) -> Vec<Vec<u8>> {
        self.encapsulate(plaintext, now)
    }

    fn outbound_at(&mut self, hop: usize, plaintext: &[u8], now: Instant) -> Vec<Vec<u8>> {
        self.encapsulate_at(hop, plaintext, now)
    }

    fn inbound(&mut self, datagram: &[u8], now: Instant) -> EngineOutput {
        let last = self.len() - 1;
        let r = self.decapsulate(datagram, now);
        let mut out = EngineOutput {
            network: r.network,
            chaff: r.chaff,
            errors: r.errors,
            ..Default::default()
        };
        for (hop, pkt) in r.delivered {
            if hop == last {
                out.tunnel.push(pkt);
            } else {
                out.control.push((hop, pkt));
            }
        }
        out
    }

    fn tick(&mut self, now: Instant) -> Vec<Vec<u8>> {
        Cascade::tick(self, now)
    }

    fn chaff(&mut self, size: usize, now: Instant) -> Option<Vec<u8>> {
        self.make_chaff(size, now)
    }

    fn established(&self) -> bool {
        Cascade::established(self)
    }

    fn handshakes_completed(&self) -> u64 {
        Cascade::handshakes_completed(self)
    }
}

/// What a [`PacketFilter`] decided.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FilterVerdict {
    /// Continue through the pipeline.
    Forward,
    /// Discard silently.
    Drop,
    /// Discard and answer locally with this packet (outbound: written back to
    /// the TUN, e.g. a DNS-vault answer; inbound: sent back into the tunnel).
    Respond(Vec<u8>),
}

/// Daemon hook for STUN filtering, DNS interception and the policy gate.
pub trait PacketFilter: Send + Sync {
    /// A plaintext packet read from the TUN, after sanitizing.
    fn outbound(&self, pkt: &mut Vec<u8>) -> FilterVerdict {
        let _ = pkt;
        FilterVerdict::Forward
    }
    /// A decrypted packet about to be written to the TUN.
    fn inbound(&self, pkt: &mut Vec<u8>) -> FilterVerdict {
        let _ = pkt;
        FilterVerdict::Forward
    }
    /// Plaintext from an intermediate cascade hop (control traffic). Dropped
    /// unless the filter handles it; `Respond` is sent back on that hop.
    fn hop_control(&self, hop: usize, pkt: &mut Vec<u8>) -> FilterVerdict {
        let _ = (hop, pkt);
        FilterVerdict::Drop
    }
}

/// Forwards everything.
#[derive(Debug, Default, Clone, Copy)]
pub struct PassThrough;

impl PacketFilter for PassThrough {}

/// Driver tuning.
#[derive(Debug, Clone)]
pub struct DriverConfig {
    /// Timer tick period.
    pub tick_interval: Duration,
    /// Outbound sanitizer (pipeline step 1), if any.
    pub sanitizer: Option<Sanitizer>,
    /// DAITA bucket padding (pipeline step 5), if enabled.
    pub daita: Option<DaitaParams>,
}

impl Default for DriverConfig {
    fn default() -> Self {
        Self {
            tick_interval: Duration::from_millis(250),
            sanitizer: None,
            daita: None,
        }
    }
}

const BUF_LEN: usize = 65_535;

/// The async tunnel pump.
pub struct TunnelDriver<E: Engine> {
    engine: Arc<Mutex<E>>,
    tun: Arc<dyn TunDevice>,
    transport: Arc<dyn StealthTransport>,
    filter: Arc<dyn PacketFilter>,
    counters: Arc<Counters>,
    config: DriverConfig,
}

/// Handle to a spawned driver.
pub struct DriverHandle {
    shutdown: watch::Sender<bool>,
    task: JoinHandle<Result<()>>,
}

impl DriverHandle {
    /// Stop the driver and wait for it.
    pub async fn shutdown(self) -> Result<()> {
        let _ = self.shutdown.send(true);
        self.task
            .await
            .map_err(|e| VwError::Transport(format!("driver task failed: {e}")))?
    }

    pub fn is_finished(&self) -> bool {
        self.task.is_finished()
    }
}

fn lock<E>(m: &Mutex<E>) -> MutexGuard<'_, E> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

struct Shared<E: Engine> {
    engine: Arc<Mutex<E>>,
    tun: Arc<dyn TunDevice>,
    transport: Arc<dyn StealthTransport>,
    filter: Arc<dyn PacketFilter>,
    counters: Arc<Counters>,
    config: DriverConfig,
    seen_handshakes: AtomicU64,
}

impl<E: Engine> Shared<E> {
    fn note_handshakes(&self, total: u64) {
        let prev = self.seen_handshakes.fetch_max(total, Ordering::Relaxed);
        if total > prev {
            Counters::add(&self.counters.handshakes, total - prev);
        }
    }

    /// Run `f` on the engine and record completed handshakes.
    fn with_engine<R>(&self, f: impl FnOnce(&mut E) -> R) -> R {
        let mut e = lock(&self.engine);
        let r = f(&mut e);
        let hs = e.handshakes_completed();
        drop(e);
        self.note_handshakes(hs);
        r
    }

    async fn send_all(&self, datagrams: Vec<Vec<u8>>) -> Result<()> {
        for d in datagrams {
            if is_handshake_initiation(&d) {
                self.transport.before_handshake().await?;
            }
            if let Err(e) = self.transport.send(&d).await {
                // Transient (e.g. no route during a network change); WireGuard
                // timers retransmit what matters.
                tracing::debug!(error = %e, "transport send failed");
            }
        }
        Ok(())
    }

    async fn outbound_loop(&self) -> Result<()> {
        let mut buf = vec![0u8; BUF_LEN];
        loop {
            let n = self.tun.read_packet(&mut buf).await?;
            let mut pkt = buf[..n].to_vec();
            if let Some(s) = &self.config.sanitizer {
                s.process_outbound(&mut pkt).record(&self.counters);
            }
            match self.filter.outbound(&mut pkt) {
                FilterVerdict::Forward => {}
                FilterVerdict::Drop => continue,
                FilterVerdict::Respond(r) => {
                    self.tun.write_packet(&r).await?;
                    continue;
                }
            }
            if let Some(d) = &self.config.daita {
                pad_plaintext(&mut pkt, d);
            }
            let dgs = self.with_engine(|e| e.outbound(&pkt, Instant::now()));
            Counters::add(&self.counters.tx_packets, 1);
            Counters::add(&self.counters.tx_bytes, n as u64);
            self.send_all(dgs).await?;
        }
    }

    async fn inbound_loop(&self) -> Result<()> {
        let mut buf = vec![0u8; BUF_LEN];
        loop {
            let n = self.transport.recv(&mut buf).await?;
            let out = self.with_engine(|e| e.inbound(&buf[..n], Instant::now()));
            self.send_all(out.network).await?;
            for mut pkt in out.tunnel {
                match self.filter.inbound(&mut pkt) {
                    FilterVerdict::Forward => {
                        Counters::add(&self.counters.rx_packets, 1);
                        Counters::add(&self.counters.rx_bytes, pkt.len() as u64);
                        self.tun.write_packet(&pkt).await?;
                    }
                    FilterVerdict::Drop => {}
                    FilterVerdict::Respond(r) => {
                        let d = self.with_engine(|e| e.outbound(&r, Instant::now()));
                        self.send_all(d).await?;
                    }
                }
            }
            for (hop, mut pkt) in out.control {
                if let FilterVerdict::Respond(r) = self.filter.hop_control(hop, &mut pkt) {
                    let d = self.with_engine(|e| e.outbound_at(hop, &r, Instant::now()));
                    self.send_all(d).await?;
                }
            }
        }
    }

    async fn timer_loop(&self) -> Result<()> {
        let mut iv = tokio::time::interval(self.config.tick_interval);
        iv.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            iv.tick().await;
            let d = self.with_engine(|e| e.tick(Instant::now()));
            self.send_all(d).await?;
        }
    }
}

impl<E: Engine> TunnelDriver<E> {
    pub fn new(
        engine: Arc<Mutex<E>>,
        tun: Arc<dyn TunDevice>,
        transport: Arc<dyn StealthTransport>,
        counters: Arc<Counters>,
    ) -> Self {
        Self {
            engine,
            tun,
            transport,
            filter: Arc::new(PassThrough),
            counters,
            config: DriverConfig::default(),
        }
    }

    pub fn with_filter(mut self, filter: Arc<dyn PacketFilter>) -> Self {
        self.filter = filter;
        self
    }

    pub fn with_config(mut self, config: DriverConfig) -> Self {
        self.config = config;
        self
    }

    /// The shared engine (e.g. to call `set_psk` after a VWCP rotation).
    pub fn engine(&self) -> Arc<Mutex<E>> {
        self.engine.clone()
    }

    /// Run until `shutdown` becomes true or a TUN / transport receive fails.
    pub async fn run(self, mut shutdown: watch::Receiver<bool>) -> Result<()> {
        let shared = Arc::new(Shared {
            engine: self.engine,
            tun: self.tun,
            transport: self.transport,
            filter: self.filter,
            counters: self.counters,
            config: self.config,
            seen_handshakes: AtomicU64::new(0),
        });
        let mut set = JoinSet::new();
        let s = shared.clone();
        set.spawn(async move { s.outbound_loop().await });
        let s = shared.clone();
        set.spawn(async move { s.inbound_loop().await });
        let s = shared.clone();
        set.spawn(async move { s.timer_loop().await });

        let result = loop {
            tokio::select! {
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() {
                        break Ok(());
                    }
                }
                done = set.join_next() => {
                    break match done {
                        Some(Ok(r)) => r,
                        Some(Err(e)) => Err(VwError::Transport(format!("driver task failed: {e}"))),
                        None => Ok(()),
                    };
                }
            }
        };
        set.abort_all();
        result
    }

    /// Spawn [`run`](Self::run) on the current tokio runtime.
    pub fn spawn(self) -> DriverHandle {
        let (tx, rx) = watch::channel(false);
        let task = tokio::spawn(self.run(rx));
        DriverHandle { shutdown: tx, task }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::noise::{generate_private_key, public_key};
    use crate::tun::VirtualTunChannel;
    use async_trait::async_trait;
    use std::net::SocketAddr;
    use std::sync::atomic::AtomicUsize;
    use tokio::sync::mpsc;
    use vw_core::config::TransportKind;

    /// Test-only datagram channel transport.
    struct ChanTransport {
        tx: mpsc::UnboundedSender<Vec<u8>>,
        rx: tokio::sync::Mutex<mpsc::UnboundedReceiver<Vec<u8>>>,
        before_handshake_calls: Arc<AtomicUsize>,
    }

    fn chan_pair() -> (ChanTransport, ChanTransport) {
        let (atx, brx) = mpsc::unbounded_channel();
        let (btx, arx) = mpsc::unbounded_channel();
        (
            ChanTransport {
                tx: atx,
                rx: tokio::sync::Mutex::new(arx),
                before_handshake_calls: Arc::default(),
            },
            ChanTransport {
                tx: btx,
                rx: tokio::sync::Mutex::new(brx),
                before_handshake_calls: Arc::default(),
            },
        )
    }

    #[async_trait]
    impl StealthTransport for ChanTransport {
        async fn send(&self, datagram: &[u8]) -> Result<()> {
            self.tx
                .send(datagram.to_vec())
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
            TransportKind::NativeUdp
        }
        fn remote_addr(&self) -> SocketAddr {
            "192.0.2.1:51820".parse().unwrap()
        }
        async fn before_handshake(&self) -> Result<()> {
            self.before_handshake_calls.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }
    }

    struct DropPort(u16);
    impl PacketFilter for DropPort {
        fn outbound(&self, pkt: &mut Vec<u8>) -> FilterVerdict {
            let v = vw_core::packet::IpView::parse(pkt).unwrap();
            if v.ports(pkt).map(|p| p.1) == Some(self.0) {
                FilterVerdict::Drop
            } else {
                FilterVerdict::Forward
            }
        }
    }

    async fn read_timeout(t: &VirtualTunChannel) -> Vec<u8> {
        let mut buf = vec![0u8; 2048];
        let n = tokio::time::timeout(Duration::from_secs(5), t.read_packet(&mut buf))
            .await
            .expect("packet arrives")
            .unwrap();
        buf.truncate(n);
        buf
    }

    #[tokio::test]
    async fn two_drivers_ping_end_to_end() {
        let ck = generate_private_key();
        let sk = generate_private_key();
        let client = Peer::new_initiator(ck.clone(), public_key(&sk), None, [0; 3]);
        let server = Peer::new_responder(sk, public_key(&ck), None, [0; 3]);
        let (ct, st) = chan_pair();
        let bh = ct.before_handshake_calls.clone();
        let (client_app, client_tun) = VirtualTunChannel::pair(1420);
        let (server_app, server_tun) = VirtualTunChannel::pair(1420);
        let c_counters = Arc::new(Counters::default());
        let s_counters = Arc::new(Counters::default());
        let cfg = DriverConfig {
            tick_interval: Duration::from_millis(20),
            sanitizer: Some(Sanitizer::new(Default::default(), 1420)),
            daita: Some(DaitaParams {
                enabled: true,
                ..Default::default()
            }),
        };
        let client_engine = Arc::new(Mutex::new(client));
        let cd = TunnelDriver::new(
            client_engine.clone(),
            Arc::new(client_tun),
            Arc::new(ct),
            c_counters.clone(),
        )
        .with_config(cfg.clone())
        .with_filter(Arc::new(DropPort(9)))
        .spawn();
        let sd = TunnelDriver::new(
            Arc::new(Mutex::new(server)),
            Arc::new(server_tun),
            Arc::new(st),
            s_counters.clone(),
        )
        .with_config(cfg)
        .spawn();

        let a: SocketAddr = "100.96.0.2:5000".parse().unwrap();
        let b: SocketAddr = "203.0.113.99:7".parse().unwrap();
        for i in 0..10u8 {
            let ping = vw_core::packet::build_udp(a, b, &[i; 50], 128).unwrap();
            client_app.write_packet(&ping).await.unwrap();
            let got = read_timeout(&server_app).await;
            // Sanitizer normalised the TTL; DAITA padding was stripped.
            let mut expect = ping.clone();
            Sanitizer::new(Default::default(), 1420).process_outbound(&mut expect);
            assert_eq!(got, expect);
            let pong = vw_core::packet::build_udp(b, a, &[i; 70], 64).unwrap();
            server_app.write_packet(&pong).await.unwrap();
            assert_eq!(read_timeout(&client_app).await, pong);
        }
        // The filter drops port 9; the next packet still arrives.
        let dropped =
            vw_core::packet::build_udp(a, "203.0.113.99:9".parse().unwrap(), b"x", 64).unwrap();
        client_app.write_packet(&dropped).await.unwrap();
        let ok = vw_core::packet::build_udp(a, b, b"after", 64).unwrap();
        client_app.write_packet(&ok).await.unwrap();
        assert_eq!(read_timeout(&server_app).await, ok);

        assert!(lock(&client_engine).established());
        assert!(bh.load(Ordering::Relaxed) >= 1);
        let cs = c_counters.snapshot();
        assert!(cs.handshakes >= 1);
        assert_eq!(cs.tx_packets, 11);
        assert_eq!(cs.rx_packets, 10);
        assert_eq!(cs.ttl_normalized, 10);
        assert_eq!(s_counters.snapshot().rx_packets, 11);
        cd.shutdown().await.unwrap();
        // The server's transport peer is gone now, so its driver may already
        // have stopped with a receive error; either outcome is fine.
        let _ = sd.shutdown().await;
    }
}
