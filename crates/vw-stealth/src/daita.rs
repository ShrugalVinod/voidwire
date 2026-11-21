//! DAITA cover traffic: Poisson chaff on top of any client transport.
//!
//! A background task emits chaff datagrams (produced and encrypted by a
//! [`ChaffSource`], i.e. the WireGuard engine) with exponentially distributed
//! inter-arrival times of mean `1 / chaff_rate_hz`; each chaff plaintext size
//! is drawn uniformly from `DaitaParams.buckets`.
//!
//! # Overhead cap
//! Over a sliding 1 s window, measured in wire bytes:
//!
//! ```text
//! chaff_bytes(window) ≤ max(real_tx_bytes(window) × max_overhead_pct / 100,
//!                           CHAFF_FLOOR_BYTES_PER_SEC)
//! ```
//!
//! A chaff event that would exceed the budget is skipped (the Poisson process
//! is thinned, never bunched up later). The floor keeps idle links covered by
//! a trickle of chaff so that "no traffic" is not itself a signal.

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use tokio::task::JoinHandle;
use tokio::time::Instant;
use tracing::debug;
use vw_core::config::{DaitaParams, TransportKind};
use vw_core::consts::DAITA_BUCKETS;
use vw_core::telemetry::Counters;
use vw_core::transport::{ChaffSource, StealthTransport};
use vw_core::Result;

/// Chaff allowance per 1 s window regardless of real traffic.
pub const CHAFF_FLOOR_BYTES_PER_SEC: usize = 2048;
const WINDOW: Duration = Duration::from_secs(1);
/// WireGuard transport-data overhead (header 16 + tag 16), used to pre-check
/// the budget before asking the engine to encrypt chaff.
const WG_DATA_OVERHEAD: usize = 32;
/// Upper bound on a single inter-arrival gap (guards absurdly low rates).
const MAX_GAP: Duration = Duration::from_secs(3600);

#[derive(Debug)]
struct Window {
    events: VecDeque<(Instant, usize)>,
    sum: usize,
}

impl Window {
    fn new() -> Self {
        Self {
            events: VecDeque::new(),
            sum: 0,
        }
    }

    /// Keep events with `t > now - 1 s`.
    fn prune(&mut self, now: Instant) {
        while let Some(&(t, n)) = self.events.front() {
            if now.duration_since(t) >= WINDOW {
                self.events.pop_front();
                self.sum -= n;
            } else {
                break;
            }
        }
    }

    fn push(&mut self, now: Instant, n: usize) {
        self.events.push_back((now, n));
        self.sum += n;
    }
}

#[derive(Debug)]
struct Budget {
    real: Window,
    chaff: Window,
    pct: usize,
}

impl Budget {
    fn allowance(&mut self, now: Instant) -> usize {
        self.real.prune(now);
        self.chaff.prune(now);
        (self.real.sum * self.pct / 100).max(CHAFF_FLOOR_BYTES_PER_SEC)
    }

    fn fits(&mut self, now: Instant, n: usize) -> bool {
        self.chaff.sum + n <= self.allowance(now)
    }

    fn try_take(&mut self, now: Instant, n: usize) -> bool {
        let ok = self.fits(now, n);
        if ok {
            self.chaff.push(now, n);
        }
        ok
    }

    fn record_real(&mut self, now: Instant, n: usize) {
        self.real.prune(now);
        self.real.push(now, n);
    }
}

/// Wraps a client transport and adds Poisson chaff (see module docs).
pub struct DaitaTransport<T: StealthTransport + ?Sized + 'static> {
    inner: Arc<T>,
    budget: Arc<Mutex<Budget>>,
    task: Mutex<Option<JoinHandle<()>>>,
}

impl<T: StealthTransport + ?Sized + 'static> DaitaTransport<T> {
    /// Wrap `inner`. Must be called inside a tokio runtime. Chaff runs only if
    /// `params.enabled` and the rate is positive and finite; chaff datagrams
    /// are counted in `counters.chaff_sent`.
    pub fn new(
        inner: Arc<T>,
        params: DaitaParams,
        source: Arc<dyn ChaffSource>,
        counters: Option<Arc<Counters>>,
    ) -> Self {
        Self::with_rng(inner, params, source, counters, StdRng::from_entropy())
    }

    fn with_rng(
        inner: Arc<T>,
        params: DaitaParams,
        source: Arc<dyn ChaffSource>,
        counters: Option<Arc<Counters>>,
        rng: StdRng,
    ) -> Self {
        let budget = Arc::new(Mutex::new(Budget {
            real: Window::new(),
            chaff: Window::new(),
            pct: params.max_overhead_pct as usize,
        }));
        let active =
            params.enabled && params.chaff_rate_hz.is_finite() && params.chaff_rate_hz > 0.0;
        let task = active.then(|| {
            tokio::spawn(chaff_loop(
                inner.clone(),
                source,
                budget.clone(),
                params,
                counters,
                rng,
            ))
        });
        Self {
            inner,
            budget,
            task: Mutex::new(task),
        }
    }

    /// Whether the chaff task is running.
    pub fn chaff_active(&self) -> bool {
        self.task
            .lock()
            .map(|t| t.as_ref().is_some_and(|h| !h.is_finished()))
            .unwrap_or(false)
    }

    /// Stop emitting chaff; the inner transport stays usable.
    pub fn stop_chaff(&self) {
        if let Ok(mut t) = self.task.lock() {
            if let Some(h) = t.take() {
                h.abort();
            }
        }
    }

    pub fn inner(&self) -> &Arc<T> {
        &self.inner
    }
}

impl<T: StealthTransport + ?Sized + 'static> Drop for DaitaTransport<T> {
    fn drop(&mut self) {
        self.stop_chaff();
    }
}

async fn chaff_loop<T: StealthTransport + ?Sized + 'static>(
    inner: Arc<T>,
    source: Arc<dyn ChaffSource>,
    budget: Arc<Mutex<Budget>>,
    params: DaitaParams,
    counters: Option<Arc<Counters>>,
    mut rng: StdRng,
) {
    let buckets: Vec<usize> = if params.buckets.is_empty() {
        DAITA_BUCKETS.iter().map(|b| *b as usize).collect()
    } else {
        params.buckets.iter().map(|b| *b as usize).collect()
    };
    let rate = params.chaff_rate_hz;
    // Absolute deadlines so timer rounding never accumulates into rate drift.
    let mut next = Instant::now();
    loop {
        let u: f64 = rng.gen();
        let gap = -(1.0 - u).ln() / rate;
        next += Duration::try_from_secs_f64(gap)
            .unwrap_or(MAX_GAP)
            .min(MAX_GAP);
        tokio::time::sleep_until(next).await;

        let size = buckets[rng.gen_range(0..buckets.len())];
        let now = Instant::now();
        let fits = budget
            .lock()
            .map(|mut b| b.fits(now, size + WG_DATA_OVERHEAD))
            .unwrap_or(false);
        if !fits {
            continue;
        }
        let Some(datagram) = source.make_chaff(size) else {
            continue;
        };
        let taken = budget
            .lock()
            .map(|mut b| b.try_take(now, datagram.len()))
            .unwrap_or(false);
        if !taken {
            continue;
        }
        match inner.send(&datagram).await {
            Ok(()) => {
                if let Some(c) = &counters {
                    Counters::add(&c.chaff_sent, 1);
                }
            }
            Err(e) => debug!("daita: chaff send failed: {e}"),
        }
    }
}

#[async_trait]
impl<T: StealthTransport + ?Sized + 'static> StealthTransport for DaitaTransport<T> {
    async fn send(&self, datagram: &[u8]) -> Result<()> {
        if let Ok(mut b) = self.budget.lock() {
            b.record_real(Instant::now(), datagram.len());
        }
        self.inner.send(datagram).await
    }

    async fn recv(&self, buf: &mut [u8]) -> Result<usize> {
        // Incoming chaff decrypts to a 0x00-led plaintext that the WG engine drops.
        self.inner.recv(buf).await
    }

    fn kind(&self) -> TransportKind {
        self.inner.kind()
    }

    fn overhead(&self) -> u16 {
        self.inner.overhead()
    }

    fn remote_addr(&self) -> SocketAddr {
        self.inner.remote_addr()
    }

    async fn before_handshake(&self) -> Result<()> {
        self.inner.before_handshake().await
    }

    async fn rebind(&self) -> Result<()> {
        self.inner.rebind().await
    }

    async fn close(&self) -> Result<()> {
        self.stop_chaff();
        self.inner.close().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::Ordering::Relaxed;

    const CHAFF_BYTE: u8 = 0xcc;
    const REAL_BYTE: u8 = 0x11;

    /// Records every datagram with its (virtual) send time.
    #[derive(Default)]
    struct MemTransport {
        sent: Mutex<Vec<(Instant, Vec<u8>)>>,
    }

    impl MemTransport {
        fn sent(&self) -> Vec<(Instant, Vec<u8>)> {
            self.sent.lock().unwrap().clone()
        }
    }

    #[async_trait]
    impl StealthTransport for MemTransport {
        async fn send(&self, d: &[u8]) -> Result<()> {
            self.sent.lock().unwrap().push((Instant::now(), d.to_vec()));
            Ok(())
        }
        async fn recv(&self, _buf: &mut [u8]) -> Result<usize> {
            std::future::pending().await
        }
        fn kind(&self) -> TransportKind {
            TransportKind::NativeUdp
        }
        fn remote_addr(&self) -> SocketAddr {
            "192.0.2.1:51820".parse().unwrap()
        }
    }

    /// "Encrypts" chaff as size + 32 bytes of a marker.
    struct FakeChaff;
    impl ChaffSource for FakeChaff {
        fn make_chaff(&self, size: usize) -> Option<Vec<u8>> {
            Some(vec![CHAFF_BYTE; size + WG_DATA_OVERHEAD])
        }
    }

    struct NoSession;
    impl ChaffSource for NoSession {
        fn make_chaff(&self, _size: usize) -> Option<Vec<u8>> {
            None
        }
    }

    fn params(rate: f64, buckets: Vec<u16>, pct: u8) -> DaitaParams {
        DaitaParams {
            enabled: true,
            buckets,
            chaff_rate_hz: rate,
            max_overhead_pct: pct,
        }
    }

    fn wrap(
        mem: &Arc<MemTransport>,
        p: DaitaParams,
        counters: Option<Arc<Counters>>,
    ) -> DaitaTransport<MemTransport> {
        DaitaTransport::with_rng(
            mem.clone(),
            p,
            Arc::new(FakeChaff),
            counters,
            StdRng::seed_from_u64(7),
        )
    }

    fn chaff_times(sent: &[(Instant, Vec<u8>)]) -> Vec<Instant> {
        sent.iter()
            .filter(|(_, d)| d[0] == CHAFF_BYTE)
            .map(|(t, _)| *t)
            .collect()
    }

    /// Bytes of kind `marker` in the window (t - 1 s, t].
    fn window_bytes(sent: &[(Instant, Vec<u8>)], t: Instant, marker: u8) -> usize {
        sent.iter()
            .filter(|(s, d)| d[0] == marker && *s <= t && t.duration_since(*s) < WINDOW)
            .map(|(_, d)| d.len())
            .sum()
    }

    #[tokio::test(start_paused = true)]
    async fn poisson_rate_statistics() {
        let mem = Arc::new(MemTransport::default());
        let counters = Arc::new(Counters::default());
        // 20 Hz × 48 B stays far below the idle floor, so nothing is thinned.
        let d = wrap(&mem, params(20.0, vec![16], 25), Some(counters.clone()));
        assert!(d.chaff_active());
        let secs = 500.0;
        tokio::time::sleep(Duration::from_secs_f64(secs)).await;
        d.close().await.unwrap();

        let times = chaff_times(&mem.sent());
        let n = times.len() as f64;
        let expected = 20.0 * secs;
        // Poisson σ = √10000 = 100; allow 4σ.
        assert!((n - expected).abs() < 400.0, "count {n}");
        assert_eq!(counters.chaff_sent.load(Relaxed), times.len() as u64);

        let gaps: Vec<f64> = times
            .windows(2)
            .map(|w| w[1].duration_since(w[0]).as_secs_f64())
            .collect();
        let mean = gaps.iter().sum::<f64>() / gaps.len() as f64;
        let var = gaps.iter().map(|g| (g - mean).powi(2)).sum::<f64>() / gaps.len() as f64;
        let cv = var.sqrt() / mean;
        assert!((mean - 0.05).abs() < 0.0025, "mean gap {mean}");
        // Exponential inter-arrivals: coefficient of variation 1, P(gap > mean) = 1/e.
        assert!((cv - 1.0).abs() < 0.08, "cv {cv}");
        let above = gaps.iter().filter(|g| **g > mean).count() as f64 / gaps.len() as f64;
        assert!((above - (-1.0f64).exp()).abs() < 0.03, "tail {above}");
        assert!(mem.sent().iter().all(|(_, d)| d.len() == 48));
    }

    #[tokio::test(start_paused = true)]
    async fn overhead_cap_under_load() {
        let mem = Arc::new(MemTransport::default());
        // Huge chaff demand (1000 Hz × 1312 B) must be capped at 25 % of real.
        let d = Arc::new(wrap(&mem, params(1000.0, vec![1280], 25), None));
        let sender = {
            let d = d.clone();
            tokio::spawn(async move {
                let mut tick = tokio::time::interval(Duration::from_millis(10));
                for _ in 0..1000 {
                    tick.tick().await;
                    d.send(&[REAL_BYTE; 1000]).await.unwrap();
                }
            })
        };
        sender.await.unwrap();
        d.close().await.unwrap();

        let sent = mem.sent();
        let chaff = chaff_times(&sent);
        assert!(!chaff.is_empty());
        for t in &chaff {
            let c = window_bytes(&sent, *t, CHAFF_BYTE);
            let r = window_bytes(&sent, *t, REAL_BYTE);
            let allowed = (r * 25 / 100).max(CHAFF_FLOOR_BYTES_PER_SEC);
            assert!(c <= allowed, "chaff {c} > allowed {allowed} (real {r})");
        }
        let real_total: usize = sent
            .iter()
            .filter(|(_, d)| d[0] == REAL_BYTE)
            .map(|(_, d)| d.len())
            .sum();
        let chaff_total: usize = sent
            .iter()
            .filter(|(_, d)| d[0] == CHAFF_BYTE)
            .map(|(_, d)| d.len())
            .sum();
        assert_eq!(real_total, 1_000_000);
        let ratio = chaff_total as f64 / real_total as f64;
        assert!(ratio <= 0.26 && ratio > 0.18, "overhead ratio {ratio}");
    }

    #[tokio::test(start_paused = true)]
    async fn idle_floor_and_stop() {
        let mem = Arc::new(MemTransport::default());
        let d = wrap(&mem, params(1000.0, vec![128, 256], 25), None);
        tokio::time::sleep(Duration::from_secs(20)).await;
        let sent = mem.sent();
        let chaff = chaff_times(&sent);
        // Idle link: some cover traffic, never more than the floor per window.
        assert!(chaff.len() > 20 * 5);
        for t in &chaff {
            assert!(window_bytes(&sent, *t, CHAFF_BYTE) <= CHAFF_FLOOR_BYTES_PER_SEC);
        }

        d.close().await.unwrap();
        tokio::task::yield_now().await;
        assert!(!d.chaff_active());
        let before = mem.sent().len();
        tokio::time::sleep(Duration::from_secs(10)).await;
        assert_eq!(mem.sent().len(), before, "chaff after close");
    }

    #[tokio::test(start_paused = true)]
    async fn disabled_or_no_session_sends_nothing() {
        let mem = Arc::new(MemTransport::default());
        let mut p = params(50.0, vec![128], 25);
        p.enabled = false;
        let d = wrap(&mem, p, None);
        assert!(!d.chaff_active());
        let d2 = DaitaTransport::new(
            mem.clone(),
            params(50.0, vec![128], 25),
            Arc::new(NoSession),
            None,
        );
        tokio::time::sleep(Duration::from_secs(5)).await;
        assert!(mem.sent().is_empty());
        d.send(b"\x11real").await.unwrap();
        assert_eq!(mem.sent().len(), 1);
        assert_eq!(d2.kind(), TransportKind::NativeUdp);
        drop(d2);
    }

    #[tokio::test(start_paused = true)]
    async fn wraps_trait_objects() {
        let mem: Arc<dyn StealthTransport> = Arc::new(MemTransport::default());
        let d = DaitaTransport::new(mem, params(5.0, vec![], 25), Arc::new(FakeChaff), None);
        tokio::time::sleep(Duration::from_secs(10)).await;
        assert!(d.chaff_active());
        d.close().await.unwrap();
    }
}
