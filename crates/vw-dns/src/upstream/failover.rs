//! Ordered failover across upstreams with health tracking and timeouts.

use std::sync::atomic::{AtomicU32, AtomicU64, Ordering::Relaxed};
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;

use super::Upstream;
use crate::error::{DnsError, Result};

/// Consecutive failures before an upstream is benched.
const FAILS_TO_BENCH: u32 = 2;
const BENCH_BASE: Duration = Duration::from_secs(5);
const BENCH_MAX: Duration = Duration::from_secs(120);

struct Slot {
    upstream: Arc<dyn Upstream>,
    failures: AtomicU32,
    /// Benched until `epoch + this many ms` (0 = healthy).
    benched_until_ms: AtomicU64,
}

/// Health snapshot of one upstream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpstreamHealth {
    pub name: &'static str,
    pub healthy: bool,
    pub consecutive_failures: u32,
}

/// Tries upstreams in configured order. Healthy upstreams are tried first;
/// benched ones (exponential backoff after repeated failures) are tried last
/// so the vault keeps answering even if every upstream is flapping.
pub struct FailoverUpstream {
    slots: Vec<Slot>,
    timeout: Duration,
    epoch: Instant,
}

impl std::fmt::Debug for FailoverUpstream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FailoverUpstream")
            .field("health", &self.health())
            .finish()
    }
}

impl FailoverUpstream {
    pub fn new(upstreams: Vec<Arc<dyn Upstream>>, timeout: Duration) -> Self {
        Self {
            slots: upstreams
                .into_iter()
                .map(|upstream| Slot {
                    upstream,
                    failures: AtomicU32::new(0),
                    benched_until_ms: AtomicU64::new(0),
                })
                .collect(),
            timeout,
            epoch: Instant::now(),
        }
    }

    fn now_ms(&self) -> u64 {
        self.epoch.elapsed().as_millis() as u64
    }

    fn is_healthy(&self, s: &Slot) -> bool {
        s.benched_until_ms.load(Relaxed) <= self.now_ms()
    }

    pub fn health(&self) -> Vec<UpstreamHealth> {
        self.slots
            .iter()
            .map(|s| UpstreamHealth {
                name: s.upstream.name(),
                healthy: self.is_healthy(s),
                consecutive_failures: s.failures.load(Relaxed),
            })
            .collect()
    }

    fn record_success(&self, s: &Slot) {
        s.failures.store(0, Relaxed);
        s.benched_until_ms.store(0, Relaxed);
    }

    fn record_failure(&self, s: &Slot) {
        let n = s.failures.fetch_add(1, Relaxed) + 1;
        if n >= FAILS_TO_BENCH {
            let exp = (n - FAILS_TO_BENCH).min(5);
            let bench = (BENCH_BASE * 2u32.pow(exp)).min(BENCH_MAX);
            s.benched_until_ms
                .store(self.now_ms() + bench.as_millis() as u64, Relaxed);
        }
    }
}

#[async_trait]
impl Upstream for FailoverUpstream {
    async fn query(&self, wire: &[u8]) -> Result<Vec<u8>> {
        let (healthy, benched): (Vec<&Slot>, Vec<&Slot>) =
            self.slots.iter().partition(|s| self.is_healthy(s));
        let mut last = DnsError::AllUpstreamsFailed;
        for s in healthy.into_iter().chain(benched) {
            match tokio::time::timeout(self.timeout, s.upstream.query(wire)).await {
                Ok(Ok(resp)) => {
                    self.record_success(s);
                    return Ok(resp);
                }
                Ok(Err(e)) => {
                    tracing::debug!(upstream = s.upstream.name(), error = %e, "upstream failed");
                    self.record_failure(s);
                    last = e;
                }
                Err(_) => {
                    tracing::debug!(upstream = s.upstream.name(), "upstream timed out");
                    self.record_failure(s);
                    last = DnsError::Timeout;
                }
            }
        }
        Err(last)
    }

    fn name(&self) -> &'static str {
        "failover"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;

    struct Fixed {
        name: &'static str,
        ok: bool,
        delay: Duration,
        calls: AtomicUsize,
    }

    #[async_trait]
    impl Upstream for Fixed {
        async fn query(&self, wire: &[u8]) -> Result<Vec<u8>> {
            self.calls.fetch_add(1, Relaxed);
            tokio::time::sleep(self.delay).await;
            if self.ok {
                let mut r = wire.to_vec();
                r[2] |= 0x80;
                Ok(r)
            } else {
                Err(DnsError::upstream(self.name, "down"))
            }
        }
        fn name(&self) -> &'static str {
            self.name
        }
    }

    fn fixed(name: &'static str, ok: bool, delay_ms: u64) -> Arc<Fixed> {
        Arc::new(Fixed {
            name,
            ok,
            delay: Duration::from_millis(delay_ms),
            calls: AtomicUsize::new(0),
        })
    }

    #[tokio::test]
    async fn fails_over_and_benches() {
        let bad = fixed("bad", false, 0);
        let slow = fixed("slow", true, 500);
        let good = fixed("good", true, 0);
        let f = FailoverUpstream::new(
            vec![bad.clone(), slow.clone(), good.clone()],
            Duration::from_millis(100),
        );
        let q = [0u8; 12];
        for _ in 0..3 {
            assert!(f.query(&q).await.is_ok());
        }
        let h = f.health();
        assert!(!h[0].healthy && !h[1].healthy && h[2].healthy);
        // Benched upstreams are tried after healthy ones.
        let before = bad.calls.load(Relaxed);
        assert!(f.query(&q).await.is_ok());
        assert_eq!(bad.calls.load(Relaxed), before);
        assert_eq!(good.calls.load(Relaxed), 4);
    }

    #[tokio::test]
    async fn all_down_errors() {
        let f = FailoverUpstream::new(
            vec![fixed("a", false, 0), fixed("b", false, 0)],
            Duration::from_millis(50),
        );
        assert!(f.query(&[0u8; 12]).await.is_err());
    }
}
