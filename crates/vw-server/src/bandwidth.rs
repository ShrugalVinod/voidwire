//! Per-session token-bucket rate limiting (ARCHITECTURE.md §8.1).
//!
//! Rates are in bits per second as carried by invites and token tiers; `0`
//! means unlimited (the node owner's devices and the top tier).

use std::time::{Duration, Instant};

/// Minimum burst size: enough for a few full-size packets so that low rates
/// never stall a single datagram forever.
pub const MIN_BURST_BYTES: u64 = 16 * 1024;
/// Burst window: the bucket holds this much time's worth of traffic.
pub const BURST_WINDOW: Duration = Duration::from_millis(250);

/// A token bucket measured in bytes.
#[derive(Debug, Clone)]
pub struct TokenBucket {
    /// Refill rate in bytes per second (`0` = unlimited).
    rate_bytes: u64,
    capacity: u64,
    /// Available tokens, scaled by 1e9 (byte-nanoseconds / second) to keep the
    /// arithmetic exact in integers.
    tokens_scaled: u128,
    last: Instant,
}

const SCALE: u128 = 1_000_000_000;

impl TokenBucket {
    /// A bucket for `bandwidth_bps` bits per second, starting full.
    pub fn new(bandwidth_bps: u64, now: Instant) -> Self {
        let rate_bytes = bandwidth_bps / 8;
        let window = (rate_bytes as u128 * BURST_WINDOW.as_nanos() / SCALE) as u64;
        let capacity = window.max(MIN_BURST_BYTES);
        Self {
            rate_bytes,
            capacity,
            tokens_scaled: capacity as u128 * SCALE,
            last: now,
        }
    }

    /// An unlimited bucket.
    pub fn unlimited(now: Instant) -> Self {
        Self::new(0, now)
    }

    pub fn is_unlimited(&self) -> bool {
        self.rate_bytes == 0
    }

    /// Bucket capacity in bytes.
    pub fn capacity(&self) -> u64 {
        self.capacity
    }

    /// Refill rate in bytes per second.
    pub fn rate_bytes(&self) -> u64 {
        self.rate_bytes
    }

    fn refill(&mut self, now: Instant) {
        let elapsed = now.saturating_duration_since(self.last).as_nanos();
        self.last = self.last.max(now);
        let add = elapsed.saturating_mul(self.rate_bytes as u128);
        let cap = self.capacity as u128 * SCALE;
        self.tokens_scaled = self.tokens_scaled.saturating_add(add).min(cap);
    }

    /// Whole bytes currently available.
    pub fn available(&mut self, now: Instant) -> u64 {
        if self.is_unlimited() {
            return u64::MAX;
        }
        self.refill(now);
        (self.tokens_scaled / SCALE) as u64
    }

    /// Take `bytes` if available; returns false (and takes nothing) otherwise.
    pub fn try_consume(&mut self, bytes: usize, now: Instant) -> bool {
        if self.is_unlimited() {
            return true;
        }
        self.refill(now);
        let need = bytes as u128 * SCALE;
        if self.tokens_scaled >= need {
            self.tokens_scaled -= need;
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unlimited_never_blocks() {
        let now = Instant::now();
        let mut b = TokenBucket::unlimited(now);
        assert!(b.is_unlimited());
        for _ in 0..10_000 {
            assert!(b.try_consume(65_535, now));
        }
    }

    #[test]
    fn rate_and_burst_math() {
        let t0 = Instant::now();
        // 50 Mbps = 6.25 MB/s; burst window 250 ms = 1_562_500 bytes.
        let mut b = TokenBucket::new(50_000_000, t0);
        assert_eq!(b.rate_bytes(), 6_250_000);
        assert_eq!(b.capacity(), 1_562_500);
        assert_eq!(b.available(t0), 1_562_500);
        assert!(b.try_consume(1_562_500, t0));
        assert!(!b.try_consume(1, t0));
        // 1 ms later exactly 6250 bytes are back.
        let t1 = t0 + Duration::from_millis(1);
        assert_eq!(b.available(t1), 6_250);
        assert!(!b.try_consume(6_251, t1));
        assert!(b.try_consume(6_250, t1));
        assert_eq!(b.available(t1), 0);
        // Refill is capped at capacity.
        let t2 = t1 + Duration::from_secs(10);
        assert_eq!(b.available(t2), 1_562_500);
    }

    #[test]
    fn low_rates_get_minimum_burst_and_sustained_rate_holds() {
        let t0 = Instant::now();
        let mut b = TokenBucket::new(80_000, t0); // 10 kB/s
        assert_eq!(b.capacity(), MIN_BURST_BYTES);
        assert!(b.try_consume(MIN_BURST_BYTES as usize, t0));
        // Over 10 simulated seconds, ~100 kB pass in 1000-byte packets.
        let mut sent = 0u64;
        for ms in 1..=10_000u64 {
            let now = t0 + Duration::from_millis(ms);
            while b.try_consume(1000, now) {
                sent += 1000;
            }
        }
        assert_eq!(sent, 100_000);
    }

    #[test]
    fn time_going_backwards_is_harmless() {
        let t0 = Instant::now() + Duration::from_secs(5);
        let mut b = TokenBucket::new(8_000_000, t0);
        let cap = b.capacity();
        assert!(b.try_consume(cap as usize, t0));
        assert_eq!(b.available(t0 - Duration::from_secs(1)), 0);
    }
}
