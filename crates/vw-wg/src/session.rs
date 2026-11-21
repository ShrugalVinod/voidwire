//! Transport-data sessions (keypairs) and the anti-replay window.

use std::time::Instant;

use vw_core::secret::Key32;

use crate::error::WgError;
use crate::noise::{self, DATA_HEADER_LEN, DATA_MIN_LEN, TAG_LEN, TYPE_DATA};
use crate::timers::{
    REJECT_AFTER_MESSAGES, REJECT_AFTER_TIME, REKEY_AFTER_MESSAGES, REKEY_AFTER_TIME,
};

/// Size of the sliding anti-replay window in counters.
pub const REPLAY_WINDOW: u64 = 2048;
const BLOCK_BITS: u64 = 64;
/// Ring size in 64-bit blocks; a power of two strictly larger than
/// `REPLAY_WINDOW / 64 + 1` so in-window bits are never recycled.
const RING_BLOCKS: u64 = 64;

/// RFC 6479-style sliding bitmap window (as used by wireguard-go), sized for
/// [`REPLAY_WINDOW`] counters.
#[derive(Clone)]
pub struct ReplayWindow {
    last: u64,
    ring: [u64; RING_BLOCKS as usize],
}

impl Default for ReplayWindow {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for ReplayWindow {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReplayWindow")
            .field("last", &self.last)
            .finish_non_exhaustive()
    }
}

impl ReplayWindow {
    pub fn new() -> Self {
        Self {
            last: 0,
            ring: [0; RING_BLOCKS as usize],
        }
    }

    fn bit(counter: u64) -> (usize, u64) {
        let block = ((counter / BLOCK_BITS) % RING_BLOCKS) as usize;
        (block, 1u64 << (counter % BLOCK_BITS))
    }

    /// Would `counter` be accepted? Does not modify the window, so it can run
    /// before the (expensive) authentication step.
    pub fn check(&self, counter: u64) -> bool {
        if counter >= REJECT_AFTER_MESSAGES {
            return false;
        }
        if counter > self.last {
            return true;
        }
        if self.last - counter >= REPLAY_WINDOW {
            return false;
        }
        let (b, m) = Self::bit(counter);
        self.ring[b] & m == 0
    }

    /// Mark `counter` as seen (call only after successful authentication).
    /// Returns false if it was a replay.
    pub fn update(&mut self, counter: u64) -> bool {
        if !self.check(counter) {
            return false;
        }
        if counter > self.last {
            let current = self.last / BLOCK_BITS;
            let target = counter / BLOCK_BITS;
            let diff = (target - current).min(RING_BLOCKS);
            for i in 1..=diff {
                self.ring[((current + i) % RING_BLOCKS) as usize] = 0;
            }
            self.last = counter;
        }
        let (b, m) = Self::bit(counter);
        self.ring[b] |= m;
        true
    }

    /// Highest counter seen so far.
    pub fn last(&self) -> u64 {
        self.last
    }
}

/// One direction-pair of transport keys bound to a pair of indices.
pub struct Session {
    pub(crate) local_index: u32,
    pub(crate) remote_index: u32,
    send_key: Key32,
    recv_key: Key32,
    send_counter: u64,
    replay: ReplayWindow,
    pub(crate) created: Instant,
    /// True when we sent the initiation that produced this session.
    pub(crate) we_initiated: bool,
}

impl std::fmt::Debug for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Session")
            .field("local_index", &self.local_index)
            .field("remote_index", &self.remote_index)
            .field("send_counter", &self.send_counter)
            .field("we_initiated", &self.we_initiated)
            .finish_non_exhaustive()
    }
}

impl Session {
    pub(crate) fn new(
        local_index: u32,
        remote_index: u32,
        send_key: Key32,
        recv_key: Key32,
        created: Instant,
        we_initiated: bool,
    ) -> Self {
        Self {
            local_index,
            remote_index,
            send_key,
            recv_key,
            send_counter: 0,
            replay: ReplayWindow::new(),
            created,
            we_initiated,
        }
    }

    /// Past REJECT_AFTER_TIME or the message limit: unusable in both directions.
    pub fn expired(&self, now: Instant) -> bool {
        now.saturating_duration_since(self.created) >= REJECT_AFTER_TIME
            || self.send_counter >= REJECT_AFTER_MESSAGES
            || self.replay.last() >= REJECT_AFTER_MESSAGES
    }

    /// Whether the sender should start a new handshake (whitepaper §6.2).
    pub fn needs_rekey(&self, now: Instant) -> bool {
        self.send_counter >= REKEY_AFTER_MESSAGES
            || (self.we_initiated
                && now.saturating_duration_since(self.created) >= REKEY_AFTER_TIME)
    }

    /// Next sending counter value.
    pub fn send_counter(&self) -> u64 {
        self.send_counter
    }

    /// Encrypt one transport data message. `padded_len >= plaintext.len()`
    /// zero bytes of plaintext are sealed (WireGuard 16-byte padding).
    pub(crate) fn encrypt(
        &mut self,
        plaintext: &[u8],
        padded_len: usize,
        reserved: [u8; 3],
        now: Instant,
    ) -> Result<Vec<u8>, WgError> {
        if self.expired(now) {
            return Err(WgError::Expired);
        }
        let counter = self.send_counter;
        self.send_counter += 1;
        let padded_len = padded_len.max(plaintext.len());
        let mut out = Vec::with_capacity(DATA_HEADER_LEN + padded_len + TAG_LEN);
        out.push(TYPE_DATA);
        out.extend_from_slice(&reserved);
        out.extend_from_slice(&self.remote_index.to_le_bytes());
        out.extend_from_slice(&counter.to_le_bytes());
        out.extend_from_slice(plaintext);
        out.resize(DATA_HEADER_LEN + padded_len, 0);
        let mut body = out.split_off(DATA_HEADER_LEN);
        noise::aead_seal(self.send_key.expose(), counter, &mut body, &[]);
        out.extend_from_slice(&body);
        Ok(out)
    }

    /// Authenticate and decrypt a transport data message (header included),
    /// updating the replay window. Returns the (still padded) plaintext.
    pub(crate) fn decrypt(&mut self, msg: &[u8], now: Instant) -> Result<Vec<u8>, WgError> {
        if msg.len() < DATA_MIN_LEN {
            return Err(WgError::Malformed);
        }
        if self.expired(now) {
            return Err(WgError::Expired);
        }
        let mut c = [0u8; 8];
        c.copy_from_slice(&msg[8..16]);
        let counter = u64::from_le_bytes(c);
        if !self.replay.check(counter) {
            return Err(WgError::Replay);
        }
        let mut buf = msg[DATA_HEADER_LEN..].to_vec();
        let n = noise::aead_open_in_place(self.recv_key.expose(), counter, &mut buf, &[])?;
        if !self.replay.update(counter) {
            return Err(WgError::Replay);
        }
        buf.truncate(n);
        Ok(buf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn window_basic() {
        let mut w = ReplayWindow::new();
        assert!(w.update(0));
        assert!(!w.update(0));
        assert!(w.update(5));
        assert!(w.update(3));
        assert!(!w.update(3));
        assert!(w.update(4000));
        // 4000 - 2048 = 1952: anything at or below is outside the window.
        assert!(!w.check(1952));
        assert!(w.check(1953));
        assert!(w.update(1953));
        assert!(!w.update(1953));
        assert!(w.update(3999));
        assert!(!w.check(5));
    }

    #[test]
    fn window_large_jump_clears_ring() {
        let mut w = ReplayWindow::new();
        for i in 0..100 {
            assert!(w.update(i));
        }
        assert!(w.update(1_000_000));
        assert!(w.check(1_000_000 - 1));
        assert!(w.check(1_000_000 - 2047));
        assert!(!w.check(1_000_000 - 2048));
        assert!(!w.check(REJECT_AFTER_MESSAGES));
    }

    #[test]
    fn window_every_counter_once() {
        let mut w = ReplayWindow::new();
        // Out-of-order delivery within the window is accepted exactly once.
        let order: Vec<u64> = (0..5000).map(|i| (i * 7919) % 5000).collect();
        let mut accepted = 0;
        for &c in &order {
            if w.update(c) {
                accepted += 1;
            }
            assert!(!w.update(c));
        }
        assert!(accepted > 0);
    }
}
