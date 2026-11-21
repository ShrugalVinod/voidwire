//! WireGuard protocol timer constants (whitepaper §6, ARCHITECTURE.md §7).

use std::time::Duration;

/// Initiate a new handshake after this many messages on a session.
pub const REKEY_AFTER_MESSAGES: u64 = 1 << 60;
/// Refuse to use a session after this many messages.
pub const REJECT_AFTER_MESSAGES: u64 = u64::MAX - (1 << 13);
/// The session initiator rekeys after this long.
pub const REKEY_AFTER_TIME: Duration = Duration::from_secs(120);
/// Sessions are unusable after this long.
pub const REJECT_AFTER_TIME: Duration = Duration::from_secs(180);
/// Give up a handshake attempt (and drop queued packets) after this long.
pub const REKEY_ATTEMPT_TIME: Duration = Duration::from_secs(90);
/// Retransmit an unanswered initiation after this long (plus jitter).
pub const REKEY_TIMEOUT: Duration = Duration::from_secs(5);
/// Maximum random jitter added to [`REKEY_TIMEOUT`].
pub const REKEY_TIMEOUT_JITTER_MS: u64 = 333;
/// Passive keepalive delay.
pub const KEEPALIVE_TIMEOUT: Duration = Duration::from_secs(10);
/// All key material is erased after this long without a new handshake.
pub const ZERO_KEYS_AFTER: Duration = Duration::from_secs(3 * 180);
/// Minimum spacing between accepted initiations from one peer (50/s).
pub const MIN_INITIATION_SPACING: Duration = Duration::from_millis(20);
/// Plaintext packets queued while waiting for a session.
pub const MAX_QUEUED_PACKETS: usize = 256;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reject_after_messages_matches_whitepaper() {
        // 2^64 - 2^13 - 1
        assert_eq!(REJECT_AFTER_MESSAGES, u64::MAX - 8192);
        assert_eq!(
            REJECT_AFTER_MESSAGES as u128,
            (1u128 << 64) - (1u128 << 13) - 1
        );
    }
}
