//! DAITA plaintext handling: bucket padding, padding removal and chaff.
//!
//! Padding is appended as zero bytes *inside* the encrypted plaintext; the
//! receiver strips it using the IP header's length field ([`strip_padding`]).
//! Chaff plaintext starts with `0x00`, which is never a valid IP version
//! nibble, so receivers recognise and silently drop it ([`is_chaff`]).

use std::sync::{Arc, Mutex};
use std::time::Instant;

use vw_core::config::DaitaParams;
use vw_core::transport::ChaffSource;

use crate::driver::Engine;
use crate::error::WgError;

/// First plaintext byte of every chaff packet.
pub const CHAFF_MARKER: u8 = 0x00;

/// Zero-pad `packet` up to the smallest configured bucket that fits it.
/// No-op when DAITA is disabled or the packet exceeds every bucket.
pub fn pad_plaintext(packet: &mut Vec<u8>, params: &DaitaParams) {
    if !params.enabled || packet.is_empty() {
        return;
    }
    let target = params.bucket_for(packet.len());
    if target > packet.len() {
        packet.resize(target, 0);
    }
}

/// Length of the IP packet at the start of `plaintext` (dropping any
/// WireGuard or DAITA padding that follows it).
pub fn strip_padding(plaintext: &[u8]) -> Result<usize, WgError> {
    match plaintext.first().map(|b| b >> 4) {
        Some(4) => {
            if plaintext.len() < 20 {
                return Err(WgError::InvalidPlaintext);
            }
            let total = u16::from_be_bytes([plaintext[2], plaintext[3]]) as usize;
            if total < 20 || total > plaintext.len() {
                return Err(WgError::InvalidPlaintext);
            }
            Ok(total)
        }
        Some(6) => {
            if plaintext.len() < 40 {
                return Err(WgError::InvalidPlaintext);
            }
            let total = 40 + u16::from_be_bytes([plaintext[4], plaintext[5]]) as usize;
            if total > plaintext.len() {
                return Err(WgError::InvalidPlaintext);
            }
            Ok(total)
        }
        _ => Err(WgError::InvalidPlaintext),
    }
}

/// Chaff plaintext of `size` bytes (at least one), starting with [`CHAFF_MARKER`].
/// The body is zeros; it is encrypted before leaving the host.
pub fn chaff_plaintext(size: usize) -> Vec<u8> {
    vec![CHAFF_MARKER; size.max(1)]
}

/// True for decrypted chaff plaintext.
pub fn is_chaff(plaintext: &[u8]) -> bool {
    plaintext.first() == Some(&CHAFF_MARKER)
}

/// [`ChaffSource`] over a shared engine (a [`crate::Peer`] or
/// [`crate::Cascade`]); chaff is encrypted on the outermost session.
pub struct EngineChaff<E: Engine>(pub Arc<Mutex<E>>);

impl<E: Engine> Clone for EngineChaff<E> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<E: Engine> ChaffSource for EngineChaff<E> {
    fn make_chaff(&self, size: usize) -> Option<Vec<u8>> {
        let mut e = self.0.lock().unwrap_or_else(|p| p.into_inner());
        e.chaff(size, Instant::now())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn params() -> DaitaParams {
        DaitaParams {
            enabled: true,
            ..DaitaParams::default()
        }
    }

    #[test]
    fn pads_to_bucket_and_strips() {
        let pkt = vw_core::packet::build_udp(
            "10.0.0.1:1".parse().unwrap(),
            "10.0.0.2:2".parse().unwrap(),
            &[7u8; 100],
            64,
        )
        .unwrap();
        let mut p = pkt.clone();
        pad_plaintext(&mut p, &params());
        assert_eq!(p.len(), 128);
        assert_eq!(strip_padding(&p).unwrap(), pkt.len());
        let mut big = vec![0x45u8; 1300];
        pad_plaintext(&mut big, &params());
        assert_eq!(big.len(), 1300);
        let mut off = pkt.clone();
        pad_plaintext(&mut off, &DaitaParams::default());
        assert_eq!(off, pkt);
    }

    #[test]
    fn strip_v6_and_garbage() {
        let pkt = vw_core::packet::build_udp(
            "[fd00::1]:1".parse().unwrap(),
            "[fd00::2]:2".parse().unwrap(),
            b"abc",
            64,
        )
        .unwrap();
        let mut p = pkt.clone();
        p.resize(256, 0);
        assert_eq!(strip_padding(&p).unwrap(), pkt.len());
        assert!(strip_padding(&[]).is_err());
        assert!(strip_padding(&[0x45, 0, 0xff, 0xff]).is_err());
        assert!(strip_padding(&pkt[..30]).is_err());
    }

    #[test]
    fn chaff_marker() {
        let c = chaff_plaintext(200);
        assert_eq!(c.len(), 200);
        assert!(is_chaff(&c));
        assert!(is_chaff(&chaff_plaintext(0)));
        assert!(!is_chaff(&[0x45]));
        assert!(!is_chaff(&[]));
    }
}
