//! Zeroizing secret containers with redacted `Debug` and constant-time equality.

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Fixed-size secret (keys, PSKs, nonces that must not leak).
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Secret<const N: usize>([u8; N]);

impl<const N: usize> Secret<N> {
    pub const fn new(bytes: [u8; N]) -> Self {
        Self(bytes)
    }

    pub fn zero() -> Self {
        Self([0u8; N])
    }

    /// Fill from the OS CSPRNG.
    pub fn random() -> Self {
        let mut b = [0u8; N];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut b);
        Self(b)
    }

    pub fn expose(&self) -> &[u8; N] {
        &self.0
    }

    pub fn expose_mut(&mut self) -> &mut [u8; N] {
        &mut self.0
    }

    pub fn is_zero(&self) -> bool {
        self.0.ct_eq(&[0u8; N]).into()
    }

    pub fn from_slice(s: &[u8]) -> Option<Self> {
        let arr: [u8; N] = s.try_into().ok()?;
        Some(Self(arr))
    }

    pub fn to_base64(&self) -> String {
        B64.encode(self.0)
    }

    pub fn from_base64(s: &str) -> Option<Self> {
        let mut v = B64.decode(s.trim()).ok()?;
        let out = Self::from_slice(&v);
        v.zeroize();
        out
    }
}

impl<const N: usize> PartialEq for Secret<N> {
    fn eq(&self, other: &Self) -> bool {
        self.0.ct_eq(&other.0).into()
    }
}
impl<const N: usize> Eq for Secret<N> {}

impl<const N: usize> std::fmt::Debug for Secret<N> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Secret<{N}>(REDACTED)")
    }
}

impl<const N: usize> Serialize for Secret<N> {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut enc = self.to_base64();
        let r = s.serialize_str(&enc);
        enc.zeroize();
        r
    }
}

impl<'de, const N: usize> Deserialize<'de> for Secret<N> {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let mut s = String::deserialize(d)?;
        let out = Self::from_base64(&s)
            .ok_or_else(|| serde::de::Error::custom(format!("expected {N}-byte base64 secret")));
        s.zeroize();
        out
    }
}

/// Variable-length secret buffer (session buffers, tokens, decapsulated material).
#[derive(Clone, Default, Zeroize, ZeroizeOnDrop)]
pub struct SecretVec(Vec<u8>);

impl SecretVec {
    pub fn new(v: Vec<u8>) -> Self {
        Self(v)
    }
    pub fn with_capacity(n: usize) -> Self {
        Self(Vec::with_capacity(n))
    }
    pub fn expose(&self) -> &[u8] {
        &self.0
    }
    pub fn expose_mut(&mut self) -> &mut Vec<u8> {
        &mut self.0
    }
    pub fn len(&self) -> usize {
        self.0.len()
    }
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl PartialEq for SecretVec {
    fn eq(&self, other: &Self) -> bool {
        self.0.len() == other.0.len() && bool::from(self.0.ct_eq(&other.0))
    }
}
impl Eq for SecretVec {}

impl std::fmt::Debug for SecretVec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SecretVec(len={}, REDACTED)", self.0.len())
    }
}

impl Serialize for SecretVec {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut enc = B64.encode(&self.0);
        let r = s.serialize_str(&enc);
        enc.zeroize();
        r
    }
}

impl<'de> Deserialize<'de> for SecretVec {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let mut s = String::deserialize(d)?;
        let out = B64
            .decode(s.trim())
            .map(SecretVec)
            .map_err(serde::de::Error::custom);
        s.zeroize();
        out
    }
}

/// 32-byte key alias used throughout (X25519 private keys, PSKs, tokens).
pub type Key32 = Secret<32>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_is_redacted() {
        let s = Key32::new([7u8; 32]);
        let d = format!("{s:?}");
        assert!(!d.contains('7'));
        assert!(d.contains("REDACTED"));
        let v = SecretVec::new(vec![1, 2, 3]);
        assert!(format!("{v:?}").contains("REDACTED"));
    }

    #[test]
    fn serde_roundtrip() {
        let s = Key32::random();
        let j = serde_json::to_string(&s).unwrap();
        let back: Key32 = serde_json::from_str(&j).unwrap();
        assert_eq!(s, back);
        assert!(serde_json::from_str::<Key32>("\"AAAA\"").is_err());
    }

    #[test]
    fn zeroize_clears() {
        let mut s = Key32::new([9u8; 32]);
        s.zeroize();
        assert!(s.is_zero());
    }
}
