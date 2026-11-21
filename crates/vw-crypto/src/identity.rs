//! Ed25519 node identities.
//!
//! A node identity signs VWCP ServerHello transcripts, F2F invites and runtime
//! attestation reports. Verification is strict (RFC 8032 §5.1.7 plus rejection
//! of non-canonical `S`, small-order `R` and weak public keys).

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use vw_core::config::Bytes32;
use vw_core::secret::Key32;

use crate::error::{CryptoError, Result};

/// Ed25519 signature length.
pub const SIGNATURE_LEN: usize = 64;

/// A node's long-term Ed25519 signing key. The secret is zeroized on drop.
pub struct NodeIdentity {
    sk: SigningKey,
}

impl NodeIdentity {
    /// Generate a fresh identity from the OS CSPRNG.
    pub fn generate() -> Self {
        Self::from_seed(&Key32::random())
    }

    /// Rebuild an identity from its 32-byte RFC 8032 seed.
    pub fn from_seed(seed: &Key32) -> Self {
        Self {
            sk: SigningKey::from_bytes(seed.expose()),
        }
    }

    /// Rebuild an identity from raw seed bytes (must be exactly 32).
    pub fn from_seed_bytes(seed: &[u8]) -> Result<Self> {
        let k = Key32::from_slice(seed).ok_or(CryptoError::Length {
            what: "Ed25519 seed",
            expected: 32,
            got: seed.len(),
        })?;
        Ok(Self::from_seed(&k))
    }

    /// Export the 32-byte seed (for sealed storage only).
    pub fn to_seed(&self) -> Key32 {
        Key32::new(self.sk.to_bytes())
    }

    /// The public verification key.
    pub fn public(&self) -> Bytes32 {
        Bytes32(self.sk.verifying_key().to_bytes())
    }

    /// Sign `msg` (pure Ed25519, no prehash).
    pub fn sign(&self, msg: &[u8]) -> [u8; SIGNATURE_LEN] {
        self.sk.sign(msg).to_bytes()
    }
}

impl std::fmt::Debug for NodeIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NodeIdentity")
            .field("public", &self.public())
            .field("secret", &"REDACTED")
            .finish()
    }
}

/// Strictly verify an Ed25519 signature.
pub fn verify(public: &Bytes32, msg: &[u8], sig: &[u8; SIGNATURE_LEN]) -> Result<()> {
    let vk = VerifyingKey::from_bytes(&public.0).map_err(|_| CryptoError::BadSignature)?;
    if vk.is_weak() {
        return Err(CryptoError::BadSignature);
    }
    let sig = Signature::from_bytes(sig);
    vk.verify_strict(msg, &sig)
        .map_err(|_| CryptoError::BadSignature)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_verify_roundtrip() {
        let id = NodeIdentity::generate();
        let sig = id.sign(b"hello");
        verify(&id.public(), b"hello", &sig).unwrap();
        assert_eq!(
            verify(&id.public(), b"hellO", &sig).unwrap_err(),
            CryptoError::BadSignature
        );
        let mut bad = sig;
        bad[0] ^= 1;
        assert!(verify(&id.public(), b"hello", &bad).is_err());
        let other = NodeIdentity::generate();
        assert!(verify(&other.public(), b"hello", &sig).is_err());
    }

    #[test]
    fn seed_roundtrip_and_rfc8032_vector() {
        // RFC 8032 §7.1 TEST 1.
        let seed = hex::decode("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
            .unwrap();
        let id = NodeIdentity::from_seed_bytes(&seed).unwrap();
        assert_eq!(
            hex::encode(id.public().0),
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
        );
        let sig = id.sign(b"");
        assert_eq!(
            hex::encode(sig),
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155\
             5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
        );
        assert_eq!(id.to_seed().expose().as_slice(), seed.as_slice());
        assert!(NodeIdentity::from_seed_bytes(&seed[..31]).is_err());
    }

    #[test]
    fn rejects_weak_key_and_redacts() {
        // The identity point (small order) must never verify anything.
        let mut weak = [0u8; 32];
        weak[0] = 1;
        assert!(verify(&Bytes32(weak), b"", &[0u8; 64]).is_err());
        let id = NodeIdentity::from_seed(&Key32::new([0xAB; 32]));
        let dbg = format!("{id:?}");
        assert!(dbg.contains("REDACTED"));
        assert!(!dbg.to_lowercase().contains("abab"));
    }
}
