//! Hybrid key-exchange primitives: ephemeral X25519 and ML-KEM-1024 (FIPS 203).
//!
//! Both halves are combined by [`crate::kdf::derive_session_keys`]; an
//! attacker must break X25519 *and* ML-KEM-1024 to recover the PSK.

use ml_kem::array::Array;
use ml_kem::{Decapsulate, Encapsulate, KeyExport, TryKeyInit};
use vw_core::secret::{Key32, Secret};
use x25519_dalek::{EphemeralSecret, PublicKey};
use zeroize::Zeroize;

use crate::error::{CryptoError, Result};

/// X25519 public key / shared secret length.
pub const X25519_LEN: usize = 32;
/// ML-KEM-1024 encapsulation key length.
pub const MLKEM_EK_LEN: usize = 1568;
/// ML-KEM-1024 ciphertext length.
pub const MLKEM_CT_LEN: usize = 1568;
/// ML-KEM shared secret length.
pub const MLKEM_SS_LEN: usize = 32;
/// ML-KEM decapsulation key seed length (`d || z`, FIPS 203 §7.1).
pub const MLKEM_SEED_LEN: usize = 64;

/// A single-use X25519 key pair. The secret scalar is zeroized on drop and is
/// consumed by [`X25519Ephemeral::diffie_hellman`], so it can never be reused.
pub struct X25519Ephemeral {
    secret: EphemeralSecret,
    public: [u8; 32],
}

impl X25519Ephemeral {
    /// Generate from the OS CSPRNG.
    pub fn generate() -> Self {
        let secret = EphemeralSecret::random();
        let public = PublicKey::from(&secret).to_bytes();
        Self { secret, public }
    }

    /// Our public key.
    pub fn public(&self) -> [u8; 32] {
        self.public
    }

    /// Complete the exchange, rejecting low-order peer keys (all-zero output).
    pub fn diffie_hellman(self, peer_public: &[u8; 32]) -> Result<Key32> {
        let shared = self.secret.diffie_hellman(&PublicKey::from(*peer_public));
        if !shared.was_contributory() {
            return Err(CryptoError::NonContributory);
        }
        Ok(Key32::new(shared.to_bytes()))
    }
}

impl std::fmt::Debug for X25519Ephemeral {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("X25519Ephemeral")
            .field("secret", &"REDACTED")
            .finish_non_exhaustive()
    }
}

/// An ML-KEM-1024 decapsulation key with its serialized encapsulation key.
///
/// The decapsulation key (and the seed it is derived from) is zeroized on drop.
pub struct MlKemKeypair {
    dk: ml_kem::DecapsulationKey1024,
    ek: Vec<u8>,
}

impl MlKemKeypair {
    /// Generate a fresh key pair from a 64-byte OS-random seed.
    pub fn generate() -> Self {
        let seed = Secret::<MLKEM_SEED_LEN>::random();
        Self::from_seed(&seed)
    }

    /// Deterministically derive the key pair from a 64-byte seed (`d || z`).
    pub fn from_seed(seed: &Secret<MLKEM_SEED_LEN>) -> Self {
        let mut arr: ml_kem::Seed = Array::from(*seed.expose());
        let dk = ml_kem::DecapsulationKey1024::from_seed(arr);
        arr[..].zeroize();
        let ek = dk.encapsulation_key().to_bytes().as_slice().to_vec();
        Self { dk, ek }
    }

    /// The 1568-byte encapsulation key to send to the peer.
    pub fn encapsulation_key(&self) -> &[u8] {
        &self.ek
    }

    /// Decapsulate a 1568-byte ciphertext. ML-KEM uses implicit rejection: a
    /// tampered ciphertext yields an unrelated pseudo-random secret, which the
    /// VWCP key confirmation then rejects.
    pub fn decapsulate(&self, ct: &[u8]) -> Result<Key32> {
        if ct.len() != MLKEM_CT_LEN {
            return Err(CryptoError::Length {
                what: "ML-KEM ciphertext",
                expected: MLKEM_CT_LEN,
                got: ct.len(),
            });
        }
        let ct = ml_kem::ml_kem_1024::Ciphertext::try_from(ct)
            .map_err(|_| CryptoError::Malformed("ML-KEM ciphertext"))?;
        let mut ss = self.dk.decapsulate(&ct);
        let out = Key32::from_slice(ss.as_slice());
        ss[..].zeroize();
        out.ok_or(CryptoError::Backend("ML-KEM shared secret size"))
    }
}

impl std::fmt::Debug for MlKemKeypair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MlKemKeypair")
            .field("dk", &"REDACTED")
            .finish_non_exhaustive()
    }
}

/// Encapsulate to a peer's 1568-byte ML-KEM-1024 encapsulation key.
///
/// Returns `(ciphertext[1568], shared_secret)`. Invalid keys (wrong length or
/// failing the FIPS 203 modulus check) are rejected.
pub fn mlkem_encapsulate(ek: &[u8]) -> Result<(Vec<u8>, Key32)> {
    if ek.len() != MLKEM_EK_LEN {
        return Err(CryptoError::Length {
            what: "ML-KEM encapsulation key",
            expected: MLKEM_EK_LEN,
            got: ek.len(),
        });
    }
    let ek = <ml_kem::EncapsulationKey1024 as TryKeyInit>::new_from_slice(ek)
        .map_err(|_| CryptoError::InvalidKey("ML-KEM encapsulation key"))?;
    let (ct, mut ss) = ek.encapsulate();
    let key = Key32::from_slice(ss.as_slice());
    ss[..].zeroize();
    Ok((
        ct.as_slice().to_vec(),
        key.ok_or(CryptoError::Backend("ML-KEM shared secret size"))?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn x25519_agrees() {
        let a = X25519Ephemeral::generate();
        let b = X25519Ephemeral::generate();
        let (pa, pb) = (a.public(), b.public());
        let sa = a.diffie_hellman(&pb).unwrap();
        let sb = b.diffie_hellman(&pa).unwrap();
        assert_eq!(sa, sb);
        assert!(!sa.is_zero());
    }

    #[test]
    fn x25519_rejects_low_order() {
        let a = X25519Ephemeral::generate();
        assert_eq!(
            a.diffie_hellman(&[0u8; 32]).unwrap_err(),
            CryptoError::NonContributory
        );
        assert!(format!("{:?}", X25519Ephemeral::generate()).contains("REDACTED"));
    }

    #[test]
    fn mlkem_roundtrip_and_sizes() {
        let kp = MlKemKeypair::generate();
        assert_eq!(kp.encapsulation_key().len(), MLKEM_EK_LEN);
        let (ct, ss) = mlkem_encapsulate(kp.encapsulation_key()).unwrap();
        assert_eq!(ct.len(), MLKEM_CT_LEN);
        assert_eq!(kp.decapsulate(&ct).unwrap(), ss);
    }

    #[test]
    fn mlkem_implicit_rejection_and_length_checks() {
        let kp = MlKemKeypair::generate();
        let (mut ct, ss) = mlkem_encapsulate(kp.encapsulation_key()).unwrap();
        ct[10] ^= 1;
        assert_ne!(kp.decapsulate(&ct).unwrap(), ss);
        assert!(kp.decapsulate(&ct[..100]).is_err());
        assert!(mlkem_encapsulate(&[0u8; 10]).is_err());
        // Coefficients >= q fail the FIPS 203 encapsulation-key check.
        assert!(mlkem_encapsulate(&[0xff; MLKEM_EK_LEN]).is_err());
    }

    #[test]
    fn mlkem_seed_is_deterministic() {
        let seed = Secret::<64>::new([5; 64]);
        let a = MlKemKeypair::from_seed(&seed);
        let b = MlKemKeypair::from_seed(&seed);
        assert_eq!(a.encapsulation_key(), b.encapsulation_key());
        let (ct, ss) = mlkem_encapsulate(a.encapsulation_key()).unwrap();
        assert_eq!(b.decapsulate(&ct).unwrap(), ss);
    }
}
