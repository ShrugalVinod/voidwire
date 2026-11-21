//! Signed runtime attestation envelope.
//!
//! The node daemon collects the facts (binary hash, swap state, logging,
//! tmpfs state dir, uptime); this module only provides the canonical encoding
//! and the Ed25519 envelope. Attestation is *honest-operator evidence*, not a
//! proof: a malicious operator controls the signing key.
//!
//! Canonical encoding (big-endian):
//!
//! ```text
//! ver u8 = 1 | node_identity[32] | nonce[32] | unix_time u64 | uptime_secs u64
//! | flags u8 (bit0 swap_disabled, bit1 logging_off, bit2 ram_only; others 0)
//! | binary_blake3[64] (lowercase hex ASCII)
//! ```
//!
//! `sig = Ed25519(node_identity, "VWATTEST-v1" || canonical)`.
//! The [`SignedAttestation::encode`] form is `canonical || sig[64]`.

use serde::{Deserialize, Serialize};
use vw_core::config::Bytes32;

use crate::error::{CryptoError, Result};
use crate::identity::{self, NodeIdentity, SIGNATURE_LEN};

/// Canonical encoding version.
pub const ATTEST_VERSION: u8 = 1;
/// Signature domain separator.
pub const ATTEST_DOMAIN: &[u8] = b"VWATTEST-v1";
/// Canonical encoding length.
pub const CANONICAL_LEN: usize = 1 + 32 + 32 + 8 + 8 + 1 + 64;

const FLAG_SWAP_DISABLED: u8 = 0b001;
const FLAG_LOGGING_OFF: u8 = 0b010;
const FLAG_RAM_ONLY: u8 = 0b100;

/// Runtime facts reported by a node.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttestationReport {
    /// BLAKE3 of the running binary, 64 lowercase hex characters.
    pub binary_blake3: String,
    /// Swap is disabled system-wide.
    pub swap_disabled: bool,
    /// Persistent logging is disabled.
    pub logging_off: bool,
    /// State directory is on tmpfs (RAM only).
    pub ram_only: bool,
    /// Node process uptime.
    pub uptime_secs: u64,
    /// Time the report was produced (Unix seconds).
    pub unix_time: u64,
    /// Verifier-supplied freshness nonce.
    #[serde(with = "hex32")]
    pub nonce: [u8; 32],
    /// The node's Ed25519 identity.
    pub node_identity: Bytes32,
}

fn valid_hash(h: &str) -> bool {
    h.len() == 64 && h.bytes().all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f'))
}

impl AttestationReport {
    /// Canonical byte encoding (see module docs).
    pub fn canonical(&self) -> Result<Vec<u8>> {
        if !valid_hash(&self.binary_blake3) {
            return Err(CryptoError::Malformed("attestation binary_blake3"));
        }
        let mut flags = 0u8;
        if self.swap_disabled {
            flags |= FLAG_SWAP_DISABLED;
        }
        if self.logging_off {
            flags |= FLAG_LOGGING_OFF;
        }
        if self.ram_only {
            flags |= FLAG_RAM_ONLY;
        }
        let mut b = Vec::with_capacity(CANONICAL_LEN);
        b.push(ATTEST_VERSION);
        b.extend_from_slice(&self.node_identity.0);
        b.extend_from_slice(&self.nonce);
        b.extend_from_slice(&self.unix_time.to_be_bytes());
        b.extend_from_slice(&self.uptime_secs.to_be_bytes());
        b.push(flags);
        b.extend_from_slice(self.binary_blake3.as_bytes());
        Ok(b)
    }

    /// Decode a canonical encoding (strict: version, length, flags, hex).
    pub fn from_canonical(b: &[u8]) -> Result<Self> {
        if b.len() != CANONICAL_LEN {
            return Err(CryptoError::Length {
                what: "attestation report",
                expected: CANONICAL_LEN,
                got: b.len(),
            });
        }
        if b[0] != ATTEST_VERSION {
            return Err(CryptoError::Version(b[0]));
        }
        let flags = b[81];
        if flags & !(FLAG_SWAP_DISABLED | FLAG_LOGGING_OFF | FLAG_RAM_ONLY) != 0 {
            return Err(CryptoError::Malformed("attestation flags"));
        }
        let hash = std::str::from_utf8(&b[82..])
            .map_err(|_| CryptoError::Malformed("attestation binary_blake3"))?;
        if !valid_hash(hash) {
            return Err(CryptoError::Malformed("attestation binary_blake3"));
        }
        let mut id = [0u8; 32];
        id.copy_from_slice(&b[1..33]);
        let mut nonce = [0u8; 32];
        nonce.copy_from_slice(&b[33..65]);
        let mut t = [0u8; 8];
        t.copy_from_slice(&b[65..73]);
        let mut u = [0u8; 8];
        u.copy_from_slice(&b[73..81]);
        Ok(Self {
            binary_blake3: hash.to_owned(),
            swap_disabled: flags & FLAG_SWAP_DISABLED != 0,
            logging_off: flags & FLAG_LOGGING_OFF != 0,
            ram_only: flags & FLAG_RAM_ONLY != 0,
            uptime_secs: u64::from_be_bytes(u),
            unix_time: u64::from_be_bytes(t),
            nonce,
            node_identity: Bytes32(id),
        })
    }

    /// Sign with the node identity, which must equal `self.node_identity`.
    pub fn sign(&self, identity: &NodeIdentity) -> Result<SignedAttestation> {
        if identity.public() != self.node_identity {
            return Err(CryptoError::InvalidKey(
                "attestation signer is not node_identity",
            ));
        }
        let sig = identity.sign(&signing_input(&self.canonical()?));
        Ok(SignedAttestation {
            report: self.clone(),
            sig,
        })
    }
}

fn signing_input(canonical: &[u8]) -> Vec<u8> {
    let mut m = Vec::with_capacity(ATTEST_DOMAIN.len() + canonical.len());
    m.extend_from_slice(ATTEST_DOMAIN);
    m.extend_from_slice(canonical);
    m
}

/// A report plus its Ed25519 signature. Serializes to JSON with `sig` as hex.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedAttestation {
    /// The signed facts.
    pub report: AttestationReport,
    /// `Ed25519(node_identity, "VWATTEST-v1" || canonical)`.
    #[serde(with = "hex64")]
    pub sig: [u8; SIGNATURE_LEN],
}

impl SignedAttestation {
    /// Verify the signature against the identity embedded in the report.
    pub fn verify_signature(&self) -> Result<&AttestationReport> {
        let msg = signing_input(&self.report.canonical()?);
        identity::verify(&self.report.node_identity, &msg, &self.sig)?;
        Ok(&self.report)
    }

    /// Full verification: signature valid, signer is `expected_identity`
    /// (from the node descriptor), and the report echoes `expected_nonce`.
    pub fn verify(
        &self,
        expected_identity: &Bytes32,
        expected_nonce: &[u8; 32],
    ) -> Result<&AttestationReport> {
        if self.report.node_identity != *expected_identity {
            return Err(CryptoError::InvalidKey("attestation from unexpected node"));
        }
        if !bool::from(subtle::ConstantTimeEq::ct_eq(
            &self.report.nonce[..],
            &expected_nonce[..],
        )) {
            return Err(CryptoError::Malformed("attestation nonce mismatch"));
        }
        self.verify_signature()
    }

    /// Binary form: `canonical || sig`.
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut b = self.report.canonical()?;
        b.extend_from_slice(&self.sig);
        Ok(b)
    }

    /// Decode the binary form (does not verify; call [`Self::verify`]).
    pub fn decode(b: &[u8]) -> Result<Self> {
        if b.len() != CANONICAL_LEN + SIGNATURE_LEN {
            return Err(CryptoError::Length {
                what: "signed attestation",
                expected: CANONICAL_LEN + SIGNATURE_LEN,
                got: b.len(),
            });
        }
        let report = AttestationReport::from_canonical(&b[..CANONICAL_LEN])?;
        let mut sig = [0u8; SIGNATURE_LEN];
        sig.copy_from_slice(&b[CANONICAL_LEN..]);
        Ok(Self { report, sig })
    }
}

macro_rules! hex_array {
    ($name:ident, $n:expr) => {
        mod $name {
            use serde::{Deserialize, Deserializer, Serializer};

            pub fn serialize<S: Serializer>(v: &[u8; $n], s: S) -> Result<S::Ok, S::Error> {
                s.serialize_str(&hex::encode(v))
            }

            pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; $n], D::Error> {
                let s = String::deserialize(d)?;
                let v = hex::decode(s.trim()).map_err(serde::de::Error::custom)?;
                v.try_into()
                    .map_err(|_| serde::de::Error::custom(concat!("expected ", $n, " hex bytes")))
            }
        }
    };
}
hex_array!(hex32, 32);
hex_array!(hex64, 64);

#[cfg(test)]
mod tests {
    use super::*;

    fn report(id: &NodeIdentity) -> AttestationReport {
        AttestationReport {
            binary_blake3: blake3::hash(b"voidwire-node").to_hex().to_string(),
            swap_disabled: true,
            logging_off: true,
            ram_only: false,
            uptime_secs: 3_600,
            unix_time: 1_800_000_000,
            nonce: [7; 32],
            node_identity: id.public(),
        }
    }

    #[test]
    fn sign_verify_roundtrip() {
        let id = NodeIdentity::generate();
        let r = report(&id);
        let s = r.sign(&id).unwrap();
        assert_eq!(s.verify(&id.public(), &[7; 32]).unwrap(), &r);
        let enc = s.encode().unwrap();
        assert_eq!(enc.len(), CANONICAL_LEN + 64);
        let back = SignedAttestation::decode(&enc).unwrap();
        assert_eq!(back, s);
        back.verify_signature().unwrap();
        let json = serde_json::to_string(&s).unwrap();
        let from_json: SignedAttestation = serde_json::from_str(&json).unwrap();
        assert_eq!(from_json, s);
    }

    #[test]
    fn canonical_layout() {
        let id = NodeIdentity::generate();
        let r = report(&id);
        let c = r.canonical().unwrap();
        assert_eq!(c.len(), CANONICAL_LEN);
        assert_eq!(c[0], 1);
        assert_eq!(&c[1..33], &id.public().0);
        assert_eq!(&c[33..65], &[7; 32]);
        assert_eq!(&c[65..73], &1_800_000_000u64.to_be_bytes());
        assert_eq!(&c[73..81], &3_600u64.to_be_bytes());
        assert_eq!(c[81], 0b011);
        assert_eq!(&c[82..], r.binary_blake3.as_bytes());
        assert_eq!(AttestationReport::from_canonical(&c).unwrap(), r);
    }

    #[test]
    fn rejects_tampering_and_mismatch() {
        let id = NodeIdentity::generate();
        let s = report(&id).sign(&id).unwrap();
        let mut t = s.clone();
        t.report.ram_only = true;
        assert_eq!(t.verify_signature().unwrap_err(), CryptoError::BadSignature);
        let mut t = s.clone();
        t.sig[3] ^= 1;
        assert!(t.verify_signature().is_err());
        assert!(s.verify(&id.public(), &[8; 32]).is_err());
        assert!(s
            .verify(&NodeIdentity::generate().public(), &[7; 32])
            .is_err());
        let other = NodeIdentity::generate();
        assert!(report(&id).sign(&other).is_err());
        let mut bad = report(&id);
        bad.binary_blake3 = "XYZ".into();
        assert!(bad.sign(&id).is_err());
        let mut enc = s.encode().unwrap();
        enc[81] = 0x80;
        assert!(SignedAttestation::decode(&enc).is_err());
        assert!(SignedAttestation::decode(&enc[..10]).is_err());
    }
}
