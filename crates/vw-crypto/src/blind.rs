//! Chaumian blind-signature session tokens (ARCHITECTURE.md §8).
//!
//! RFC 9474 RSABSSA-SHA384-PSS-Randomized with one 2048-bit issuer key per
//! bandwidth tier. Flow:
//!
//! 1. client: [`prepare_token`]`(&pk)` → ([`BlindRequest`], [`PendingToken`])
//! 2. issuer: [`blind_sign`]`(&sk, &request)` → blind signature bytes
//! 3. client: [`finalize`]`(pending, &blind_sig)` → [`SessionToken`]
//! 4. node:   [`verify`]`(&pk, &token)` and [`SpentSet::spend`]
//!
//! The issuer only ever sees the blinded message; the finalized
//! `(randomizer, msg, sig)` triple is unlinkable to it.
//!
//! # Token wire layout
//!
//! ```text
//! tier u8 | msg[32] | randomizer[32] | sig[256]      (321 bytes)
//! ```
//!
//! `msg` is 32 random bytes chosen by the client; `randomizer` is the RFC 9474
//! §4.1 message randomizer (required by the Randomized variant, the signed
//! message is `randomizer || msg`); `sig` is the 2048-bit RSA-PSS signature.
//! ARCHITECTURE.md's `tier | msg | sig` is this layout with the randomizer
//! counted as part of the signature material.

use std::collections::HashSet;

use blind_rsa_signatures::{
    BlindMessage, BlindingResult, DefaultRng, KeyPairSha384PSSRandomized, MessageRandomizer,
    PublicKeySha384PSSRandomized, Secret as BlindingSecret, SecretKeySha384PSSRandomized,
    Signature,
};
use vw_core::secret::{Key32, SecretVec};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::{CryptoError, Result};

/// RSA modulus size of every token key.
pub const TOKEN_KEY_BITS: usize = 2048;
/// RSA signature / blinded message length.
pub const RSA_LEN: usize = TOKEN_KEY_BITS / 8;
/// Token `msg` length.
pub const TOKEN_MSG_LEN: usize = 32;
/// RFC 9474 message randomizer length.
pub const RANDOMIZER_LEN: usize = 32;
/// Encoded [`SessionToken`] length.
pub const TOKEN_LEN: usize = 1 + TOKEN_MSG_LEN + RANDOMIZER_LEN + RSA_LEN;

fn backend(_: blind_rsa_signatures::Error) -> CryptoError {
    CryptoError::Backend("RSA blind signature")
}

fn modulus_bits(n: &[u8]) -> usize {
    match n.iter().position(|b| *b != 0) {
        Some(i) => (n.len() - i) * 8 - n[i].leading_zeros() as usize,
        None => 0,
    }
}

fn check_size(pk: &PublicKeySha384PSSRandomized) -> Result<()> {
    if modulus_bits(&pk.components().n()) != TOKEN_KEY_BITS {
        return Err(CryptoError::InvalidKey("token key must be RSA-2048"));
    }
    Ok(())
}

/// Issuer private key for one tier. The RSA key is zeroized on drop.
pub struct TokenIssuerKey {
    tier: u8,
    sk: SecretKeySha384PSSRandomized,
    pk: PublicKeySha384PSSRandomized,
}

impl TokenIssuerKey {
    /// Generate a fresh 2048-bit issuer key for `tier`.
    pub fn generate(tier: u8) -> Result<Self> {
        let kp = KeyPairSha384PSSRandomized::generate(&mut DefaultRng, TOKEN_KEY_BITS)
            .map_err(backend)?;
        Ok(Self {
            tier,
            sk: kp.sk,
            pk: kp.pk,
        })
    }

    fn from_sk(tier: u8, sk: SecretKeySha384PSSRandomized) -> Result<Self> {
        let pk = sk.public_key().map_err(backend)?;
        check_size(&pk)?;
        Ok(Self { tier, sk, pk })
    }

    /// Import a PKCS#8 (or PKCS#1) DER private key.
    pub fn from_der(tier: u8, der: &[u8]) -> Result<Self> {
        let sk = SecretKeySha384PSSRandomized::from_der(der)
            .map_err(|_| CryptoError::InvalidKey("token issuer DER"))?;
        Self::from_sk(tier, sk)
    }

    /// Import a PKCS#8 PEM private key (UTF-8 bytes).
    pub fn from_pem(tier: u8, pem: &[u8]) -> Result<Self> {
        let pem =
            std::str::from_utf8(pem).map_err(|_| CryptoError::InvalidKey("token issuer PEM"))?;
        let sk = SecretKeySha384PSSRandomized::from_pem(pem)
            .map_err(|_| CryptoError::InvalidKey("token issuer PEM"))?;
        Self::from_sk(tier, sk)
    }

    /// Export as PKCS#8 DER in a zeroizing buffer.
    pub fn to_der(&self) -> Result<SecretVec> {
        Ok(SecretVec::new(self.sk.to_der().map_err(backend)?))
    }

    /// Export as PKCS#8 PEM (UTF-8) in a zeroizing buffer.
    pub fn to_pem(&self) -> Result<SecretVec> {
        Ok(SecretVec::new(
            self.sk.to_pem().map_err(backend)?.into_bytes(),
        ))
    }

    /// The tier this key issues for.
    pub fn tier(&self) -> u8 {
        self.tier
    }

    /// Public verification key for clients and nodes.
    pub fn public_key(&self) -> TokenPublicKey {
        TokenPublicKey {
            tier: self.tier,
            pk: self.pk.clone(),
        }
    }
}

impl std::fmt::Debug for TokenIssuerKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TokenIssuerKey")
            .field("tier", &self.tier)
            .field("secret", &"REDACTED")
            .finish()
    }
}

/// Issuer public key for one tier.
#[derive(Clone, PartialEq, Eq)]
pub struct TokenPublicKey {
    tier: u8,
    pk: PublicKeySha384PSSRandomized,
}

impl TokenPublicKey {
    /// The tier of tokens verified by this key.
    pub fn tier(&self) -> u8 {
        self.tier
    }

    /// PKCS#1 DER (`RSAPublicKey`).
    pub fn to_der(&self) -> Result<Vec<u8>> {
        self.pk.to_der().map_err(backend)
    }

    /// RFC 9474 SPKI encoding (`id-RSASSA-PSS` with SHA-384 parameters).
    pub fn to_spki(&self) -> Result<Vec<u8>> {
        self.pk.to_spki().map_err(backend)
    }

    /// Import from DER (PKCS#1 or SPKI) and require a 2048-bit modulus.
    pub fn from_der(tier: u8, der: &[u8]) -> Result<Self> {
        let pk = PublicKeySha384PSSRandomized::from_der(der)
            .or_else(|_| PublicKeySha384PSSRandomized::from_spki(der))
            .map_err(|_| CryptoError::InvalidKey("token public key DER"))?;
        check_size(&pk)?;
        Ok(Self { tier, pk })
    }

    /// Stable key identifier: `BLAKE3(tier || SPKI)`.
    pub fn key_id(&self) -> Result<[u8; 32]> {
        let mut h = blake3::Hasher::new();
        h.update(&[self.tier]);
        h.update(&self.to_spki()?);
        Ok(*h.finalize().as_bytes())
    }
}

impl std::fmt::Debug for TokenPublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let id = self.key_id().map(hex::encode).unwrap_or_default();
        f.debug_struct("TokenPublicKey")
            .field("tier", &self.tier)
            .field("key_id", &id.get(..16).unwrap_or(""))
            .finish()
    }
}

/// The blinded message a client sends to the issuer (256 bytes).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlindRequest(Vec<u8>);

impl BlindRequest {
    /// Wire bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Parse wire bytes (exact length).
    pub fn from_bytes(b: &[u8]) -> Result<Self> {
        if b.len() != RSA_LEN {
            return Err(CryptoError::Length {
                what: "blind request",
                expected: RSA_LEN,
                got: b.len(),
            });
        }
        Ok(Self(b.to_vec()))
    }
}

/// Client-side state between [`prepare_token`] and [`finalize`].
///
/// Holds the blinding factor and the unblinded message; zeroized on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct PendingToken {
    tier: u8,
    msg: Key32,
    randomizer: Key32,
    blinding: SecretVec,
    #[zeroize(skip)]
    pk: PublicKeySha384PSSRandomized,
}

impl std::fmt::Debug for PendingToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PendingToken")
            .field("tier", &self.tier)
            .field("secret", &"REDACTED")
            .finish()
    }
}

/// An unblinded, issuer-signed session token (bearer credential).
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct SessionToken {
    /// Bandwidth tier (selects the verification key).
    pub tier: u8,
    /// Client-chosen random message; the double-spend identifier.
    pub msg: [u8; TOKEN_MSG_LEN],
    /// RFC 9474 message randomizer.
    pub randomizer: [u8; RANDOMIZER_LEN],
    /// RSA-PSS signature over `randomizer || msg` (256 bytes).
    pub sig: Vec<u8>,
}

impl std::fmt::Debug for SessionToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionToken")
            .field("tier", &self.tier)
            .field("secret", &"REDACTED")
            .finish()
    }
}

impl SessionToken {
    /// Encode as `tier u8 | msg[32] | randomizer[32] | sig[256]`.
    pub fn encode(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(TOKEN_LEN);
        b.push(self.tier);
        b.extend_from_slice(&self.msg);
        b.extend_from_slice(&self.randomizer);
        b.extend_from_slice(&self.sig);
        b
    }

    /// Decode with an exact length check (does not verify the signature).
    pub fn decode(b: &[u8]) -> Result<Self> {
        if b.len() != TOKEN_LEN {
            return Err(CryptoError::Length {
                what: "session token",
                expected: TOKEN_LEN,
                got: b.len(),
            });
        }
        let mut msg = [0u8; TOKEN_MSG_LEN];
        msg.copy_from_slice(&b[1..33]);
        let mut randomizer = [0u8; RANDOMIZER_LEN];
        randomizer.copy_from_slice(&b[33..65]);
        Ok(Self {
            tier: b[0],
            msg,
            randomizer,
            sig: b[65..].to_vec(),
        })
    }
}

/// Client: pick a random token message and blind it for `pk`.
pub fn prepare_token(pk: &TokenPublicKey) -> Result<(BlindRequest, PendingToken)> {
    let msg = Key32::random();
    let mut br = pk
        .pk
        .blind(&mut DefaultRng, msg.expose())
        .map_err(backend)?;
    let blinding = SecretVec::new(std::mem::take(&mut br.secret.0));
    let randomizer = br
        .msg_randomizer
        .take()
        .ok_or(CryptoError::Backend("missing RFC 9474 randomizer"))?;
    let randomizer = Key32::new(randomizer.0);
    let request = BlindRequest(std::mem::take(&mut br.blind_message.0));
    Ok((
        request,
        PendingToken {
            tier: pk.tier,
            msg,
            randomizer,
            blinding,
            pk: pk.pk.clone(),
        },
    ))
}

/// Issuer: sign a blinded request. Returns the 256-byte blind signature.
///
/// The caller is responsible for authorizing the request (e.g. a redeemed
/// invite secret) before signing.
pub fn blind_sign(sk: &TokenIssuerKey, request: &BlindRequest) -> Result<Vec<u8>> {
    if request.0.len() != RSA_LEN {
        return Err(CryptoError::Length {
            what: "blind request",
            expected: RSA_LEN,
            got: request.0.len(),
        });
    }
    Ok(sk.sk.blind_sign(&request.0).map_err(backend)?.0)
}

/// Client: unblind the issuer's response into a verified [`SessionToken`].
pub fn finalize(pending: PendingToken, blind_sig: &[u8]) -> Result<SessionToken> {
    if blind_sig.len() != RSA_LEN {
        return Err(CryptoError::Length {
            what: "blind signature",
            expected: RSA_LEN,
            got: blind_sig.len(),
        });
    }
    let mut result = BlindingResult {
        blind_message: BlindMessage(Vec::new()),
        secret: BlindingSecret(pending.blinding.expose().to_vec()),
        msg_randomizer: Some(MessageRandomizer(*pending.randomizer.expose())),
    };
    let sig = pending.pk.finalize(
        &blind_rsa_signatures::BlindSignature(blind_sig.to_vec()),
        &result,
        pending.msg.expose(),
    );
    result.secret.0.zeroize();
    let sig = sig.map_err(|_| CryptoError::BadSignature)?;
    Ok(SessionToken {
        tier: pending.tier,
        msg: *pending.msg.expose(),
        randomizer: *pending.randomizer.expose(),
        sig: sig.0,
    })
}

/// Node: verify a token's tier and RSA signature against `pk`.
pub fn verify(pk: &TokenPublicKey, token: &SessionToken) -> Result<()> {
    if token.tier != pk.tier {
        return Err(CryptoError::TokenRejected("token tier mismatch"));
    }
    if token.sig.len() != RSA_LEN {
        return Err(CryptoError::TokenRejected("token signature length"));
    }
    pk.pk
        .verify(
            &Signature(token.sig.clone()),
            Some(MessageRandomizer(token.randomizer)),
            token.msg,
        )
        .map_err(|_| CryptoError::TokenRejected("token signature invalid"))
}

/// In-RAM set of spent token messages (never persisted).
///
/// Entries are `BLAKE3("vw-token-spent" , tier || msg)` so the set does not
/// retain redeemable credentials. Clear it when the issuing keys rotate.
#[derive(Default)]
pub struct SpentSet {
    spent: HashSet<[u8; 32]>,
}

impl std::fmt::Debug for SpentSet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SpentSet")
            .field("len", &self.spent.len())
            .finish()
    }
}

impl SpentSet {
    /// Empty set.
    pub fn new() -> Self {
        Self::default()
    }

    fn id(token: &SessionToken) -> [u8; 32] {
        let mut h = blake3::Hasher::new_derive_key("vw-token-spent");
        h.update(&[token.tier]);
        h.update(&token.msg);
        *h.finalize().as_bytes()
    }

    /// Whether `token` was already spent.
    pub fn is_spent(&self, token: &SessionToken) -> bool {
        self.spent.contains(&Self::id(token))
    }

    /// Record `token` as spent; fails with [`CryptoError::DoubleSpend`] if it was.
    pub fn spend(&mut self, token: &SessionToken) -> Result<()> {
        if self.spent.insert(Self::id(token)) {
            Ok(())
        } else {
            Err(CryptoError::DoubleSpend)
        }
    }

    /// Verify against `pk` and spend in one step (verification first, so
    /// forged tokens never occupy the set).
    pub fn verify_and_spend(&mut self, pk: &TokenPublicKey, token: &SessionToken) -> Result<()> {
        verify(pk, token)?;
        self.spend(token)
    }

    /// Number of spent tokens.
    pub fn len(&self) -> usize {
        self.spent.len()
    }

    /// True if nothing has been spent.
    pub fn is_empty(&self) -> bool {
        self.spent.is_empty()
    }

    /// Forget all entries (call when the issuing key rotates).
    pub fn clear(&mut self) {
        self.spent.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::OnceLock;

    fn keys() -> &'static (TokenIssuerKey, TokenIssuerKey) {
        static KEYS: OnceLock<(TokenIssuerKey, TokenIssuerKey)> = OnceLock::new();
        KEYS.get_or_init(|| {
            (
                TokenIssuerKey::generate(1).unwrap(),
                TokenIssuerKey::generate(1).unwrap(),
            )
        })
    }

    fn issue(sk: &TokenIssuerKey) -> (BlindRequest, Vec<u8>, SessionToken) {
        let pk = sk.public_key();
        let (req, pending) = prepare_token(&pk).unwrap();
        let bs = blind_sign(sk, &req).unwrap();
        let tok = finalize(pending, &bs).unwrap();
        (req, bs, tok)
    }

    #[test]
    fn issue_finalize_verify() {
        let (sk, _) = keys();
        let pk = sk.public_key();
        let (req, bs, tok) = issue(sk);
        assert_eq!(req.as_bytes().len(), RSA_LEN);
        assert_eq!(bs.len(), RSA_LEN);
        assert_eq!(tok.tier, 1);
        verify(&pk, &tok).unwrap();

        let enc = tok.encode();
        assert_eq!(enc.len(), TOKEN_LEN);
        assert_eq!(enc[0], 1);
        assert_eq!(&enc[1..33], &tok.msg);
        assert_eq!(&enc[33..65], &tok.randomizer);
        let back = SessionToken::decode(&enc).unwrap();
        assert_eq!(back, tok);
        verify(&pk, &back).unwrap();
        assert!(SessionToken::decode(&enc[..TOKEN_LEN - 1]).is_err());
        assert!(format!("{tok:?}").contains("REDACTED"));
    }

    #[test]
    fn unlinkability_sanity() {
        let (sk, _) = keys();
        let (req, bs, tok) = issue(sk);
        // The issuer's view (blinded message, blind signature) shares nothing
        // with the redeemed token.
        assert_ne!(req.as_bytes(), tok.sig.as_slice());
        assert_ne!(bs, tok.sig);
        let r = req.as_bytes();
        assert!(!r.windows(32).any(|w| w == tok.msg));
        assert!(!bs.windows(32).any(|w| w == tok.msg));
        // Two tokens for the same key have independent messages.
        let (_, _, tok2) = issue(sk);
        assert_ne!(tok.msg, tok2.msg);
        assert_ne!(tok.randomizer, tok2.randomizer);
    }

    #[test]
    fn double_spend_rejected() {
        let (sk, _) = keys();
        let pk = sk.public_key();
        let (_, _, tok) = issue(sk);
        let mut spent = SpentSet::new();
        spent.verify_and_spend(&pk, &tok).unwrap();
        assert!(spent.is_spent(&tok));
        assert_eq!(
            spent.verify_and_spend(&pk, &tok).unwrap_err(),
            CryptoError::DoubleSpend
        );
        assert_eq!(spent.len(), 1);
        spent.clear();
        assert!(spent.is_empty());
    }

    #[test]
    fn wrong_key_tier_or_tamper_rejected() {
        let (sk, other) = keys();
        let (_, _, tok) = issue(sk);
        assert!(verify(&other.public_key(), &tok).is_err());

        let mut spent = SpentSet::new();
        assert!(spent.verify_and_spend(&other.public_key(), &tok).is_err());
        assert!(spent.is_empty(), "forged tokens must not be recorded");

        let mut t = tok.clone();
        t.msg[0] ^= 1;
        assert!(verify(&sk.public_key(), &t).is_err());
        let mut t = tok.clone();
        t.randomizer[0] ^= 1;
        assert!(verify(&sk.public_key(), &t).is_err());
        let mut t = tok.clone();
        t.tier = 2;
        assert_eq!(
            verify(&sk.public_key(), &t).unwrap_err(),
            CryptoError::TokenRejected("token tier mismatch")
        );

        // A blind signature from the wrong key fails finalization.
        // (the wrong key may also refuse outright when the blinded message does
        // not fit its modulus; both outcomes reject the token)
        let (req, pending) = prepare_token(&sk.public_key()).unwrap();
        if let Ok(bs) = blind_sign(other, &req) {
            assert_eq!(
                finalize(pending, &bs).unwrap_err(),
                CryptoError::BadSignature
            );
        }
        let (_, pending) = prepare_token(&sk.public_key()).unwrap();
        assert!(finalize(pending, &[0u8; 10]).is_err());
        assert!(BlindRequest::from_bytes(&[0u8; 255]).is_err());
    }

    #[test]
    fn key_serialization_roundtrip() {
        let (sk, _) = keys();
        let der = sk.to_der().unwrap();
        let back = TokenIssuerKey::from_der(1, der.expose()).unwrap();
        assert_eq!(back.public_key(), sk.public_key());
        let pem = sk.to_pem().unwrap();
        assert!(pem.expose().starts_with(b"-----BEGIN PRIVATE KEY-----"));
        let back = TokenIssuerKey::from_pem(1, pem.expose()).unwrap();
        assert_eq!(back.public_key(), sk.public_key());
        assert!(TokenIssuerKey::from_der(1, b"garbage").is_err());

        let pk = sk.public_key();
        let from_der = TokenPublicKey::from_der(1, &pk.to_der().unwrap()).unwrap();
        let from_spki = TokenPublicKey::from_der(1, &pk.to_spki().unwrap()).unwrap();
        assert_eq!(from_der, pk);
        assert_eq!(from_spki, pk);
        assert_eq!(pk.key_id().unwrap(), from_spki.key_id().unwrap());
        assert_ne!(
            pk.key_id().unwrap(),
            TokenPublicKey::from_der(2, &pk.to_der().unwrap())
                .unwrap()
                .key_id()
                .unwrap()
        );

        // Tokens from a re-imported key still verify.
        let (_, _, tok) = issue(&back);
        verify(&pk, &tok).unwrap();
        assert!(format!("{sk:?}").contains("REDACTED"));
    }
}
