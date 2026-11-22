//! Capability checks for VWCP admission (ARCHITECTURE.md §8, §8.1).
//!
//! * [`Tier`] / [`TIERS`]: the node's bandwidth tiers, one RSA blind-token
//!   issuer key each ([`Issuers`]).
//! * [`TokenClaim`]: parsing of the `ClientHello.token` field.
//! * [`SpentLedger`]: double-spend protection for session tokens.
//! * [`InviteTable`]: single-use F2F invite secrets, held only in RAM (as
//!   hashes; the secret itself is never stored).
//! * [`AddressPool`]: client address assignment from `CLIENT_POOL_V4/V6`.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::io::Write;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use vw_core::config::TokenKeyInfo;
use vw_core::consts::{CLIENT_POOL_V4, CLIENT_POOL_V6, NODE_GATEWAY_V4, PROVISIONAL_V4};
use vw_core::{Result, VwError};
use vw_crypto::blind::{self, SessionToken, SpentSet, TokenIssuerKey, TokenPublicKey, TOKEN_LEN};
use vw_crypto::CryptoError;

/// Tier id used for the owner's own devices (never a blind-token tier).
pub const OWNER_TIER: u8 = 0xFF;

/// `ClientHello.token` kind bytes (ARCHITECTURE.md §8.1).
pub const TOKEN_KIND_OWNER: u8 = 0x00;
pub const TOKEN_KIND_SESSION: u8 = 0x01;
pub const TOKEN_KIND_INVITE: u8 = 0x02;

/// One bandwidth tier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Tier {
    pub id: u8,
    /// Bits per second, `0` = unlimited.
    pub bandwidth_bps: u64,
}

/// The node's tiers, ordered by increasing bandwidth (unlimited last).
pub const TIERS: [Tier; 4] = [
    Tier {
        id: 0,
        bandwidth_bps: 10_000_000,
    },
    Tier {
        id: 1,
        bandwidth_bps: 50_000_000,
    },
    Tier {
        id: 2,
        bandwidth_bps: 200_000_000,
    },
    Tier {
        id: 3,
        bandwidth_bps: 0,
    },
];

/// Look up a tier by id.
pub fn tier(id: u8) -> Option<Tier> {
    TIERS.iter().copied().find(|t| t.id == id)
}

/// The tier granted for a requested bandwidth: the fastest limited tier that
/// does not exceed the request (never below the slowest tier). Only an
/// explicit `0` (unlimited) maps to the unlimited tier.
pub fn tier_for_bandwidth(bps: u64) -> Tier {
    if bps == 0 {
        return TIERS[TIERS.len() - 1];
    }
    TIERS
        .iter()
        .rev()
        .copied()
        .find(|t| t.bandwidth_bps != 0 && t.bandwidth_bps <= bps)
        .unwrap_or(TIERS[0])
}

/// Human-readable bandwidth (`50 Mbps`, `unlimited`).
pub fn format_bandwidth(bps: u64) -> String {
    match bps {
        0 => "unlimited".into(),
        b if b % 1_000_000_000 == 0 => format!("{} Gbps", b / 1_000_000_000),
        b if b % 1_000_000 == 0 => format!("{} Mbps", b / 1_000_000),
        b if b % 1_000 == 0 => format!("{} kbps", b / 1_000),
        b => format!("{b} bps"),
    }
}

/// The per-tier RSA blind-token issuer keys.
#[derive(Debug, Default)]
pub struct Issuers {
    keys: BTreeMap<u8, TokenIssuerKey>,
    pubs: BTreeMap<u8, TokenPublicKey>,
}

impl Issuers {
    pub fn new(keys: Vec<TokenIssuerKey>) -> Self {
        let mut s = Self::default();
        for k in keys {
            s.pubs.insert(k.tier(), k.public_key());
            s.keys.insert(k.tier(), k);
        }
        s
    }

    pub fn key(&self, tier: u8) -> Option<&TokenIssuerKey> {
        self.keys.get(&tier)
    }

    pub fn public(&self, tier: u8) -> Option<&TokenPublicKey> {
        self.pubs.get(&tier)
    }

    pub fn tiers(&self) -> impl Iterator<Item = u8> + '_ {
        self.keys.keys().copied()
    }

    /// Descriptor entries (`NodeDescriptor.token_keys`).
    pub fn token_key_infos(&self) -> Result<Vec<TokenKeyInfo>> {
        self.pubs
            .iter()
            .map(|(id, pk)| {
                let t = tier(*id).ok_or_else(|| VwError::Config("unknown token tier".into()))?;
                Ok(TokenKeyInfo {
                    tier: *id,
                    bandwidth_bps: t.bandwidth_bps,
                    spki: B64.encode(pk.to_spki()?),
                })
            })
            .collect()
    }
}

/// A parsed `ClientHello.token`.
pub enum TokenClaim {
    /// `0x00` or empty: owner device (static key must be pre-authorised).
    Owner,
    /// `0x01 || SessionToken`.
    Session(SessionToken),
    /// `0x02 || invite_secret[32]`, carried as its lookup hash.
    Invite([u8; 32]),
}

impl std::fmt::Debug for TokenClaim {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TokenClaim::Owner => f.write_str("Owner"),
            TokenClaim::Session(t) => write!(f, "Session(tier {})", t.tier),
            TokenClaim::Invite(_) => f.write_str("Invite(REDACTED)"),
        }
    }
}

/// Lookup hash of an invite secret (the secret itself is never stored).
pub fn invite_hash(secret: &[u8; 32]) -> [u8; 32] {
    blake3::derive_key("voidwire-node invite-secret v1", secret)
}

/// Parse the token field of a ClientHello.
pub fn parse_token(token: &[u8]) -> std::result::Result<TokenClaim, CryptoError> {
    let Some((&kind, rest)) = token.split_first() else {
        return Ok(TokenClaim::Owner);
    };
    match kind {
        TOKEN_KIND_OWNER if rest.is_empty() => Ok(TokenClaim::Owner),
        TOKEN_KIND_OWNER => Err(CryptoError::TokenRejected("owner token carries data")),
        TOKEN_KIND_SESSION => {
            if rest.len() != TOKEN_LEN {
                return Err(CryptoError::TokenRejected("session token length"));
            }
            Ok(TokenClaim::Session(SessionToken::decode(rest)?))
        }
        TOKEN_KIND_INVITE => {
            let mut secret: [u8; 32] = rest
                .try_into()
                .map_err(|_| CryptoError::TokenRejected("invite secret length"))?;
            let h = invite_hash(&secret);
            zeroize::Zeroize::zeroize(&mut secret);
            Ok(TokenClaim::Invite(h))
        }
        _ => Err(CryptoError::TokenRejected("unknown token kind")),
    }
}

/// Double-spend protection for session tokens.
///
/// Spent tokens live in a [`SpentSet`]; their unlinkable ids are additionally
/// appended to `<state>/spent.ledger` (which is on tmpfs for `--ram-only`
/// nodes) so a process restart cannot re-admit a spent token while the
/// issuer keys are unchanged. The ledger is wiped whenever the keys rotate.
#[derive(Debug, Default)]
pub struct SpentLedger {
    set: SpentSet,
    ids: HashSet<[u8; 32]>,
    file: Option<PathBuf>,
}

fn spent_id(t: &SessionToken) -> [u8; 32] {
    let mut h = blake3::Hasher::new_derive_key("voidwire-node spent-token v1");
    h.update(&[t.tier]);
    h.update(&t.msg);
    *h.finalize().as_bytes()
}

impl SpentLedger {
    /// In-memory only (tests).
    pub fn in_memory() -> Self {
        Self::default()
    }

    /// Load (or create) the persistent ledger at `path`.
    pub fn open(path: &Path) -> Result<Self> {
        let mut ids = HashSet::new();
        match std::fs::read(path) {
            Ok(raw) => {
                for c in raw.chunks_exact(32) {
                    let mut id = [0u8; 32];
                    id.copy_from_slice(c);
                    ids.insert(id);
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
        Ok(Self {
            set: SpentSet::new(),
            ids,
            file: Some(path.to_path_buf()),
        })
    }

    pub fn len(&self) -> usize {
        self.ids.len()
    }

    pub fn is_empty(&self) -> bool {
        self.ids.is_empty()
    }

    /// Verify the signature with the tier's key and that it is unspent.
    pub fn check(
        &self,
        pk: &TokenPublicKey,
        t: &SessionToken,
    ) -> std::result::Result<(), CryptoError> {
        blind::verify(pk, t)?;
        if self.set.is_spent(t) || self.ids.contains(&spent_id(t)) {
            return Err(CryptoError::DoubleSpend);
        }
        Ok(())
    }

    /// Mark a (verified) token spent. Fails on double spend.
    pub fn spend(&mut self, t: &SessionToken) -> std::result::Result<(), CryptoError> {
        let id = spent_id(t);
        if self.ids.contains(&id) {
            return Err(CryptoError::DoubleSpend);
        }
        self.set.spend(t)?;
        self.ids.insert(id);
        if let Some(path) = &self.file {
            if let Err(e) = append_private(path, &id) {
                tracing::error!("cannot persist spent-token ledger: {e}");
            }
        }
        Ok(())
    }
}

fn append_private(path: &Path, data: &[u8]) -> std::io::Result<()> {
    let mut o = std::fs::OpenOptions::new();
    o.create(true).append(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut o, 0o600);
    let mut f = o.open(path)?;
    f.write_all(data)?;
    f.sync_data()
}

/// One outstanding invite.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InviteEntry {
    pub tier: u8,
    pub bandwidth_bps: u64,
    pub expires_unix: u64,
}

/// Outstanding single-use invites, keyed by [`invite_hash`].
#[derive(Debug, Default)]
pub struct InviteTable {
    map: HashMap<[u8; 32], InviteEntry>,
}

impl InviteTable {
    pub fn insert(&mut self, hash: [u8; 32], e: InviteEntry) {
        self.map.insert(hash, e);
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// Check an invite without consuming it.
    pub fn check(
        &self,
        hash: &[u8; 32],
        now_unix: u64,
    ) -> std::result::Result<InviteEntry, CryptoError> {
        let e = self
            .map
            .get(hash)
            .ok_or(CryptoError::TokenRejected("unknown or used invite"))?;
        if now_unix >= e.expires_unix {
            return Err(CryptoError::Expired);
        }
        Ok(*e)
    }

    /// Consume an invite (single use).
    pub fn consume(
        &mut self,
        hash: &[u8; 32],
        now_unix: u64,
    ) -> std::result::Result<InviteEntry, CryptoError> {
        let e = self.check(hash, now_unix)?;
        self.map.remove(hash);
        Ok(e)
    }

    /// Drop expired invites.
    pub fn expire(&mut self, now_unix: u64) {
        self.map.retain(|_, e| now_unix < e.expires_unix);
    }
}

/// Number of host offsets in the v4 pool.
const POOL_SIZE: u32 = 1 << (32 - CLIENT_POOL_V4.1);

/// Client address allocator: offset `i` maps to `CLIENT_POOL_V4 + i` and
/// `CLIENT_POOL_V6 + i`. The gateway, `PROVISIONAL_V4`, the network and the
/// broadcast address are never handed out.
#[derive(Debug)]
pub struct AddressPool {
    next: u32,
    free: BTreeSet<u32>,
    used: HashSet<u32>,
}

impl Default for AddressPool {
    fn default() -> Self {
        Self::new()
    }
}

impl AddressPool {
    pub fn new() -> Self {
        Self {
            next: 1,
            free: BTreeSet::new(),
            used: HashSet::new(),
        }
    }

    fn base_v4() -> u32 {
        u32::from(CLIENT_POOL_V4.0)
    }

    fn reserved(i: u32) -> bool {
        let a = Self::base_v4() + i;
        i == 0
            || i >= POOL_SIZE - 1
            || a == u32::from(NODE_GATEWAY_V4)
            || a == u32::from(PROVISIONAL_V4)
    }

    pub fn v4_of(i: u32) -> Ipv4Addr {
        Ipv4Addr::from(Self::base_v4() + i)
    }

    pub fn v6_of(i: u32) -> Ipv6Addr {
        Ipv6Addr::from(u128::from(CLIENT_POOL_V6.0) | u128::from(i))
    }

    /// Allocate a fresh offset.
    pub fn allocate(&mut self) -> Option<u32> {
        if let Some(i) = self.free.pop_first() {
            self.used.insert(i);
            return Some(i);
        }
        while self.next < POOL_SIZE {
            let i = self.next;
            self.next += 1;
            if !Self::reserved(i) {
                self.used.insert(i);
                return Some(i);
            }
        }
        None
    }

    pub fn release(&mut self, i: u32) {
        if self.used.remove(&i) {
            self.free.insert(i);
        }
    }

    pub fn in_use(&self) -> usize {
        self.used.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tier_mapping() {
        assert_eq!(tier_for_bandwidth(50_000_000).id, 1);
        assert_eq!(tier_for_bandwidth(60_000_000).id, 1);
        assert_eq!(tier_for_bandwidth(200_000_000).id, 2);
        assert_eq!(tier_for_bandwidth(10_000_000_000).id, 2);
        assert_eq!(tier_for_bandwidth(1_000_000).id, 0);
        assert_eq!(tier_for_bandwidth(0).id, 3);
        assert_eq!(tier(3).unwrap().bandwidth_bps, 0);
        assert!(tier(9).is_none());
        assert_eq!(format_bandwidth(50_000_000), "50 Mbps");
        assert_eq!(format_bandwidth(0), "unlimited");
        assert_eq!(format_bandwidth(1_500_000), "1500 kbps");
    }

    #[test]
    fn token_field_parsing() {
        assert!(matches!(parse_token(&[]), Ok(TokenClaim::Owner)));
        assert!(matches!(parse_token(&[0]), Ok(TokenClaim::Owner)));
        assert!(parse_token(&[0, 1]).is_err());
        assert!(parse_token(&[1; 10]).is_err());
        assert!(parse_token(&[9]).is_err());
        let mut inv = vec![2u8];
        inv.extend_from_slice(&[7; 32]);
        match parse_token(&inv).unwrap() {
            TokenClaim::Invite(h) => assert_eq!(h, invite_hash(&[7; 32])),
            other => panic!("unexpected {other:?}"),
        }
        assert!(parse_token(&inv[..32]).is_err());
        assert!(!format!("{:?}", parse_token(&inv).unwrap()).contains('7'));
    }

    #[test]
    fn invite_table_single_use_and_expiry() {
        let mut t = InviteTable::default();
        let e = InviteEntry {
            tier: 1,
            bandwidth_bps: 50_000_000,
            expires_unix: 1000,
        };
        t.insert([1; 32], e);
        assert_eq!(t.check(&[1; 32], 10).unwrap(), e);
        assert_eq!(t.check(&[1; 32], 1000), Err(CryptoError::Expired));
        assert_eq!(t.consume(&[1; 32], 999).unwrap(), e);
        assert!(t.consume(&[1; 32], 999).is_err());
        t.insert([2; 32], e);
        t.expire(1000);
        assert!(t.is_empty());
    }

    #[test]
    fn address_pool_skips_reserved_and_reuses() {
        let mut p = AddressPool::new();
        let a = p.allocate().unwrap();
        assert_eq!(AddressPool::v4_of(a), Ipv4Addr::new(100, 96, 0, 2));
        assert_eq!(
            AddressPool::v6_of(a),
            "fd00:564f:4944:1::2".parse::<Ipv6Addr>().unwrap()
        );
        let b = p.allocate().unwrap();
        assert_eq!(AddressPool::v4_of(b), Ipv4Addr::new(100, 96, 0, 3));
        p.release(a);
        assert_eq!(p.allocate().unwrap(), a);
        assert_eq!(p.in_use(), 2);
        assert!(AddressPool::reserved(1));
        assert!(AddressPool::reserved(POOL_SIZE - 2), "provisional");
        assert!(AddressPool::reserved(POOL_SIZE - 1), "broadcast");
        assert_eq!(
            AddressPool::v4_of(POOL_SIZE - 2),
            PROVISIONAL_V4,
            "provisional address is at the top of the pool"
        );
    }

    #[test]
    fn spent_ledger_persists() {
        let dir = std::env::temp_dir().join(format!("vw-ledger-{}", rand::random::<u64>()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("spent.ledger");
        let tok = SessionToken {
            tier: 1,
            msg: [3; 32],
            randomizer: [4; 32],
            sig: vec![0; 256],
        };
        let mut l = SpentLedger::open(&path).unwrap();
        l.spend(&tok).unwrap();
        assert_eq!(l.spend(&tok), Err(CryptoError::DoubleSpend));
        let l2 = SpentLedger::open(&path).unwrap();
        assert_eq!(l2.len(), 1);
        let mut l2 = l2;
        assert_eq!(l2.spend(&tok), Err(CryptoError::DoubleSpend));
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
