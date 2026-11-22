//! Friend-to-friend invites (ARCHITECTURE.md §8).
//!
//! Wire layout (all integers big-endian):
//!
//! ```text
//! ver u8 = 1 | node_identity[32] | bandwidth_bps u64 | expires_unix u64
//! | invite_secret[32] | node_uri_len u16 | node_uri utf8 | ed25519_sig[64]
//! ```
//!
//! The signature is made by the node identity over every byte before it. The
//! encoded invite carries the single-use `invite_secret`, so the byte form is
//! returned as a [`SecretVec`]. URI form: `voidwire://f2f/<base64url(invite)>`.

use std::time::Duration;

use vw_core::config::Bytes32;
use vw_core::secret::{Key32, SecretVec};
use vw_core::uri::{decode_blob, decode_node, encode_blob, F2F_PREFIX, NODE_PREFIX};
use zeroize::Zeroize;

use crate::error::{CryptoError, Result};
use crate::identity::{self, NodeIdentity, SIGNATURE_LEN};

/// Current invite encoding version.
pub const INVITE_VERSION: u8 = 1;
const FIXED_LEN: usize = 1 + 32 + 8 + 8 + 32 + 2;

/// A friend-to-friend invite to a node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Invite {
    /// Ed25519 identity of the inviting node (also the signer).
    pub node_identity: Bytes32,
    /// Bandwidth limit granted to the friend (bits per second, 0 = unlimited).
    pub bandwidth_bps: u64,
    /// Expiry as Unix seconds; the invite is invalid at or after this time.
    pub expires_unix: u64,
    /// Single-use redemption secret (zeroized on drop, redacted in `Debug`).
    pub invite_secret: Key32,
    /// `voidwire://node/...` URI describing how to reach the node.
    pub node_uri: String,
}

impl Invite {
    /// New invite for `identity` with a fresh random secret.
    pub fn new(
        identity: &NodeIdentity,
        bandwidth_bps: u64,
        expires_unix: u64,
        node_uri: String,
    ) -> Self {
        Self {
            node_identity: identity.public(),
            bandwidth_bps,
            expires_unix,
            invite_secret: Key32::random(),
            node_uri,
        }
    }

    fn signed_bytes(&self) -> Result<SecretVec> {
        let ulen = u16::try_from(self.node_uri.len()).map_err(|_| CryptoError::Length {
            what: "invite node_uri",
            expected: u16::MAX as usize,
            got: self.node_uri.len(),
        })?;
        let mut out = SecretVec::with_capacity(FIXED_LEN + self.node_uri.len() + SIGNATURE_LEN);
        let b = out.expose_mut();
        b.push(INVITE_VERSION);
        b.extend_from_slice(&self.node_identity.0);
        b.extend_from_slice(&self.bandwidth_bps.to_be_bytes());
        b.extend_from_slice(&self.expires_unix.to_be_bytes());
        b.extend_from_slice(self.invite_secret.expose());
        b.extend_from_slice(&ulen.to_be_bytes());
        b.extend_from_slice(self.node_uri.as_bytes());
        Ok(out)
    }

    /// Sign and encode. Fails if `identity` is not `self.node_identity`, or
    /// the node URI exceeds 65535 bytes.
    pub fn sign(&self, identity: &NodeIdentity) -> Result<SecretVec> {
        if identity.public() != self.node_identity {
            return Err(CryptoError::InvalidKey(
                "invite signer is not node_identity",
            ));
        }
        let mut out = self.signed_bytes()?;
        let sig = identity.sign(out.expose());
        out.expose_mut().extend_from_slice(&sig);
        Ok(out)
    }

    /// Decode and verify: version, exact length, UTF-8 URI, Ed25519 signature
    /// by the embedded node identity, expiry (`now_unix < expires_unix`), and
    /// that `node_uri` is a valid node URI whose `identity_key` (if present)
    /// equals `node_identity`.
    pub fn decode_verified(bytes: &[u8], now_unix: u64) -> Result<Invite> {
        if bytes.is_empty() {
            return Err(CryptoError::Malformed("empty invite"));
        }
        if bytes[0] != INVITE_VERSION {
            return Err(CryptoError::Version(bytes[0]));
        }
        if bytes.len() < FIXED_LEN + SIGNATURE_LEN {
            return Err(CryptoError::Length {
                what: "invite",
                expected: FIXED_LEN + SIGNATURE_LEN,
                got: bytes.len(),
            });
        }
        let ulen = u16::from_be_bytes([bytes[FIXED_LEN - 2], bytes[FIXED_LEN - 1]]) as usize;
        let total = FIXED_LEN + ulen + SIGNATURE_LEN;
        if bytes.len() != total {
            return Err(CryptoError::Length {
                what: "invite",
                expected: total,
                got: bytes.len(),
            });
        }
        let signed = &bytes[..FIXED_LEN + ulen];
        let mut sig = [0u8; SIGNATURE_LEN];
        sig.copy_from_slice(&bytes[FIXED_LEN + ulen..]);
        let mut id = [0u8; 32];
        id.copy_from_slice(&bytes[1..33]);
        let node_identity = Bytes32(id);
        identity::verify(&node_identity, signed, &sig)?;

        let u64_at = |o: usize| {
            let mut a = [0u8; 8];
            a.copy_from_slice(&bytes[o..o + 8]);
            u64::from_be_bytes(a)
        };
        let bandwidth_bps = u64_at(33);
        let expires_unix = u64_at(41);
        if now_unix >= expires_unix {
            return Err(CryptoError::Expired);
        }
        let invite_secret =
            Key32::from_slice(&bytes[49..81]).ok_or(CryptoError::Malformed("invite secret"))?;
        let node_uri = std::str::from_utf8(&bytes[FIXED_LEN..FIXED_LEN + ulen])
            .map_err(|_| CryptoError::Malformed("invite node_uri utf8"))?
            .to_owned();
        if !node_uri.starts_with(NODE_PREFIX) {
            return Err(CryptoError::Malformed("invite node_uri prefix"));
        }
        let desc = decode_node(&node_uri).map_err(|_| CryptoError::Malformed("invite node_uri"))?;
        if let Some(k) = desc.identity_key {
            if k != node_identity {
                return Err(CryptoError::InvalidKey(
                    "node_uri identity differs from signer",
                ));
            }
        }
        Ok(Invite {
            node_identity,
            bandwidth_bps,
            expires_unix,
            invite_secret,
            node_uri,
        })
    }

    /// Sign and render as `voidwire://f2f/<base64url>`.
    ///
    /// The returned string contains the invite secret; treat it as a credential.
    pub fn to_uri(&self, identity: &NodeIdentity) -> Result<String> {
        let bytes = self.sign(identity)?;
        Ok(encode_blob(F2F_PREFIX, bytes.expose()))
    }

    /// Parse and verify a `voidwire://f2f/...` URI.
    pub fn from_uri(uri: &str, now_unix: u64) -> Result<Invite> {
        let mut raw =
            decode_blob(F2F_PREFIX, uri).map_err(|_| CryptoError::Malformed("f2f uri"))?;
        let out = Self::decode_verified(&raw, now_unix);
        raw.zeroize();
        out
    }
}

/// Split `s` into a decimal number and a lowercase unit suffix.
fn split_number(s: &str) -> Result<(u128, u32, String)> {
    let s = s.trim();
    let end = s
        .find(|c: char| !(c.is_ascii_digit() || c == '.'))
        .unwrap_or(s.len());
    let (num, unit) = s.split_at(end);
    if num.is_empty() {
        return Err(CryptoError::Parse(format!("missing number in {s:?}")));
    }
    let (int_part, frac_part) = match num.split_once('.') {
        Some((i, f)) => (i, f),
        None => (num, ""),
    };
    if int_part.is_empty() || frac_part.contains('.') || (num.contains('.') && frac_part.is_empty())
    {
        return Err(CryptoError::Parse(format!("bad number in {s:?}")));
    }
    if frac_part.len() > 9 {
        return Err(CryptoError::Parse(format!("too many decimals in {s:?}")));
    }
    let digits = format!("{int_part}{frac_part}");
    let mantissa: u128 = digits
        .parse()
        .map_err(|_| CryptoError::Parse(format!("number out of range in {s:?}")))?;
    Ok((
        mantissa,
        frac_part.len() as u32,
        unit.trim().to_ascii_lowercase(),
    ))
}

fn scale(mantissa: u128, decimals: u32, mult: u128, what: &str) -> Result<u64> {
    let v = mantissa
        .checked_mul(mult)
        .ok_or_else(|| CryptoError::Parse(format!("{what} out of range")))?
        / 10u128.pow(decimals);
    u64::try_from(v).map_err(|_| CryptoError::Parse(format!("{what} out of range")))
}

/// Parse a bandwidth such as `"50Mbps"`, `"1Gbps"`, `"500kbps"`, `"1.5 Gbps"`
/// into bits per second (SI multiples of 1000). The unit is case-insensitive
/// and the bare suffix `bps` (or none) means bits per second. Zero is rejected.
pub fn parse_bandwidth(s: &str) -> Result<u64> {
    let (m, d, unit) = split_number(s)?;
    let mult: u128 = match unit.as_str() {
        "" | "bps" | "b/s" => 1,
        "k" | "kbps" | "kbit/s" | "kb/s" => 1_000,
        "m" | "mbps" | "mbit/s" | "mb/s" => 1_000_000,
        "g" | "gbps" | "gbit/s" | "gb/s" => 1_000_000_000,
        "t" | "tbps" | "tbit/s" | "tb/s" => 1_000_000_000_000,
        other => {
            return Err(CryptoError::Parse(format!(
                "unknown bandwidth unit {other:?}"
            )))
        }
    };
    let v = scale(m, d, mult, "bandwidth")?;
    if v == 0 {
        return Err(CryptoError::Parse("bandwidth must be > 0".into()));
    }
    Ok(v)
}

/// Parse a duration such as `"30d"`, `"12h"`, `"45m"`, `"90s"`, `"2w"`,
/// `"1.5h"`. Units: `s`, `m`/`min`, `h`, `d`, `w` (case-insensitive). Zero is
/// rejected.
pub fn parse_duration(s: &str) -> Result<Duration> {
    let (m, d, unit) = split_number(s)?;
    let mult: u128 = match unit.as_str() {
        "s" | "sec" | "secs" => 1,
        "m" | "min" | "mins" => 60,
        "h" | "hr" | "hrs" => 3_600,
        "d" | "day" | "days" => 86_400,
        "w" | "week" | "weeks" => 604_800,
        "" => return Err(CryptoError::Parse(format!("duration {s:?} needs a unit"))),
        other => {
            return Err(CryptoError::Parse(format!(
                "unknown duration unit {other:?}"
            )))
        }
    };
    let secs = scale(m, d, mult, "duration")?;
    if secs == 0 {
        return Err(CryptoError::Parse("duration must be > 0".into()));
    }
    Ok(Duration::from_secs(secs))
}

#[cfg(test)]
mod tests {
    use super::*;
    use vw_core::config::{Endpoint, NodeDescriptor, NodeKind, NodeRole, TransportKind};
    use vw_core::uri::encode_node;

    fn node_uri(id: &NodeIdentity) -> String {
        encode_node(&NodeDescriptor {
            version: 1,
            name: "friend".into(),
            kind: NodeKind::Voidwire,
            role: NodeRole::Both,
            wg_public_key: Bytes32([1; 32]),
            identity_key: Some(id.public()),
            endpoints: vec![Endpoint {
                transport: TransportKind::NativeUdp,
                host: "192.0.2.10".into(),
                port: 51820,
                sni: None,
                path: None,
                cert_sha256: None,
            }],
            amnezia: None,
            country: None,
            ipv6_exit: false,
            static_v4: None,
            static_v6: None,
            reserved: None,
            static_psk: None,
            token_keys: Vec::new(),
            client_private: None,
        })
        .unwrap()
    }

    const NOW: u64 = 1_800_000_000;

    #[test]
    fn sign_decode_roundtrip_and_layout() {
        let id = NodeIdentity::generate();
        let inv = Invite::new(&id, 50_000_000, NOW + 86_400, node_uri(&id));
        let bytes = inv.sign(&id).unwrap();
        let b = bytes.expose();
        assert_eq!(b[0], 1);
        assert_eq!(&b[1..33], &id.public().0);
        assert_eq!(&b[33..41], &50_000_000u64.to_be_bytes());
        assert_eq!(&b[41..49], &(NOW + 86_400).to_be_bytes());
        assert_eq!(&b[49..81], inv.invite_secret.expose());
        assert_eq!(
            u16::from_be_bytes([b[81], b[82]]) as usize,
            inv.node_uri.len()
        );
        assert_eq!(b.len(), 83 + inv.node_uri.len() + 64);
        let back = Invite::decode_verified(b, NOW).unwrap();
        assert_eq!(back, inv);
        assert!(!format!("{back:?}").contains(&inv.invite_secret.to_base64()));

        let uri = inv.to_uri(&id).unwrap();
        assert!(uri.starts_with("voidwire://f2f/"));
        assert_eq!(Invite::from_uri(&uri, NOW).unwrap(), inv);
        assert!(Invite::from_uri("voidwire://node/abc", NOW).is_err());
    }

    #[test]
    fn rejects_expired_tampered_wrong_version() {
        let id = NodeIdentity::generate();
        let inv = Invite::new(&id, 1_000, NOW + 10, node_uri(&id));
        let bytes = inv.sign(&id).unwrap().expose().to_vec();
        assert_eq!(
            Invite::decode_verified(&bytes, NOW + 10).unwrap_err(),
            CryptoError::Expired
        );
        let mut bad = bytes.clone();
        bad[35] ^= 1; // bandwidth
        assert_eq!(
            Invite::decode_verified(&bad, NOW).unwrap_err(),
            CryptoError::BadSignature
        );
        let mut bad = bytes.clone();
        *bad.last_mut().unwrap() ^= 1;
        assert_eq!(
            Invite::decode_verified(&bad, NOW).unwrap_err(),
            CryptoError::BadSignature
        );
        let mut bad = bytes.clone();
        bad[0] = 2;
        assert_eq!(
            Invite::decode_verified(&bad, NOW).unwrap_err(),
            CryptoError::Version(2)
        );
        assert!(Invite::decode_verified(&bytes[..bytes.len() - 1], NOW).is_err());
        assert!(Invite::decode_verified(&[], NOW).is_err());
    }

    #[test]
    fn rejects_foreign_signer_and_mismatched_uri() {
        let id = NodeIdentity::generate();
        let other = NodeIdentity::generate();
        let inv = Invite::new(&id, 1_000, NOW + 10, node_uri(&id));
        assert!(inv.sign(&other).is_err());
        // Signed correctly, but the node URI names another identity.
        let inv = Invite::new(&id, 1_000, NOW + 10, node_uri(&other));
        let bytes = inv.sign(&id).unwrap();
        assert!(matches!(
            Invite::decode_verified(bytes.expose(), NOW),
            Err(CryptoError::InvalidKey(_))
        ));
        let inv = Invite::new(&id, 1_000, NOW + 10, "https://example.com".into());
        let bytes = inv.sign(&id).unwrap();
        assert!(Invite::decode_verified(bytes.expose(), NOW).is_err());
    }

    #[test]
    fn bandwidth_parsing() {
        assert_eq!(parse_bandwidth("50Mbps").unwrap(), 50_000_000);
        assert_eq!(parse_bandwidth("1Gbps").unwrap(), 1_000_000_000);
        assert_eq!(parse_bandwidth("500kbps").unwrap(), 500_000);
        assert_eq!(parse_bandwidth("1.5 gbps").unwrap(), 1_500_000_000);
        assert_eq!(parse_bandwidth("2500").unwrap(), 2_500);
        assert_eq!(parse_bandwidth(" 10M ").unwrap(), 10_000_000);
        for bad in [
            "",
            "Mbps",
            "0Mbps",
            "5Xbps",
            "1..2Mbps",
            "1.Mbps",
            "-5Mbps",
            "99999999999Tbps",
        ] {
            assert!(parse_bandwidth(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn duration_parsing() {
        assert_eq!(
            parse_duration("30d").unwrap(),
            Duration::from_secs(30 * 86_400)
        );
        assert_eq!(parse_duration("12h").unwrap(), Duration::from_secs(43_200));
        assert_eq!(parse_duration("45m").unwrap(), Duration::from_secs(2_700));
        assert_eq!(parse_duration("90s").unwrap(), Duration::from_secs(90));
        assert_eq!(
            parse_duration("2w").unwrap(),
            Duration::from_secs(1_209_600)
        );
        assert_eq!(parse_duration("1.5h").unwrap(), Duration::from_secs(5_400));
        assert_eq!(parse_duration("7D").unwrap(), Duration::from_secs(604_800));
        for bad in ["", "30", "d", "0d", "3y", "1.2.3h"] {
            assert!(parse_duration(bad).is_err(), "{bad}");
        }
    }
}
