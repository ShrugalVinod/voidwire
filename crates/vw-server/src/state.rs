//! Node state directory: keys, certificate, path tokens, issuer keys, and the
//! [`NodeDescriptor`] / `node.uri` built from them.
//!
//! Layout (directory 0700, every file 0600):
//!
//! ```text
//! identity.key      Ed25519 seed (32 B)
//! wg.key            WireGuard static private key (32 B)
//! amnezia.json      AmneziaWG parameters
//! tls.crt / tls.key node certificate (DER) and PKCS#8 key (DER)
//! meta.json         SNI of the certificate, TLS-WS + MASQUE path tokens,
//!                   issuer-key creation time
//! token-tier-N.der  RSA-2048 blind-token issuer key per tier
//! spent.ledger      spent session-token ids (wiped on key rotation)
//! node.uri          voidwire://node/...
//! control.sock      local control socket (while running)
//! ```

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use vw_core::config::{
    AmneziaParams, Bytes32, Endpoint, NodeDescriptor, NodeKind, NodeRole, TransportKind,
};
use vw_core::secret::{Key32, SecretVec};
use vw_core::{Result, VwError};
use vw_crypto::blind::TokenIssuerKey;
use vw_crypto::identity::NodeIdentity;
use zeroize::Zeroize;

use crate::admission::{Issuers, TIERS};

/// Issuer keys rotate after this many seconds (ARCHITECTURE.md §8).
pub const TOKEN_KEY_LIFETIME_SECS: u64 = 30 * 24 * 3600;

pub const NODE_URI_FILE: &str = "node.uri";
pub const CONTROL_SOCK: &str = "control.sock";
pub const SPENT_LEDGER: &str = "spent.ledger";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct Meta {
    sni: String,
    ws_token: String,
    masque_token: String,
    token_keys_created: u64,
}

/// Everything loaded from (or created in) the state directory.
pub struct NodeState {
    pub dir: PathBuf,
    pub identity: NodeIdentity,
    pub wg_key: Key32,
    pub amnezia: AmneziaParams,
    pub cert_der: Vec<u8>,
    pub key_der: SecretVec,
    pub cert_sha256: String,
    pub sni: String,
    pub ws_token: String,
    pub masque_token: String,
    pub issuers: Issuers,
    /// True when the issuer keys were (re)generated during this load.
    pub token_keys_rotated: bool,
}

impl std::fmt::Debug for NodeState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NodeState")
            .field("identity", &self.identity.public())
            .finish_non_exhaustive()
    }
}

/// Create `dir` with mode 0700 (or tighten an existing one).
pub fn ensure_private_dir(dir: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
        if !dir.exists() {
            std::fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(dir)?;
        }
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
    }
    #[cfg(not(unix))]
    std::fs::create_dir_all(dir)?;
    Ok(())
}

/// Atomically write a 0600 file.
pub fn write_private(path: &Path, data: &[u8]) -> Result<()> {
    use std::io::Write;
    let tmp = path.with_extension("tmp");
    {
        let mut o = std::fs::OpenOptions::new();
        o.create(true).write(true).truncate(true);
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut o, 0o600);
        let mut f = o.open(&tmp)?;
        f.write_all(data)?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, path)?;
    Ok(())
}

fn read_opt(path: &Path) -> Result<Option<Vec<u8>>> {
    match std::fs::read(path) {
        Ok(v) => Ok(Some(v)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.into()),
    }
}

fn random_token() -> String {
    hex::encode(&Key32::random().expose()[..16])
}

fn load_key32(path: &Path) -> Result<Option<Key32>> {
    match read_opt(path)? {
        Some(mut v) => {
            let k = Key32::from_slice(&v);
            v.zeroize();
            k.map(Some)
                .ok_or_else(|| VwError::Config(format!("{} is corrupt", path.display())))
        }
        None => Ok(None),
    }
}

fn load_or_create_key32(path: &Path) -> Result<Key32> {
    if let Some(k) = load_key32(path)? {
        return Ok(k);
    }
    let k = Key32::random();
    write_private(path, k.expose())?;
    Ok(k)
}

impl NodeState {
    /// Load the state directory, creating anything missing. `sni` is the
    /// TLS name; a changed SNI regenerates the certificate.
    pub fn load_or_create(dir: &Path, sni: &str, now_unix: u64) -> Result<Self> {
        ensure_private_dir(dir)?;
        let identity = NodeIdentity::from_seed(&load_or_create_key32(&dir.join("identity.key"))?);
        let wg_key = load_or_create_key32(&dir.join("wg.key"))?;

        let amnezia = match read_opt(&dir.join("amnezia.json"))? {
            Some(raw) => {
                let p: AmneziaParams = serde_json::from_slice(&raw)?;
                p.validate()?;
                p
            }
            None => {
                let p = AmneziaParams::random();
                write_private(&dir.join("amnezia.json"), &serde_json::to_vec(&p)?)?;
                p
            }
        };

        let mut meta: Option<Meta> = match read_opt(&dir.join("meta.json"))? {
            Some(raw) => Some(serde_json::from_slice(&raw)?),
            None => None,
        };
        let crt_path = dir.join("tls.crt");
        let key_path = dir.join("tls.key");
        let need_cert =
            meta.as_ref().is_none_or(|m| m.sni != sni) || !crt_path.exists() || !key_path.exists();
        if need_cert {
            let (cert, key, _) = vw_stealth::generate_node_cert(sni)?;
            write_private(&crt_path, &cert)?;
            write_private(&key_path, &key)?;
        }
        let cert_der = std::fs::read(&crt_path)?;
        let key_der = SecretVec::new(std::fs::read(&key_path)?);
        let cert_sha256 = vw_stealth::tls::cert_sha256_hex(&cert_der);

        let m = meta.get_or_insert_with(|| Meta {
            sni: sni.to_string(),
            ws_token: random_token(),
            masque_token: random_token(),
            token_keys_created: 0,
        });
        m.sni = sni.to_string();

        let tier_path = |t: u8| dir.join(format!("token-tier-{t}.der"));
        let expired = now_unix.saturating_sub(m.token_keys_created) >= TOKEN_KEY_LIFETIME_SECS;
        let missing = TIERS.iter().any(|t| !tier_path(t.id).exists());
        let rotated = expired || missing;
        let mut keys = Vec::with_capacity(TIERS.len());
        if rotated {
            for t in TIERS {
                let k = TokenIssuerKey::generate(t.id)?;
                write_private(&tier_path(t.id), k.to_der()?.expose())?;
                keys.push(k);
            }
            m.token_keys_created = now_unix;
            // Old tokens are invalid with new keys; their ledger goes too.
            let _ = std::fs::remove_file(dir.join(SPENT_LEDGER));
        } else {
            for t in TIERS {
                let der = SecretVec::new(std::fs::read(tier_path(t.id))?);
                keys.push(TokenIssuerKey::from_der(t.id, der.expose())?);
            }
        }
        let m = m.clone();
        write_private(&dir.join("meta.json"), &serde_json::to_vec_pretty(&m)?)?;

        Ok(Self {
            dir: dir.to_path_buf(),
            identity,
            wg_key,
            amnezia,
            cert_der,
            key_der,
            cert_sha256,
            sni: m.sni,
            ws_token: m.ws_token,
            masque_token: m.masque_token,
            issuers: Issuers::new(keys),
            token_keys_rotated: rotated,
        })
    }

    pub fn wg_public(&self) -> [u8; 32] {
        vw_wg::public_key(&self.wg_key)
    }
}

/// Listening ports and public address used in the descriptor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Advertise {
    pub name: String,
    pub host: String,
    pub udp_port: u16,
    pub quic_port: u16,
    pub tls_port: u16,
    pub ipv6_exit: bool,
}

/// Build the node descriptor.
pub fn build_descriptor(st: &NodeState, adv: &Advertise) -> Result<NodeDescriptor> {
    let ep = |transport, port, sni: Option<&str>, path: Option<&str>, pin: Option<&str>| Endpoint {
        transport,
        host: adv.host.clone(),
        port,
        sni: sni.map(str::to_string),
        path: path.map(str::to_string),
        cert_sha256: pin.map(str::to_string),
    };
    let pin = st.cert_sha256.as_str();
    let d = NodeDescriptor {
        version: 1,
        name: adv.name.clone(),
        kind: NodeKind::Voidwire,
        role: NodeRole::Both,
        wg_public_key: Bytes32(st.wg_public()),
        identity_key: Some(st.identity.public()),
        endpoints: vec![
            ep(TransportKind::NativeUdp, adv.udp_port, None, None, None),
            ep(TransportKind::AmneziaWg, adv.udp_port, None, None, None),
            ep(
                TransportKind::MasqueQuic,
                adv.quic_port,
                Some(&st.sni),
                Some(&st.masque_token),
                Some(pin),
            ),
            ep(
                TransportKind::TlsWebsocket,
                adv.tls_port,
                Some(&st.sni),
                Some(&st.ws_token),
                Some(pin),
            ),
        ],
        amnezia: Some(st.amnezia),
        country: None,
        ipv6_exit: adv.ipv6_exit,
        static_v4: None,
        static_v6: None,
        reserved: None,
        static_psk: None,
        token_keys: st.issuers.token_key_infos()?,
    };
    d.validate()?;
    Ok(d)
}

/// Encode and write `node.uri`; returns the URI.
pub fn write_node_uri(dir: &Path, d: &NodeDescriptor) -> Result<String> {
    let uri = vw_core::uri::encode_node(d)?;
    write_private(&dir.join(NODE_URI_FILE), format!("{uri}\n").as_bytes())?;
    Ok(uri)
}

/// Read `node.uri`.
pub fn read_node_uri(dir: &Path) -> Result<String> {
    let s = std::fs::read_to_string(dir.join(NODE_URI_FILE)).map_err(|e| {
        VwError::Config(format!(
            "cannot read {}: {e} (has `voidwire-node run` started?)",
            dir.join(NODE_URI_FILE).display()
        ))
    })?;
    Ok(s.trim().to_string())
}

/// Source address the OS would use towards `probe` (no packet is sent).
pub fn egress_source(probe: SocketAddr) -> Option<IpAddr> {
    let bind: SocketAddr = if probe.is_ipv4() {
        (Ipv4Addr::UNSPECIFIED, 0).into()
    } else {
        (Ipv6Addr::UNSPECIFIED, 0).into()
    };
    let s = UdpSocket::bind(bind).ok()?;
    s.connect(probe).ok()?;
    s.local_addr().ok().map(|a| a.ip())
}

/// True for globally routable IPv6 unicast (2000::/3).
pub fn is_global_v6(a: Ipv6Addr) -> bool {
    a.segments()[0] & 0xe000 == 0x2000
}

/// True for addresses that are not reachable from the Internet.
pub fn is_private_v4(a: Ipv4Addr) -> bool {
    a.is_private()
        || a.is_loopback()
        || a.is_link_local()
        || (a.octets()[0] == 100 && (a.octets()[1] & 0xc0) == 64)
}

/// Public IPv4 of the egress interface, and whether global IPv6 exists.
pub fn discover_public() -> (Option<Ipv4Addr>, bool) {
    let v4 = match egress_source("1.1.1.1:53".parse().expect("literal")) {
        Some(IpAddr::V4(a)) => Some(a),
        _ => None,
    };
    let v6 = matches!(
        egress_source("[2606:4700:4700::1111]:53".parse().expect("literal")),
        Some(IpAddr::V6(a)) if is_global_v6(a)
    );
    (v4, v6)
}

#[cfg(test)]
mod tests {
    use super::*;

    pub(crate) fn temp_dir(tag: &str) -> PathBuf {
        std::env::temp_dir().join(format!("vw-node-{tag}-{}", rand::random::<u64>()))
    }

    #[test]
    fn state_create_reload_descriptor_and_uri() {
        let dir = temp_dir("state");
        let now = 1_800_000_000;
        let st = NodeState::load_or_create(&dir, "cdn.example.net", now).unwrap();
        assert!(st.token_keys_rotated);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode(&dir), 0o700);
            for f in [
                "identity.key",
                "wg.key",
                "amnezia.json",
                "tls.crt",
                "tls.key",
                "meta.json",
                "token-tier-0.der",
            ] {
                assert_eq!(mode(&dir.join(f)), 0o600, "{f}");
            }
        }
        // Reload keeps everything.
        let st2 = NodeState::load_or_create(&dir, "cdn.example.net", now + 60).unwrap();
        assert!(!st2.token_keys_rotated);
        assert_eq!(st.identity.public(), st2.identity.public());
        assert_eq!(st.wg_public(), st2.wg_public());
        assert_eq!(st.cert_sha256, st2.cert_sha256);
        assert_eq!(st.ws_token, st2.ws_token);
        assert_eq!(st.amnezia, st2.amnezia);
        assert_eq!(st.ws_token.len(), 32);
        assert_ne!(st.ws_token, st.masque_token);

        let adv = Advertise {
            name: "test-node".into(),
            host: "198.51.100.7".into(),
            udp_port: 51820,
            quic_port: 443,
            tls_port: 8443,
            ipv6_exit: true,
        };
        let d = build_descriptor(&st2, &adv).unwrap();
        assert_eq!(d.kind, NodeKind::Voidwire);
        assert_eq!(d.identity_key, Some(st.identity.public()));
        assert_eq!(d.token_keys.len(), TIERS.len());
        assert_eq!(d.token_keys[1].bandwidth_bps, 50_000_000);
        let m = d.endpoint_for(TransportKind::MasqueQuic).unwrap();
        assert_eq!(m.port, 443);
        assert_eq!(m.path.as_deref(), Some(st.masque_token.as_str()));
        assert_eq!(m.cert_sha256.as_deref(), Some(st.cert_sha256.as_str()));
        let t = d.endpoint_for(TransportKind::TlsWebsocket).unwrap();
        assert_eq!(t.port, 8443);
        assert_eq!(t.sni.as_deref(), Some("cdn.example.net"));
        assert_eq!(
            d.endpoint_for(TransportKind::AmneziaWg).unwrap().port,
            51820
        );
        assert!(d.ipv6_exit);
        let uri = write_node_uri(&dir, &d).unwrap();
        assert_eq!(read_node_uri(&dir).unwrap(), uri);
        assert_eq!(vw_core::uri::decode_node(&uri).unwrap(), d);

        // SNI change regenerates the certificate; key expiry rotates issuers.
        let st3 =
            NodeState::load_or_create(&dir, "other.example.org", now + TOKEN_KEY_LIFETIME_SECS)
                .unwrap();
        assert_ne!(st3.cert_sha256, st.cert_sha256);
        assert!(st3.token_keys_rotated);
        assert_eq!(st3.identity.public(), st.identity.public());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn address_classes() {
        assert!(is_global_v6("2001:db8::1".parse().unwrap()));
        assert!(!is_global_v6("fd00::1".parse().unwrap()));
        assert!(!is_global_v6("fe80::1".parse().unwrap()));
        assert!(is_private_v4(Ipv4Addr::new(10, 0, 0, 5)));
        assert!(is_private_v4(Ipv4Addr::new(100, 100, 1, 1)));
        assert!(!is_private_v4(Ipv4Addr::new(198, 51, 100, 7)));
    }
}
