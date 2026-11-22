//! Typed configuration schemas shared by daemon, node, CLI, TUI and GUI.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use rand::Rng;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::consts;
use crate::error::{Result, VwError};
use crate::secret::{Key32, SecretVec};

/// A public 32-byte value (WireGuard / Ed25519 public keys), base64 in JSON.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Bytes32(pub [u8; 32]);

impl std::fmt::Debug for Bytes32 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Bytes32({})", &self.to_base64()[..8])
    }
}

impl Bytes32 {
    pub fn to_base64(&self) -> String {
        B64.encode(self.0)
    }
    pub fn from_base64(s: &str) -> Option<Self> {
        let v = B64.decode(s.trim()).ok()?;
        Some(Self(v.try_into().ok()?))
    }
}

impl Serialize for Bytes32 {
    fn serialize<S: Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_base64())
    }
}
impl<'de> Deserialize<'de> for Bytes32 {
    fn deserialize<D: Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        Self::from_base64(&s).ok_or_else(|| serde::de::Error::custom("expected 32-byte base64"))
    }
}

/// Pluggable transports (ARCHITECTURE.md §9).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, PartialOrd, Ord)]
#[serde(rename_all = "kebab-case")]
pub enum TransportKind {
    NativeUdp,
    AmneziaWg,
    MasqueQuic,
    TlsWebsocket,
}

impl TransportKind {
    pub const ALL: [TransportKind; 4] = [
        TransportKind::NativeUdp,
        TransportKind::AmneziaWg,
        TransportKind::MasqueQuic,
        TransportKind::TlsWebsocket,
    ];

    /// Bytes added on the wire per WireGuard datagram (used for MTU/MSS).
    pub const fn overhead(self) -> u16 {
        match self {
            TransportKind::NativeUdp => 0,
            TransportKind::AmneziaWg => 0,
            // QUIC short header + AEAD tag + datagram frame + CONNECT-UDP context.
            TransportKind::MasqueQuic => 1 + 20 + 16 + 3 + 2 + 4,
            // TLS record header + tag + WebSocket header (client masking key).
            TransportKind::TlsWebsocket => 5 + 16 + 14,
        }
    }

    pub const fn is_stealth(self) -> bool {
        !matches!(self, TransportKind::NativeUdp)
    }

    pub const fn label(self) -> &'static str {
        match self {
            TransportKind::NativeUdp => "WireGuard UDP",
            TransportKind::AmneziaWg => "AmneziaWG",
            TransportKind::MasqueQuic => "MASQUE HTTP/3",
            TransportKind::TlsWebsocket => "TLS-WebSocket",
        }
    }
}

/// AmneziaWG obfuscation parameters (shared via node URI).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct AmneziaParams {
    pub jc: u8,
    pub jmin: u16,
    pub jmax: u16,
    pub s1: u16,
    pub s2: u16,
    pub h1: u32,
    pub h2: u32,
    pub h3: u32,
    pub h4: u32,
}

impl AmneziaParams {
    /// Fresh random parameters satisfying AmneziaWG constraints.
    pub fn random() -> Self {
        let mut rng = rand::rngs::OsRng;
        let mut hs = [0u32; 4];
        loop {
            for h in hs.iter_mut() {
                *h = rng.gen_range(5..=u32::MAX);
            }
            let mut sorted = hs;
            sorted.sort_unstable();
            if sorted.windows(2).all(|w| w[0] != w[1]) {
                break;
            }
        }
        let s1 = rng.gen_range(15..=150);
        let mut s2 = rng.gen_range(15..=150);
        // 148 + s1 must never equal 92 + s2, otherwise lengths are ambiguous.
        while 148 + s1 == 92 + s2 {
            s2 = rng.gen_range(15..=150);
        }
        let jmin = rng.gen_range(40..=200);
        Self {
            jc: rng.gen_range(3..=10),
            jmin,
            jmax: rng.gen_range(jmin + 1..=1000),
            s1,
            s2,
            h1: hs[0],
            h2: hs[1],
            h3: hs[2],
            h4: hs[3],
        }
    }

    pub fn validate(&self) -> Result<()> {
        let hs = [self.h1, self.h2, self.h3, self.h4];
        for (i, a) in hs.iter().enumerate() {
            if *a <= 4 {
                return Err(VwError::Config("AmneziaWG H values must be > 4".into()));
            }
            if hs[i + 1..].contains(a) {
                return Err(VwError::Config(
                    "AmneziaWG H values must be distinct".into(),
                ));
            }
        }
        if self.jmin > self.jmax || self.jmax > 1280 {
            return Err(VwError::Config(
                "AmneziaWG requires Jmin <= Jmax <= 1280".into(),
            ));
        }
        if self.jc > 128 {
            return Err(VwError::Config("AmneziaWG Jc must be <= 128".into()));
        }
        if 148 + self.s1 == 92 + self.s2 {
            return Err(VwError::Config(
                "AmneziaWG S1/S2 produce ambiguous lengths".into(),
            ));
        }
        if self.s1 > 1132 || self.s2 > 1188 {
            return Err(VwError::Config("AmneziaWG padding too large".into()));
        }
        Ok(())
    }
}

/// DAITA traffic-analysis defence parameters.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DaitaParams {
    pub enabled: bool,
    pub buckets: Vec<u16>,
    /// Mean chaff packets per second (Poisson process).
    pub chaff_rate_hz: f64,
    /// Upper bound on chaff bandwidth relative to real traffic (percent).
    pub max_overhead_pct: u8,
}

impl Default for DaitaParams {
    fn default() -> Self {
        Self {
            enabled: false,
            buckets: consts::DAITA_BUCKETS.to_vec(),
            chaff_rate_hz: 8.0,
            max_overhead_pct: 25,
        }
    }
}

impl DaitaParams {
    pub fn bucket_for(&self, len: usize) -> usize {
        self.buckets
            .iter()
            .map(|b| *b as usize)
            .find(|b| *b >= len)
            .unwrap_or(len)
    }
}

/// How to reach a node over one transport.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Endpoint {
    pub transport: TransportKind,
    /// Literal IP or hostname. Hostnames are resolved through the bootstrap
    /// resolver only while the firewall pins them.
    pub host: String,
    pub port: u16,
    /// TLS SNI / QUIC server name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sni: Option<String>,
    /// Secret path (TLS-WS) or MASQUE template path token.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    /// Pinned SHA-256 of the node's TLS certificate (DER), hex.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cert_sha256: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum NodeKind {
    /// A `voidwire-node` (PQ VWCP supported).
    Voidwire,
    /// Cloudflare WARP (classical WireGuard, reserved bytes).
    Warp,
    /// A plain WireGuard / AmneziaWG server imported from a .conf.
    Generic,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum NodeRole {
    Entry,
    Exit,
    Both,
}

/// Everything a client needs to connect to a node (`voidwire://node/...`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NodeDescriptor {
    pub version: u8,
    pub name: String,
    pub kind: NodeKind,
    pub role: NodeRole,
    pub wg_public_key: Bytes32,
    /// Ed25519 node identity (signs VWCP ServerHello and attestation).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity_key: Option<Bytes32>,
    pub endpoints: Vec<Endpoint>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub amnezia: Option<AmneziaParams>,
    /// ISO 3166-1 alpha-2, informational and for `--country` filtering only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub country: Option<String>,
    #[serde(default)]
    pub ipv6_exit: bool,
    /// Static tunnel addresses (WARP / generic nodes). VoidWire nodes assign via VWCP.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub static_v4: Option<Ipv4Addr>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub static_v6: Option<Ipv6Addr>,
    /// WARP client id written into WireGuard reserved bytes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reserved: Option<[u8; 3]>,
    /// Static PSK for generic nodes (VoidWire nodes derive PQ PSKs).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub static_psk: Option<Key32>,
    /// RFC 9474 blind-token issuer public keys (one per bandwidth tier), used
    /// by F2F friends to prepare blinded session tokens.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub token_keys: Vec<TokenKeyInfo>,
    /// Client private key bound to this gateway (imported WireGuard configs:
    /// third-party providers issue one key per config). `None` = use the
    /// device's own VoidWire key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_private: Option<Key32>,
}

/// A node's blind-token issuer public key for one tier.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenKeyInfo {
    pub tier: u8,
    pub bandwidth_bps: u64,
    /// Base64 DER SubjectPublicKeyInfo.
    pub spki: String,
}

impl NodeDescriptor {
    pub fn supports_pq(&self) -> bool {
        self.kind == NodeKind::Voidwire && self.identity_key.is_some()
    }

    pub fn endpoint_for(&self, t: TransportKind) -> Option<&Endpoint> {
        self.endpoints.iter().find(|e| e.transport == t)
    }

    pub fn validate(&self) -> Result<()> {
        if self.endpoints.is_empty() {
            return Err(VwError::Config("node has no endpoints".into()));
        }
        if let Some(a) = &self.amnezia {
            a.validate()?;
        }
        if self.kind == NodeKind::Generic && self.client_private.is_none() {
            return Err(VwError::Config(
                "imported WireGuard gateway is missing its PrivateKey".into(),
            ));
        }
        if self.kind == NodeKind::Voidwire && self.identity_key.is_none() {
            return Err(VwError::Config(
                "voidwire node requires identity key".into(),
            ));
        }
        if self.name.len() > 64 {
            return Err(VwError::Config("node name too long".into()));
        }
        Ok(())
    }
}

/// Connection profiles exposed in CLI and GUI.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum Profile {
    /// Optimizer picks gateways, hops and transport.
    #[default]
    Auto,
    /// Instant Free: Cloudflare WARP single hop.
    Warp,
    /// Ghost Multi-Hop: entry + exit (WARP or node entry, node exit).
    Multihop,
    /// Chameleon Stealth: anti-DPI transports only.
    Stealth,
    /// Friend-to-friend exit.
    F2f,
    /// Max Anonymity: 3 hops / Tor exit, DAITA on, stealth transport.
    MaxAnonymity,
}

impl Profile {
    pub const ALL: [Profile; 6] = [
        Profile::Auto,
        Profile::Warp,
        Profile::Multihop,
        Profile::Stealth,
        Profile::F2f,
        Profile::MaxAnonymity,
    ];
    pub const fn label(self) -> &'static str {
        match self {
            Profile::Auto => "Auto (fastest zero-leak)",
            Profile::Warp => "Instant Free (WARP)",
            Profile::Multihop => "Ghost Multi-Hop",
            Profile::Stealth => "Chameleon Stealth",
            Profile::F2f => "Friend Exit",
            Profile::MaxAnonymity => "Max Anonymity",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum BlockMode {
    /// Answer with 0.0.0.0 / ::.
    ZeroIp,
    Nxdomain,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, PartialOrd, Ord)]
#[serde(rename_all = "kebab-case")]
pub enum ShieldCategory {
    Ads,
    Trackers,
    Telemetry,
    Malware,
    Custom,
}

impl ShieldCategory {
    pub const ALL: [ShieldCategory; 5] = [
        ShieldCategory::Ads,
        ShieldCategory::Trackers,
        ShieldCategory::Telemetry,
        ShieldCategory::Malware,
        ShieldCategory::Custom,
    ];
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "protocol", rename_all = "kebab-case")]
pub enum DnsUpstream {
    /// Oblivious DoH: query sealed for `target`, relayed by `proxy`.
    Odoh {
        proxy_url: String,
        target_host: String,
        target_path: String,
    },
    Doh {
        url: String,
    },
    Dot {
        host: String,
        addr: IpAddr,
        port: u16,
    },
}

impl DnsUpstream {
    pub fn default_odoh() -> Self {
        DnsUpstream::Odoh {
            proxy_url: "https://odoh1.surfdomeinen.nl/proxy".into(),
            target_host: "odoh.cloudflare-dns.com".into(),
            target_path: "/dns-query".into(),
        }
    }
    pub fn default_doh() -> Self {
        DnsUpstream::Doh {
            url: "https://dns.quad9.net/dns-query".into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShieldSettings {
    pub enabled: bool,
    pub categories: Vec<ShieldCategory>,
    pub cname_uncloak: bool,
    pub block_mode: BlockMode,
    #[serde(default)]
    pub custom_block: Vec<String>,
    #[serde(default)]
    pub allow: Vec<String>,
}

impl Default for ShieldSettings {
    fn default() -> Self {
        Self {
            enabled: true,
            categories: vec![
                ShieldCategory::Ads,
                ShieldCategory::Trackers,
                ShieldCategory::Telemetry,
                ShieldCategory::Malware,
                ShieldCategory::Custom,
            ],
            cname_uncloak: true,
            block_mode: BlockMode::ZeroIp,
            custom_block: Vec::new(),
            allow: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsSettings {
    /// Ordered list; the first healthy upstream wins.
    pub upstreams: Vec<DnsUpstream>,
    pub shield: ShieldSettings,
    /// Cache TTL ceiling (seconds). Cache lives in RAM only.
    pub max_cache_ttl: u32,
}

impl Default for DnsSettings {
    fn default() -> Self {
        Self {
            upstreams: vec![DnsUpstream::default_odoh(), DnsUpstream::default_doh()],
            shield: ShieldSettings::default(),
            max_cache_ttl: 300,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FirewallSettings {
    pub block_webrtc_stun: bool,
    pub strict_ipv6: bool,
    pub block_router_adverts: bool,
    pub block_mdns_netbios: bool,
    pub block_foreign_dot: bool,
    /// Allow RFC 1918 / link-local LAN traffic outside the tunnel (printers etc.).
    pub allow_lan: bool,
    /// Re-arm lockdown at boot until the user disarms.
    pub boot_lock: bool,
}

impl Default for FirewallSettings {
    fn default() -> Self {
        Self {
            block_webrtc_stun: true,
            strict_ipv6: true,
            block_router_adverts: true,
            block_mdns_netbios: true,
            block_foreign_dot: true,
            allow_lan: false,
            boot_lock: true,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SanitizerSettings {
    pub normalize_ttl: bool,
    pub clamp_mss: bool,
    pub scrub_tcp_timestamps: bool,
}

impl Default for SanitizerSettings {
    fn default() -> Self {
        Self {
            normalize_ttl: true,
            clamp_mss: true,
            scrub_tcp_timestamps: true,
        }
    }
}

/// User-facing settings persisted by the daemon.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Settings {
    pub firewall: FirewallSettings,
    pub dns: DnsSettings,
    pub daita: DaitaParams,
    pub sanitizer: SanitizerSettings,
    pub auto_optimize: bool,
    /// Forces a transport; `None` lets the optimizer decide.
    #[serde(default)]
    pub transport_preference: Option<TransportKind>,
    pub pq_rotate_secs: u64,
    pub default_profile: Profile,
    /// Volatile live DNS inspector stream (never persisted).
    #[serde(default)]
    pub live_inspector: bool,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            firewall: FirewallSettings::default(),
            dns: DnsSettings::default(),
            daita: DaitaParams::default(),
            sanitizer: SanitizerSettings::default(),
            auto_optimize: true,
            transport_preference: None,
            pq_rotate_secs: consts::PQ_ROTATE_SECS,
            default_profile: Profile::Auto,
            live_inspector: false,
        }
    }
}

/// Anonymous Cloudflare WARP device registration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WarpAccount {
    pub device_id: String,
    pub access_token: SecretVec,
    pub private_key: Key32,
    pub peer_public_key: Bytes32,
    pub client_id: [u8; 3],
    pub v4: Ipv4Addr,
    pub v6: Ipv6Addr,
    pub endpoint_host: String,
    pub endpoint_port: u16,
    #[serde(default)]
    pub endpoint_v4: Option<Ipv4Addr>,
    #[serde(default)]
    pub endpoint_v6: Option<Ipv6Addr>,
}

impl WarpAccount {
    pub fn to_node(&self) -> NodeDescriptor {
        let mut endpoints = Vec::new();
        let host = self
            .endpoint_v4
            .map(|a| a.to_string())
            .unwrap_or_else(|| self.endpoint_host.clone());
        endpoints.push(Endpoint {
            transport: TransportKind::NativeUdp,
            host,
            port: self.endpoint_port,
            sni: None,
            path: None,
            cert_sha256: None,
        });
        NodeDescriptor {
            version: 1,
            name: "Cloudflare WARP".into(),
            kind: NodeKind::Warp,
            role: NodeRole::Entry,
            wg_public_key: self.peer_public_key,
            identity_key: None,
            endpoints,
            amnezia: None,
            country: None,
            ipv6_exit: true,
            static_v4: Some(self.v4),
            static_v6: Some(self.v6),
            reserved: Some(self.client_id),
            static_psk: None,
            token_keys: Vec::new(),
            client_private: None,
        }
    }
}

/// Persistent client store (`<config_dir>/store.json`, mode 0600).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ClientStore {
    /// Client WireGuard static private key (shared by all VoidWire nodes;
    /// rotated by `panic`).
    #[serde(default)]
    pub wg_private: Option<Key32>,
    #[serde(default)]
    pub nodes: Vec<NodeDescriptor>,
    #[serde(default)]
    pub warp: Option<WarpAccount>,
    /// Unspent Chaumian session tokens per node identity (base64 blobs).
    #[serde(default)]
    pub f2f_tokens: Vec<(Bytes32, Vec<SecretVec>)>,
    #[serde(default)]
    pub settings: Settings,
    /// Per-install salt for network fingerprints.
    #[serde(default)]
    pub network_salt: Option<Key32>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn amnezia_random_is_valid() {
        for _ in 0..200 {
            AmneziaParams::random().validate().unwrap();
        }
    }

    #[test]
    fn amnezia_rejects_duplicates() {
        let mut p = AmneziaParams::random();
        p.h2 = p.h1;
        assert!(p.validate().is_err());
    }

    #[test]
    fn settings_defaults_are_safe() {
        let s = Settings::default();
        assert!(s.firewall.block_webrtc_stun);
        assert!(s.firewall.strict_ipv6);
        assert!(s.firewall.boot_lock);
        assert!(!s.firewall.allow_lan);
        assert!(s.dns.shield.cname_uncloak);
        let j = serde_json::to_string(&s).unwrap();
        let back: Settings = serde_json::from_str(&j).unwrap();
        assert_eq!(s, back);
    }

    #[test]
    fn daita_bucket() {
        let d = DaitaParams::default();
        assert_eq!(d.bucket_for(100), 128);
        assert_eq!(d.bucket_for(1300), 1300);
    }
}
