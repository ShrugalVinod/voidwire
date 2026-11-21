//! TLS trust configuration and the bootstrap resolver used by the HTTPS clients.
//!
//! All sockets opened here are ordinary, unmarked sockets: on a live system
//! they follow the default route, which is the VoidWire tunnel, so encrypted
//! DNS never touches the physical interface directly.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use hickory_proto::op::{Message, MessageType, OpCode, Query};
use hickory_proto::rr::{Name, RData, RecordType};
use rustls::pki_types::CertificateDer;
use rustls::{ClientConfig, RootCertStore};

use crate::error::{DnsError, Result};

/// The rustls crypto provider used across the crate.
pub fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// Which certificate authorities the DoH/DoT/ODoH clients trust.
#[derive(Clone, Default)]
pub struct TlsTrust {
    extra_roots: Vec<CertificateDer<'static>>,
    without_webpki: bool,
}

impl std::fmt::Debug for TlsTrust {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TlsTrust")
            .field("extra_roots", &self.extra_roots.len())
            .field("webpki_roots", &!self.without_webpki)
            .finish()
    }
}

impl TlsTrust {
    /// Mozilla's root program (webpki-roots); never the OS store, which a
    /// local attacker or MDM profile could have extended.
    pub fn webpki() -> Self {
        Self::default()
    }

    /// Trust only the given roots (private resolvers, tests).
    pub fn only(roots: Vec<CertificateDer<'static>>) -> Self {
        Self {
            extra_roots: roots,
            without_webpki: true,
        }
    }

    /// Add a root on top of the current set.
    pub fn with_root(mut self, root: CertificateDer<'static>) -> Self {
        self.extra_roots.push(root);
        self
    }

    fn roots(&self) -> Result<RootCertStore> {
        let mut store = RootCertStore::empty();
        if !self.without_webpki {
            store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        }
        for r in &self.extra_roots {
            store
                .add(r.clone())
                .map_err(|e| DnsError::Tls(e.to_string()))?;
        }
        if store.is_empty() {
            return Err(DnsError::Tls("no trust anchors".into()));
        }
        Ok(store)
    }

    /// A rustls client config (TLS 1.2+/1.3, ring) with the given ALPN list.
    pub fn client_config(&self, alpn: &[&[u8]]) -> Result<ClientConfig> {
        let mut cfg = ClientConfig::builder_with_provider(provider())
            .with_safe_default_protocol_versions()
            .map_err(|e| DnsError::Tls(e.to_string()))?
            .with_root_certificates(self.roots()?)
            .with_no_client_auth();
        cfg.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
        Ok(cfg)
    }
}

/// Built-in addresses of well-known encrypted resolvers. These are the
/// operators' published anycast addresses, which also appear in their
/// certificates' SANs.
const WELL_KNOWN: &[(&str, &[IpAddr])] = &[
    (
        "dns.quad9.net",
        &[
            IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9)),
            IpAddr::V4(Ipv4Addr::new(149, 112, 112, 112)),
            IpAddr::V6(Ipv6Addr::new(0x2620, 0xfe, 0, 0, 0, 0, 0, 0xfe)),
            IpAddr::V6(Ipv6Addr::new(0x2620, 0xfe, 0, 0, 0, 0, 0, 0x9)),
        ],
    ),
    (
        "dns9.quad9.net",
        &[
            IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9)),
            IpAddr::V4(Ipv4Addr::new(149, 112, 112, 9)),
        ],
    ),
    (
        "cloudflare-dns.com",
        &[
            IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
            IpAddr::V4(Ipv4Addr::new(1, 0, 0, 1)),
            IpAddr::V6(Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111)),
            IpAddr::V6(Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1001)),
        ],
    ),
    (
        "one.one.one.one",
        &[
            IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
            IpAddr::V4(Ipv4Addr::new(1, 0, 0, 1)),
        ],
    ),
    (
        "security.cloudflare-dns.com",
        &[
            IpAddr::V4(Ipv4Addr::new(1, 1, 1, 2)),
            IpAddr::V4(Ipv4Addr::new(1, 0, 0, 2)),
        ],
    ),
    (
        "dns.google",
        &[
            IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            IpAddr::V4(Ipv4Addr::new(8, 8, 4, 4)),
            IpAddr::V6(Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888)),
        ],
    ),
    (
        "dns.mullvad.net",
        &[
            IpAddr::V4(Ipv4Addr::new(194, 242, 2, 2)),
            IpAddr::V6(Ipv6Addr::new(0x2a07, 0xe340, 0, 0, 0, 0, 0, 0x2)),
        ],
    ),
    (
        "adblock.dns.mullvad.net",
        &[IpAddr::V4(Ipv4Addr::new(194, 242, 2, 3))],
    ),
    (
        "dns.adguard-dns.com",
        &[
            IpAddr::V4(Ipv4Addr::new(94, 140, 14, 14)),
            IpAddr::V4(Ipv4Addr::new(94, 140, 15, 15)),
        ],
    ),
];

/// IP-literal DoH endpoints used to look up upstream hostnames that are not
/// in the built-in table. Their certificates carry IP SANs, so no DNS is
/// needed to reach them.
const FALLBACK_DOH: &[&str] = &["https://1.1.1.1/dns-query", "https://9.9.9.9/dns-query"];

const BOOTSTRAP_CACHE_SECS: u64 = 1800;

/// Resolver for the hostnames of the encrypted upstreams themselves.
///
/// The OS resolver points at the vault, so asking it for `dns.quad9.net`
/// would recurse into the very upstream we are trying to reach. Instead we
/// use (1) explicit overrides, (2) a built-in table of well-known resolvers,
/// (3) a DoH lookup against IP-literal endpoints. Only upstream hostnames
/// ever go through this path, never user queries. Cheap to clone.
#[derive(Clone)]
pub struct Bootstrap {
    inner: Arc<BootstrapInner>,
}

struct BootstrapInner {
    table: HashMap<String, Vec<IpAddr>>,
    fallback: Option<reqwest::Client>,
    fallback_urls: Vec<String>,
    cache: Mutex<HashMap<String, (Vec<IpAddr>, Instant)>>,
}

impl std::fmt::Debug for Bootstrap {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Bootstrap")
            .field("entries", &self.inner.table.len())
            .field("fallback", &self.inner.fallback.is_some())
            .finish()
    }
}

impl Bootstrap {
    /// Built-in table plus DoH-over-IP-literal fallback.
    pub fn new() -> Result<Self> {
        let mut table = HashMap::new();
        for (host, addrs) in WELL_KNOWN {
            table.insert((*host).to_string(), addrs.to_vec());
        }
        let tls = TlsTrust::webpki().client_config(&[b"h2"])?;
        let client = reqwest::Client::builder()
            .tls_backend_preconfigured(tls)
            .http2_prior_knowledge()
            .redirect(reqwest::redirect::Policy::none())
            .referer(false)
            .no_proxy()
            .timeout(Duration::from_secs(5))
            .build()
            .map_err(|e| DnsError::Tls(e.without_url().to_string()))?;
        Ok(Self::from_parts(
            table,
            Some(client),
            FALLBACK_DOH.iter().map(|s| s.to_string()).collect(),
        ))
    }

    /// Only the given static entries; unknown names fail (no network lookups).
    pub fn static_only(entries: impl IntoIterator<Item = (String, Vec<IpAddr>)>) -> Self {
        Self::from_parts(
            entries
                .into_iter()
                .map(|(h, a)| (h.to_ascii_lowercase(), a))
                .collect(),
            None,
            Vec::new(),
        )
    }

    fn from_parts(
        table: HashMap<String, Vec<IpAddr>>,
        fallback: Option<reqwest::Client>,
        fallback_urls: Vec<String>,
    ) -> Self {
        Self {
            inner: Arc::new(BootstrapInner {
                table,
                fallback,
                fallback_urls,
                cache: Mutex::new(HashMap::new()),
            }),
        }
    }

    /// Pin `host` to `addrs` (takes precedence over the table and the fallback).
    pub fn with_override(self, host: &str, addrs: Vec<IpAddr>) -> Self {
        let mut table = self.inner.table.clone();
        table.insert(host.trim_end_matches('.').to_ascii_lowercase(), addrs);
        Self::from_parts(
            table,
            self.inner.fallback.clone(),
            self.inner.fallback_urls.clone(),
        )
    }

    /// Resolve an upstream hostname.
    pub async fn lookup(&self, host: &str) -> Result<Vec<IpAddr>> {
        let inner = &self.inner;
        let host = host.trim_end_matches('.').to_ascii_lowercase();
        let bare = host.trim_start_matches('[').trim_end_matches(']');
        if let Ok(ip) = bare.parse::<IpAddr>() {
            return Ok(vec![ip]);
        }
        if let Some(a) = inner.table.get(&host) {
            return Ok(a.clone());
        }
        let cached = inner.cache.lock().ok().and_then(|c| c.get(&host).cloned());
        if let Some((addrs, at)) = cached {
            if at.elapsed() < Duration::from_secs(BOOTSTRAP_CACHE_SECS) {
                return Ok(addrs);
            }
        }
        let Some(client) = &inner.fallback else {
            return Err(DnsError::Config(
                "upstream host has no bootstrap address".into(),
            ));
        };
        let name = Name::from_ascii(format!("{host}."))
            .map_err(|_| DnsError::Config("invalid upstream hostname".into()))?;
        let mut last = DnsError::AllUpstreamsFailed;
        for url in &inner.fallback_urls {
            let mut out = Vec::new();
            for qt in [RecordType::A, RecordType::AAAA] {
                match fallback_query(client, url, &name, qt).await {
                    Ok(mut v) => out.append(&mut v),
                    Err(e) => last = e,
                }
            }
            if !out.is_empty() {
                if let Ok(mut c) = inner.cache.lock() {
                    if c.len() > 256 {
                        c.clear();
                    }
                    c.insert(host.clone(), (out.clone(), Instant::now()));
                }
                return Ok(out);
            }
        }
        Err(last)
    }
}

async fn fallback_query(
    client: &reqwest::Client,
    url: &str,
    name: &Name,
    qtype: RecordType,
) -> Result<Vec<IpAddr>> {
    let mut m = Message::new();
    m.set_id(0)
        .set_message_type(MessageType::Query)
        .set_op_code(OpCode::Query)
        .set_recursion_desired(true);
    m.add_query(Query::query(name.clone(), qtype));
    let body = crate::message::encode(&m)?;
    let resp = client
        .post(url)
        .header("content-type", "application/dns-message")
        .header("accept", "application/dns-message")
        .body(body)
        .send()
        .await
        .map_err(|e| DnsError::http("bootstrap", e))?;
    if !resp.status().is_success() {
        return Err(DnsError::upstream("bootstrap", resp.status()));
    }
    let bytes = resp
        .bytes()
        .await
        .map_err(|e| DnsError::http("bootstrap", e))?;
    let msg = Message::from_vec(&bytes)?;
    Ok(msg
        .answers()
        .iter()
        .filter_map(|r| match r.data() {
            RData::A(a) => Some(IpAddr::V4(a.0)),
            RData::AAAA(a) => Some(IpAddr::V6(a.0)),
            _ => None,
        })
        .collect())
}

impl reqwest::dns::Resolve for Bootstrap {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        let host = name.as_str().to_string();
        let this = self.clone();
        Box::pin(async move {
            let addrs = this.lookup(&host).await?;
            let it: reqwest::dns::Addrs =
                Box::new(addrs.into_iter().map(|ip| SocketAddr::new(ip, 0)));
            Ok(it)
        })
    }
}
