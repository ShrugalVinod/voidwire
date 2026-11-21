//! The DNS vault: the only resolver the host talks to.
//!
//! Every query is validated, answered locally when it must never leave the
//! host (`*.local`, `*.lan`, private reverse zones, the Firefox DoH canary),
//! checked against the Shield, served from the RAM cache, or forwarded over
//! an encrypted upstream with ECS stripped and DNSSEC OK set. Answers are
//! CNAME-uncloaked before they are cached or returned. Nothing is persisted:
//! the only per-name output is the optional, volatile inspector broadcast.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering::Relaxed};
use std::sync::Arc;
use std::time::Duration;

use hickory_proto::op::{Message, ResponseCode};
use hickory_proto::rr::rdata::{A, AAAA};
use hickory_proto::rr::{RData, Record, RecordType};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::{broadcast, Semaphore};
use tokio::task::JoinHandle;
use vw_core::config::{DnsSettings, ShieldCategory};
use vw_core::telemetry::Counters;

use crate::cache::{CacheKey, DnsCache, DEFAULT_CACHE_BYTES, DEFAULT_CACHE_ENTRIES};
use crate::error::Result;
use crate::message::{
    self, cache_ttl, class_supported, client_udp_limit, encode, encode_fitting, error_for_raw,
    error_response, finalize_for_client, name_key, parse_query, prepare_upstream_query,
    response_for, EDNS_UDP_SIZE,
};
use crate::shield::Shield;
use crate::uncloak::{synthesize_block, uncloak};
use crate::upstream::Upstream;

/// Firefox's DoH canary: NXDOMAIN tells browsers to keep using the system resolver (us).
pub const FIREFOX_CANARY: &str = "use-application-dns.net";
/// Overall budget for one upstream resolution (failover included).
pub const RESOLVE_TIMEOUT: Duration = Duration::from_secs(10);
/// Capacity of the inspector channel (lagging receivers drop events).
const INSPECTOR_CAPACITY: usize = 256;
const MAX_UDP_INFLIGHT: usize = 1024;
const MAX_TCP_CONNECTIONS: usize = 256;
const TCP_IDLE: Duration = Duration::from_secs(10);
const TCP_MAX_QUERIES_PER_CONN: usize = 100;

/// Suffixes answered NXDOMAIN locally and never forwarded: mDNS / home LAN
/// names, special-use domains (RFC 6761/8375) and reverse zones of private,
/// CGNAT (tunnel) and link-local address space.
const LOCAL_SUFFIXES: &[&str] = &[
    "local",
    "lan",
    "home.arpa",
    "internal",
    "localdomain",
    "invalid",
    "10.in-addr.arpa",
    "168.192.in-addr.arpa",
    "254.169.in-addr.arpa",
    "d.f.ip6.arpa",
    "c.f.ip6.arpa",
    "8.e.f.ip6.arpa",
    "9.e.f.ip6.arpa",
    "a.e.f.ip6.arpa",
    "b.e.f.ip6.arpa",
];

fn is_local_name(name: &[u8]) -> bool {
    let ends_with = |suffix: &str| {
        let s = suffix.as_bytes();
        name == s
            || (name.len() > s.len() && name.ends_with(s) && name[name.len() - s.len() - 1] == b'.')
    };
    if LOCAL_SUFFIXES.iter().any(|s| ends_with(s)) {
        return true;
    }
    // 172.16/12 and 100.64/10 reverse zones.
    (16..32).any(|o| ends_with(&format!("{o}.172.in-addr.arpa")))
        || (64..128).any(|o| ends_with(&format!("{o}.100.in-addr.arpa")))
}

fn is_localhost(name: &[u8]) -> bool {
    name == b"localhost" || name.ends_with(b".localhost")
}

/// One inspector event (only produced while the inspector is enabled).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InspectorEvent {
    pub name: String,
    pub category: Option<ShieldCategory>,
    pub blocked: bool,
}

/// How a query was answered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Disposition {
    /// Malformed or unsupported query (FORMERR / NOTIMP / REFUSED).
    Rejected,
    /// Answered locally (local names, canary, localhost).
    Local,
    /// Question name blocked by the Shield.
    Blocked(ShieldCategory),
    /// A CNAME in the upstream answer chain was blocked.
    Uncloaked(ShieldCategory),
    Cached,
    Forwarded,
    /// Upstream failure → SERVFAIL.
    Failed,
}

/// Full result of a resolution.
#[derive(Debug, Clone)]
pub struct Resolution {
    /// Well-formed DNS response for the client.
    pub response: Vec<u8>,
    pub disposition: Disposition,
    /// Upstream set AD. Validation was done by the upstream resolver; the
    /// flag is trusted only because the channel is authenticated.
    pub dnssec_validated: bool,
}

/// The local encrypted resolver.
pub struct DnsVault {
    settings: DnsSettings,
    shield: Arc<Shield>,
    cache: DnsCache,
    upstream: Arc<dyn Upstream>,
    counters: Arc<Counters>,
    inspector_on: AtomicBool,
    inspector: broadcast::Sender<InspectorEvent>,
}

impl std::fmt::Debug for DnsVault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DnsVault")
            .field("upstream", &self.upstream.name())
            .field("cached", &self.cache.len())
            .finish()
    }
}

impl DnsVault {
    pub fn new(
        settings: DnsSettings,
        upstream: Arc<dyn Upstream>,
        counters: Arc<Counters>,
    ) -> Self {
        let shield = Arc::new(Shield::new(&settings.shield));
        let cache = DnsCache::new(
            DEFAULT_CACHE_ENTRIES,
            DEFAULT_CACHE_BYTES,
            settings.max_cache_ttl,
        );
        let (inspector, _) = broadcast::channel(INSPECTOR_CAPACITY);
        Self {
            settings,
            shield,
            cache,
            upstream,
            counters,
            inspector_on: AtomicBool::new(false),
            inspector,
        }
    }

    pub fn shield(&self) -> &Arc<Shield> {
        &self.shield
    }

    pub fn counters(&self) -> &Arc<Counters> {
        &self.counters
    }

    pub fn settings(&self) -> &DnsSettings {
        &self.settings
    }

    /// Apply new Shield settings; the cache is flushed so earlier answers
    /// do not outlive a changed policy.
    pub fn reload_shield(&self, shield: &vw_core::config::ShieldSettings) {
        self.shield.reload(shield);
        self.cache.flush();
    }

    /// Drop every cached answer (panic button).
    pub fn flush(&self) {
        self.cache.flush();
    }

    pub fn cache_len(&self) -> usize {
        self.cache.len()
    }

    /// Enable / disable the volatile inspector feed.
    pub fn set_inspector(&self, enabled: bool) {
        self.inspector_on.store(enabled, Relaxed);
    }

    /// Subscribe to inspector events (nothing is emitted while disabled).
    pub fn subscribe(&self) -> broadcast::Receiver<InspectorEvent> {
        self.inspector.subscribe()
    }

    fn inspect(&self, name: &[u8], category: Option<ShieldCategory>, blocked: bool) {
        if !self.inspector_on.load(Relaxed) || self.inspector.receiver_count() == 0 {
            return;
        }
        let _ = self.inspector.send(InspectorEvent {
            name: String::from_utf8_lossy(name).into_owned(),
            category,
            blocked,
        });
    }

    /// Resolve a query; always returns a well-formed DNS response.
    pub async fn resolve(&self, query_wire: &[u8]) -> Vec<u8> {
        self.resolve_detailed(query_wire).await.response
    }

    /// Resolve for a UDP client: the answer is fitted to the client's EDNS
    /// size (bounded by `cap`, e.g. what fits the tunnel MTU), setting TC if needed.
    pub async fn resolve_udp(&self, query_wire: &[u8], cap: usize) -> Vec<u8> {
        let res = self.resolve_detailed(query_wire).await;
        let Ok(q) = Message::from_vec(query_wire) else {
            return res.response;
        };
        let limit = client_udp_limit(&q, cap);
        if res.response.len() <= limit {
            return res.response;
        }
        match Message::from_vec(&res.response) {
            Ok(m) => encode_fitting(&m, limit).unwrap_or(res.response),
            Err(_) => res.response,
        }
    }

    /// Resolve and report how the answer was produced.
    pub async fn resolve_detailed(&self, query_wire: &[u8]) -> Resolution {
        let reject = |response| Resolution {
            response,
            disposition: Disposition::Rejected,
            dnssec_validated: false,
        };
        let query = match parse_query(query_wire) {
            Ok(q) => q,
            Err((rcode, e)) => {
                tracing::trace!(error = %e, "rejecting query");
                return reject(error_for_raw(query_wire, rcode));
            }
        };
        let Some(q) = query.queries().first().cloned() else {
            return reject(error_response(&query, ResponseCode::FormErr));
        };
        if !class_supported(q.query_class()) {
            return reject(error_response(&query, ResponseCode::Refused));
        }
        if matches!(
            q.query_type(),
            RecordType::AXFR | RecordType::IXFR | RecordType::ANY
        ) {
            // Zone transfers and ANY (RFC 8482) are not proxied.
            return reject(error_response(&query, ResponseCode::Refused));
        }
        let name = name_key(q.name());
        tracing::trace!(name = %vw_core::redact::name(&String::from_utf8_lossy(&name)), "query");

        // 1. Never-forwarded names.
        if let Some(r) = self.answer_locally(&query, &name, q.query_type()) {
            self.inspect(&name, None, false);
            return Resolution {
                response: r,
                disposition: Disposition::Local,
                dnssec_validated: false,
            };
        }

        // 2. Shield on the question.
        let shield_on = self.settings.shield.enabled;
        if shield_on {
            if let Some(cat) = self.shield.check_name(q.name()) {
                self.counters.shield_hit(cat);
                self.inspect(&name, Some(cat), true);
                let m = synthesize_block(&query, self.settings.shield.block_mode);
                return Resolution {
                    response: encode(&m)
                        .unwrap_or_else(|_| error_response(&query, ResponseCode::ServFail)),
                    disposition: Disposition::Blocked(cat),
                    dnssec_validated: false,
                };
            }
        }

        // 3. Cache (holds upstream answers; uncloaking is re-run on hits).
        let key = CacheKey::for_query(&query);
        if let Some(hit) = key.as_ref().and_then(|k| self.cache.get(k)) {
            return self.serve_answer(&query, &name, hit.message, Disposition::Cached);
        }

        // 4. Upstream.
        let upstream_id: u16 = rand::random();
        let Ok(up_query) = prepare_upstream_query(&query, upstream_id) else {
            return reject(error_response(&query, ResponseCode::FormErr));
        };
        let servfail = || Resolution {
            response: error_response(&query, ResponseCode::ServFail),
            disposition: Disposition::Failed,
            dnssec_validated: false,
        };
        let raw = match tokio::time::timeout(RESOLVE_TIMEOUT, self.upstream.query(&up_query)).await
        {
            Ok(Ok(r)) => r,
            Ok(Err(e)) => {
                tracing::debug!(error = %e, "upstream resolution failed");
                return servfail();
            }
            Err(_) => {
                tracing::debug!("upstream resolution timed out");
                return servfail();
            }
        };
        let (Ok(mut resp), Ok(up_msg)) = (Message::from_vec(&raw), Message::from_vec(&up_query))
        else {
            return servfail();
        };
        if !message::response_matches(&up_msg, &resp) {
            tracing::debug!("upstream answer does not match the question");
            return servfail();
        }
        message::strip_ecs(&mut resp);
        message::clamp_ttls(&mut resp, self.settings.max_cache_ttl.max(1));
        if let (Some(k), Some(ttl)) = (key, cache_ttl(&resp)) {
            if let Ok(w) = encode(&resp) {
                self.cache.insert(k, w, ttl);
            }
        }
        self.serve_answer(&query, &name, resp, Disposition::Forwarded)
    }

    /// Uncloak, then shape an upstream (or cached) answer for this client.
    fn serve_answer(
        &self,
        query: &Message,
        name: &[u8],
        mut resp: Message,
        disposition: Disposition,
    ) -> Resolution {
        let shield = &self.settings.shield;
        if shield.enabled && shield.cname_uncloak {
            if let Some((cat, blocked)) = uncloak(&self.shield, query, &resp, shield.block_mode) {
                Counters::add(&self.counters.shield_cname_uncloaked, 1);
                self.counters.shield_hit(cat);
                self.inspect(name, Some(cat), true);
                return Resolution {
                    response: encode(&blocked)
                        .unwrap_or_else(|_| error_response(query, ResponseCode::ServFail)),
                    disposition: Disposition::Uncloaked(cat),
                    dnssec_validated: false,
                };
            }
        }
        let dnssec_validated = resp.authentic_data();
        finalize_for_client(&mut resp, query);
        self.inspect(name, None, false);
        match encode(&resp) {
            Ok(w) => Resolution {
                response: w,
                disposition,
                dnssec_validated,
            },
            Err(_) => Resolution {
                response: error_response(query, ResponseCode::ServFail),
                disposition: Disposition::Failed,
                dnssec_validated: false,
            },
        }
    }

    fn answer_locally(&self, query: &Message, name: &[u8], qtype: RecordType) -> Option<Vec<u8>> {
        if name == FIREFOX_CANARY.as_bytes() || name.ends_with(b".use-application-dns.net") {
            return encode(&response_for(query, ResponseCode::NXDomain)).ok();
        }
        if is_localhost(name) {
            // RFC 6761 §6.3: localhost is loopback, resolved locally.
            let mut r = response_for(query, ResponseCode::NoError);
            let q = query.queries().first()?;
            let rd = match qtype {
                RecordType::A => Some(RData::A(A::new(127, 0, 0, 1))),
                RecordType::AAAA => Some(RData::AAAA(AAAA::new(0, 0, 0, 0, 0, 0, 0, 1))),
                _ => None,
            };
            if let Some(rd) = rd {
                r.add_answer(Record::from_rdata(q.name().clone(), 300, rd));
            }
            return encode(&r).ok();
        }
        if is_local_name(name) {
            return encode(&response_for(query, ResponseCode::NXDomain)).ok();
        }
        None
    }
}

/// A running vault listener; aborted on drop.
#[derive(Debug)]
pub struct DnsServer {
    local_addr: SocketAddr,
    task: JoinHandle<()>,
}

impl DnsServer {
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    pub fn shutdown(self) {
        self.task.abort();
    }
}

impl Drop for DnsServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// Serve the vault over UDP on `bind` (e.g. `DNS_VAULT_V4:53`), used when the
/// OS resolver is pointed at the vault address.
pub async fn serve_udp(vault: Arc<DnsVault>, bind: SocketAddr) -> Result<DnsServer> {
    let sock = Arc::new(UdpSocket::bind(bind).await?);
    let local_addr = sock.local_addr()?;
    let limit = Arc::new(Semaphore::new(MAX_UDP_INFLIGHT));
    let task = tokio::spawn(async move {
        let mut buf = vec![0u8; 65535];
        loop {
            let (n, peer) = match sock.recv_from(&mut buf).await {
                Ok(x) => x,
                Err(e) => {
                    tracing::debug!(error = %e, "vault udp recv error");
                    continue;
                }
            };
            let Ok(permit) = limit.clone().try_acquire_owned() else {
                continue; // overloaded: shed load
            };
            let q = buf[..n].to_vec();
            let (vault, sock) = (vault.clone(), sock.clone());
            tokio::spawn(async move {
                let resp = vault.resolve_udp(&q, EDNS_UDP_SIZE as usize).await;
                if let Err(e) = sock.send_to(&resp, peer).await {
                    tracing::trace!(error = %e, peer = %vw_core::redact::sock(&peer), "vault udp send failed");
                }
                drop(permit);
            });
        }
    });
    Ok(DnsServer { local_addr, task })
}

/// Serve the vault over TCP (RFC 7766 framing) on `bind`.
pub async fn serve_tcp(vault: Arc<DnsVault>, bind: SocketAddr) -> Result<DnsServer> {
    let listener = TcpListener::bind(bind).await?;
    let local_addr = listener.local_addr()?;
    let limit = Arc::new(Semaphore::new(MAX_TCP_CONNECTIONS));
    let task = tokio::spawn(async move {
        loop {
            let (mut stream, _) = match listener.accept().await {
                Ok(x) => x,
                Err(e) => {
                    tracing::debug!(error = %e, "vault tcp accept error");
                    continue;
                }
            };
            let Ok(permit) = limit.clone().try_acquire_owned() else {
                continue;
            };
            let vault = vault.clone();
            tokio::spawn(async move {
                let _ = stream.set_nodelay(true);
                for _ in 0..TCP_MAX_QUERIES_PER_CONN {
                    let mut lb = [0u8; 2];
                    match tokio::time::timeout(TCP_IDLE, stream.read_exact(&mut lb)).await {
                        Ok(Ok(_)) => {}
                        _ => break,
                    }
                    let n = u16::from_be_bytes(lb) as usize;
                    let mut q = vec![0u8; n];
                    match tokio::time::timeout(TCP_IDLE, stream.read_exact(&mut q)).await {
                        Ok(Ok(_)) => {}
                        _ => break,
                    }
                    let resp = vault.resolve(&q).await;
                    let mut frame = Vec::with_capacity(resp.len() + 2);
                    frame.extend_from_slice(
                        &(resp.len().min(u16::MAX as usize) as u16).to_be_bytes(),
                    );
                    frame.extend_from_slice(&resp[..resp.len().min(u16::MAX as usize)]);
                    if stream.write_all(&frame).await.is_err() {
                        break;
                    }
                }
                drop(permit);
            });
        }
    });
    Ok(DnsServer { local_addr, task })
}
