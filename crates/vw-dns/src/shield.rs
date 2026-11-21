//! Shield: domain blocklists with parent-domain matching, allowlist
//! overrides and per-category membership.
//!
//! The index is an immutable hash map keyed by the lower-cased name; a lookup
//! walks the name's suffixes (`a.b.c` → `a.b.c`, `b.c`, `c`), which is a
//! reversed-label trie walk without pointer chasing. Readers load the current
//! index through `ArcSwap` (lock-free); reloads build a new index and swap it.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use arc_swap::ArcSwap;
use hickory_proto::rr::Name;
use vw_core::config::{ShieldCategory, ShieldSettings};

use crate::error::{DnsError, Result};
use crate::tls::{Bootstrap, TlsTrust};

const BUILTIN_ADS: &str = include_str!("../lists/ads.txt");
const BUILTIN_TRACKERS: &str = include_str!("../lists/trackers.txt");
const BUILTIN_TELEMETRY: &str = include_str!("../lists/telemetry.txt");
const BUILTIN_MALWARE: &str = include_str!("../lists/malware.txt");

/// Longest presentation-format name (without trailing dot).
const MAX_NAME: usize = 253;

/// Priority when a domain is in several categories (most severe first).
const PRIORITY: [ShieldCategory; 5] = [
    ShieldCategory::Malware,
    ShieldCategory::Trackers,
    ShieldCategory::Telemetry,
    ShieldCategory::Ads,
    ShieldCategory::Custom,
];

fn bit(c: ShieldCategory) -> u8 {
    match c {
        ShieldCategory::Ads => 1,
        ShieldCategory::Trackers => 2,
        ShieldCategory::Telemetry => 4,
        ShieldCategory::Malware => 8,
        ShieldCategory::Custom => 16,
    }
}

fn first_category(mask: u8) -> Option<ShieldCategory> {
    PRIORITY.into_iter().find(|c| mask & bit(*c) != 0)
}

/// Category masks of one index entry.
#[derive(Debug, Clone, Copy, Default)]
struct Entry {
    /// Blocks the name itself and every subdomain (`example.com`).
    tree: u8,
    /// Blocks only strict subdomains (`*.example.com`).
    subs: u8,
}

/// Immutable lookup structure.
#[derive(Debug, Default)]
struct Index {
    enabled: bool,
    enabled_mask: u8,
    block: HashMap<Box<[u8]>, Entry>,
    /// Allowlist: value = subdomains only (`*.` form).
    allow: HashMap<Box<[u8]>, bool>,
}

impl Index {
    /// Walk the suffixes of `name`; returns (block mask, allowlisted).
    fn scan(&self, name: &[u8]) -> (u8, bool) {
        let mut mask = 0u8;
        let mut pos = 0usize;
        let mut first = true;
        loop {
            let suffix = &name[pos..];
            if let Some(e) = self.block.get(suffix) {
                mask |= e.tree;
                if !first {
                    mask |= e.subs;
                }
            }
            if let Some(sub_only) = self.allow.get(suffix) {
                if !(first && *sub_only) {
                    return (mask, true);
                }
            }
            match suffix.iter().position(|b| *b == b'.') {
                Some(dot) => {
                    pos += dot + 1;
                    first = false;
                }
                None => return (mask, false),
            }
        }
    }
}

/// A downloaded list: its category and parsed entries.
type ExternalList = (ShieldCategory, Arc<Vec<Box<str>>>);

/// External list state kept so reloads can rebuild the index.
#[derive(Debug, Default)]
struct Sources {
    settings: ShieldSettings,
    /// url → (category, domains) downloaded by [`BlocklistUpdater`].
    external: HashMap<String, ExternalList>,
}

/// The ad / tracker / telemetry / malware blocker.
#[derive(Debug)]
pub struct Shield {
    index: ArcSwap<Index>,
    sources: Mutex<Sources>,
}

impl Shield {
    /// Build from settings with the built-in curated lists.
    pub fn new(settings: &ShieldSettings) -> Self {
        let sources = Sources {
            settings: settings.clone(),
            external: HashMap::new(),
        };
        let index = build_index(&sources);
        Self {
            index: ArcSwap::from_pointee(index),
            sources: Mutex::new(sources),
        }
    }

    /// Apply new settings (categories, custom and allow lists, enable flag).
    pub fn reload(&self, settings: &ShieldSettings) {
        let mut s = self.sources.lock().unwrap_or_else(|p| p.into_inner());
        s.settings = settings.clone();
        self.index.store(Arc::new(build_index(&s)));
    }

    /// Install (or replace) a downloaded list.
    pub fn set_external_list(&self, url: &str, category: ShieldCategory, domains: Vec<Box<str>>) {
        let mut s = self.sources.lock().unwrap_or_else(|p| p.into_inner());
        s.external
            .insert(url.to_string(), (category, Arc::new(domains)));
        self.index.store(Arc::new(build_index(&s)));
    }

    /// Remove all downloaded lists (RAM only, so nothing to delete on disk).
    pub fn clear_external(&self) {
        let mut s = self.sources.lock().unwrap_or_else(|p| p.into_inner());
        s.external.clear();
        self.index.store(Arc::new(build_index(&s)));
    }

    /// Current settings snapshot.
    pub fn settings(&self) -> ShieldSettings {
        self.sources
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .settings
            .clone()
    }

    /// Number of indexed block entries.
    pub fn len(&self) -> usize {
        self.index.load().block.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Blocked category for `name` (presentation format, trailing dot optional),
    /// honouring enabled categories and the allowlist.
    pub fn check(&self, name: &str) -> Option<ShieldCategory> {
        with_normalized(name.as_bytes(), |n| self.check_bytes(n))
    }

    /// Same as [`Shield::check`] for a parsed DNS name.
    pub fn check_name(&self, name: &Name) -> Option<ShieldCategory> {
        let key = crate::message::name_key(name);
        self.check_bytes(&key)
    }

    /// Every category whose lists contain `name` (ignores enabled flags and allowlist).
    pub fn categories_of(&self, name: &str) -> Vec<ShieldCategory> {
        let idx = self.index.load();
        with_normalized(name.as_bytes(), |n| {
            let (mask, _) = idx.scan(n);
            PRIORITY
                .into_iter()
                .filter(|c| mask & bit(*c) != 0)
                .collect()
        })
    }

    /// Whether the allowlist covers `name`.
    pub fn is_allowed(&self, name: &str) -> bool {
        let idx = self.index.load();
        with_normalized(name.as_bytes(), |n| idx.scan(n).1)
    }

    fn check_bytes(&self, name: &[u8]) -> Option<ShieldCategory> {
        let idx = self.index.load();
        if !idx.enabled || name.is_empty() {
            return None;
        }
        let (mask, allowed) = idx.scan(name);
        if allowed {
            return None;
        }
        first_category(mask & idx.enabled_mask)
    }
}

/// Lower-case and strip the trailing dot into a stack buffer.
fn with_normalized<R>(name: &[u8], f: impl FnOnce(&[u8]) -> R) -> R {
    let name = name.strip_suffix(b".").unwrap_or(name);
    let mut buf = [0u8; MAX_NAME];
    if name.len() <= MAX_NAME {
        for (d, s) in buf.iter_mut().zip(name) {
            *d = s.to_ascii_lowercase();
        }
        f(&buf[..name.len()])
    } else {
        f(&name.to_ascii_lowercase())
    }
}

fn build_index(s: &Sources) -> Index {
    let mut block: HashMap<Box<[u8]>, Entry> = HashMap::new();
    let mut add = |pattern: &str, cat: ShieldCategory| {
        if let Some((key, subs_only)) = normalize_pattern(pattern) {
            let e = block
                .entry(key.into_bytes().into_boxed_slice())
                .or_default();
            if subs_only {
                e.subs |= bit(cat);
            } else {
                e.tree |= bit(cat);
            }
        }
    };
    for (text, cat) in [
        (BUILTIN_ADS, ShieldCategory::Ads),
        (BUILTIN_TRACKERS, ShieldCategory::Trackers),
        (BUILTIN_TELEMETRY, ShieldCategory::Telemetry),
        (BUILTIN_MALWARE, ShieldCategory::Malware),
    ] {
        for d in parse_list(text, usize::MAX) {
            add(&d, cat);
        }
    }
    for (cat, list) in s.external.values() {
        for d in list.iter() {
            add(d, *cat);
        }
    }
    for d in &s.settings.custom_block {
        add(d, ShieldCategory::Custom);
    }
    let mut allow = HashMap::new();
    for d in &s.settings.allow {
        if let Some((key, subs_only)) = normalize_pattern(d) {
            allow.insert(key.into_bytes().into_boxed_slice(), subs_only);
        }
    }
    let enabled_mask = s.settings.categories.iter().fold(0u8, |m, c| m | bit(*c));
    block.shrink_to_fit();
    Index {
        enabled: s.settings.enabled,
        enabled_mask,
        block,
        allow,
    }
}

/// Normalise a list pattern: `example.com`, `*.example.com`, `.example.com`
/// (= subdomains), `||example.com^`. Returns (key, subdomains_only).
fn normalize_pattern(p: &str) -> Option<(String, bool)> {
    let mut p = p.trim().trim_end_matches('.');
    let mut subs_only = false;
    if let Some(rest) = p.strip_prefix("*.") {
        p = rest;
        subs_only = true;
    } else if let Some(rest) = p.strip_prefix('.') {
        p = rest;
        subs_only = true;
    }
    let d = p.to_ascii_lowercase();
    valid_domain(&d).then_some((d, subs_only))
}

fn valid_domain(d: &str) -> bool {
    if d.is_empty() || d.len() > MAX_NAME {
        return false;
    }
    d.split('.').all(|l| {
        !l.is_empty()
            && l.len() <= 63
            && l.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    })
}

/// Names that hosts files map but that must never be blocked.
const HOSTS_IGNORE: &[&str] = &[
    "localhost",
    "localhost.localdomain",
    "local",
    "broadcasthost",
    "ip6-localhost",
    "ip6-loopback",
    "ip6-localnet",
    "ip6-mcastprefix",
    "ip6-allnodes",
    "ip6-allrouters",
    "ip6-allhosts",
    "0.0.0.0",
];

/// Parse a blocklist in hosts format (`0.0.0.0 ads.example`), plain domain
/// list format, or simple Adblock domain rules (`||ads.example^`). Comments
/// (`#`, `!`), blank lines, IP-only lines and malformed names are skipped.
/// Wildcard entries keep their `*.` prefix.
pub fn parse_list(text: &str, max_entries: usize) -> Vec<Box<str>> {
    let mut out: Vec<Box<str>> = Vec::new();
    let mut seen = HashSet::new();
    for line in text.lines() {
        if out.len() >= max_entries {
            break;
        }
        let line = line.split('#').next().unwrap_or("").trim();
        if line.is_empty() || line.starts_with('!') || line.starts_with('[') {
            continue;
        }
        let mut push = |raw: &str| {
            let raw = raw.trim().trim_end_matches('.');
            if HOSTS_IGNORE.contains(&raw) || raw.parse::<std::net::IpAddr>().is_ok() {
                return;
            }
            if let Some((d, subs)) = normalize_pattern(raw) {
                let s = if subs { format!("*.{d}") } else { d };
                if seen.insert(s.clone()) {
                    out.push(s.into_boxed_str());
                }
            }
        };
        if let Some(rule) = line.strip_prefix("||") {
            // Adblock: only pure domain rules (`||domain^` optionally `$...`).
            let rule = rule.split('$').next().unwrap_or("");
            if let Some(d) = rule.strip_suffix('^') {
                if !d.contains('/') && !d.contains('*') {
                    push(d);
                }
            }
            continue;
        }
        if line.starts_with("@@") {
            continue;
        }
        let mut fields = line.split_whitespace();
        let Some(first) = fields.next() else {
            continue;
        };
        if first.parse::<std::net::IpAddr>().is_ok() {
            // hosts format: every following field is a hostname.
            for f in fields {
                push(f);
            }
        } else {
            push(first);
        }
    }
    out
}

/// A downloadable blocklist.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlocklistSource {
    /// HTTPS URL of a hosts-format or domain-list-format file.
    pub url: String,
    pub category: ShieldCategory,
}

/// Outcome of a [`BlocklistUpdater::update`] run.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UpdateReport {
    pub sources_ok: usize,
    pub sources_failed: usize,
    /// Entries installed from successful sources.
    pub entries: usize,
}

/// Default cap on one downloaded list (bytes).
pub const DEFAULT_MAX_LIST_BYTES: usize = 32 * 1024 * 1024;
/// Default cap on entries per list.
pub const DEFAULT_MAX_LIST_ENTRIES: usize = 1_500_000;

/// Downloads blocklists over HTTPS straight into RAM (never to disk).
#[derive(Debug, Clone)]
pub struct BlocklistUpdater {
    client: reqwest::Client,
    sources: Vec<BlocklistSource>,
    max_bytes: usize,
    max_entries: usize,
}

impl BlocklistUpdater {
    /// Updater trusting Mozilla's roots, resolving list hosts via [`Bootstrap`].
    pub fn new(sources: Vec<BlocklistSource>) -> Result<Self> {
        Self::with_tls(sources, &TlsTrust::webpki(), Bootstrap::new()?)
    }

    pub fn with_tls(
        sources: Vec<BlocklistSource>,
        trust: &TlsTrust,
        bootstrap: Bootstrap,
    ) -> Result<Self> {
        let tls = trust.client_config(&[b"h2", b"http/1.1"])?;
        let client = reqwest::Client::builder()
            .tls_backend_preconfigured(tls)
            .dns_resolver(bootstrap)
            .https_only(true)
            .no_proxy()
            .referer(false)
            .redirect(reqwest::redirect::Policy::limited(3))
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(60))
            .build()
            .map_err(|e| DnsError::Tls(e.without_url().to_string()))?;
        Ok(Self {
            client,
            sources,
            max_bytes: DEFAULT_MAX_LIST_BYTES,
            max_entries: DEFAULT_MAX_LIST_ENTRIES,
        })
    }

    /// Override the size caps.
    pub fn with_limits(mut self, max_bytes: usize, max_entries: usize) -> Self {
        self.max_bytes = max_bytes;
        self.max_entries = max_entries;
        self
    }

    pub fn sources(&self) -> &[BlocklistSource] {
        &self.sources
    }

    /// Download and parse one list.
    pub async fn fetch(&self, src: &BlocklistSource) -> Result<Vec<Box<str>>> {
        let mut resp = self
            .client
            .get(&src.url)
            .send()
            .await
            .map_err(|e| DnsError::Blocklist(e.without_url().to_string()))?;
        if !resp.status().is_success() {
            return Err(DnsError::Blocklist(format!(
                "http status {}",
                resp.status()
            )));
        }
        if resp
            .content_length()
            .is_some_and(|l| l > self.max_bytes as u64)
        {
            return Err(DnsError::Blocklist("list exceeds size cap".into()));
        }
        let mut body = Vec::new();
        while let Some(chunk) = resp
            .chunk()
            .await
            .map_err(|e| DnsError::Blocklist(e.without_url().to_string()))?
        {
            if body.len() + chunk.len() > self.max_bytes {
                return Err(DnsError::Blocklist("list exceeds size cap".into()));
            }
            body.extend_from_slice(&chunk);
        }
        let text = String::from_utf8_lossy(&body);
        let mut list = parse_list(&text, self.max_entries);
        // Remote lists may not block whole TLDs.
        list.retain(|d| d.trim_start_matches("*.").contains('.'));
        Ok(list)
    }

    /// Fetch every source and install successful ones into `shield`. Failed
    /// sources keep their previously installed contents.
    pub async fn update(&self, shield: &Shield) -> UpdateReport {
        let mut report = UpdateReport::default();
        for src in &self.sources {
            match self.fetch(src).await {
                Ok(list) => {
                    report.sources_ok += 1;
                    report.entries += list.len();
                    shield.set_external_list(&src.url, src.category, list);
                }
                Err(e) => {
                    report.sources_failed += 1;
                    tracing::debug!(error = %e, "blocklist source failed");
                }
            }
        }
        tracing::info!(
            ok = report.sources_ok,
            failed = report.sources_failed,
            entries = report.entries,
            "shield blocklists updated"
        );
        report
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn settings() -> ShieldSettings {
        ShieldSettings::default()
    }

    #[test]
    fn builtin_lists_are_substantial_and_clean() {
        for (text, min) in [
            (BUILTIN_ADS, 150),
            (BUILTIN_TRACKERS, 150),
            (BUILTIN_TELEMETRY, 100),
            (BUILTIN_MALWARE, 50),
        ] {
            let l = parse_list(text, usize::MAX);
            assert!(l.len() >= min, "list too small: {}", l.len());
        }
        let s = Shield::new(&settings());
        // Things that must never be blocked (updates, PKI, connectivity checks).
        for host in [
            "ocsp.apple.com",
            "ocsp.digicert.com",
            "crl3.digicert.com",
            "ocsp.pki.goog",
            "r3.o.lencr.org",
            "swscan.apple.com",
            "swdist.apple.com",
            "updates.cdn-apple.com",
            "mesu.apple.com",
            "windowsupdate.com",
            "download.windowsupdate.com",
            "update.microsoft.com",
            "dl.delivery.mp.microsoft.com",
            "ctldl.windowsupdate.com",
            "www.msftconnecttest.com",
            "captive.apple.com",
            "time.apple.com",
            "github.com",
            "example.com",
        ] {
            assert_eq!(s.check(host), None, "{host} must not be blocked");
        }
    }

    #[test]
    fn exact_and_parent_matching() {
        let s = Shield::new(&settings());
        assert_eq!(s.check("doubleclick.net"), Some(ShieldCategory::Ads));
        assert_eq!(s.check("ad.doubleclick.net"), Some(ShieldCategory::Ads));
        assert_eq!(
            s.check("Deep.Sub.AD.DoubleClick.NET."),
            Some(ShieldCategory::Ads)
        );
        assert_eq!(s.check("notdoubleclick.net"), None);
        assert_eq!(s.check("net"), None);
        assert_eq!(
            s.check("www.google-analytics.com"),
            Some(ShieldCategory::Trackers)
        );
        assert_eq!(
            s.check("malware.testcategory.com"),
            Some(ShieldCategory::Malware)
        );
    }

    #[test]
    fn wildcard_allow_custom_and_categories() {
        let mut st = settings();
        st.custom_block = vec!["*.corp-tracker.example".into(), "evil.example".into()];
        st.allow = vec!["good.doubleclick.net".into()];
        let s = Shield::new(&st);
        assert_eq!(s.check("corp-tracker.example"), None);
        assert_eq!(
            s.check("x.corp-tracker.example"),
            Some(ShieldCategory::Custom)
        );
        assert_eq!(s.check("a.evil.example"), Some(ShieldCategory::Custom));
        assert_eq!(s.check("good.doubleclick.net"), None);
        assert_eq!(s.check("x.good.doubleclick.net"), None);
        assert!(s.is_allowed("x.good.doubleclick.net"));
        assert_eq!(s.check("bad.doubleclick.net"), Some(ShieldCategory::Ads));
        assert_eq!(
            s.categories_of("doubleclick.net"),
            vec![ShieldCategory::Ads]
        );

        // Disable ads only.
        st.categories = vec![ShieldCategory::Trackers];
        s.reload(&st);
        assert_eq!(s.check("doubleclick.net"), None);
        assert_eq!(
            s.check("google-analytics.com"),
            Some(ShieldCategory::Trackers)
        );
        assert_eq!(s.check("evil.example"), None);
        st.enabled = false;
        s.reload(&st);
        assert_eq!(s.check("google-analytics.com"), None);
    }

    #[test]
    fn parses_hosts_domains_and_adblock() {
        let text = "\
# comment\n\
127.0.0.1 localhost\n\
::1 ip6-localhost\n\
0.0.0.0 ads.one.example ads.two.example # trailing\n\
0.0.0.0 0.0.0.0\n\
plain.example\n\
*.wild.example\n\
||adblock.example^\n\
||adblock-opt.example^$third-party\n\
||path.example/ads^\n\
@@||allowed.example^\n\
! adblock comment\n\
bad_domain$.example\n\
UPPER.Example.\n\
plain.example\n";
        let l = parse_list(text, usize::MAX);
        let l: Vec<&str> = l.iter().map(|s| &**s).collect();
        assert_eq!(
            l,
            vec![
                "ads.one.example",
                "ads.two.example",
                "plain.example",
                "*.wild.example",
                "adblock.example",
                "adblock-opt.example",
                "upper.example",
            ]
        );
        assert_eq!(parse_list(text, 2).len(), 2);
    }

    #[test]
    fn external_lists_install_and_replace() {
        let s = Shield::new(&settings());
        assert_eq!(s.check("x.remote-list.example"), None);
        s.set_external_list(
            "https://lists.example/a",
            ShieldCategory::Malware,
            vec!["remote-list.example".into()],
        );
        assert_eq!(
            s.check("x.remote-list.example"),
            Some(ShieldCategory::Malware)
        );
        s.set_external_list("https://lists.example/a", ShieldCategory::Malware, vec![]);
        assert_eq!(s.check("x.remote-list.example"), None);
    }

    #[test]
    fn lookups_are_fast() {
        let s = Shield::new(&settings());
        let names = [
            "www.example.com",
            "a.b.c.d.e.f.example.org",
            "ad.doubleclick.net",
            "cdn.jsdelivr.net",
            "very.long.subdomain.chain.for.testing.purposes.example.co.uk",
        ];
        let start = std::time::Instant::now();
        let mut hits = 0usize;
        for i in 0..100_000 {
            if s.check(names[i % names.len()]).is_some() {
                hits += 1;
            }
        }
        let el = start.elapsed();
        assert_eq!(hits, 20_000);
        // ~0.2-1 µs/lookup in debug builds; 2 s leaves a huge margin.
        assert!(el < std::time::Duration::from_secs(2), "slow: {el:?}");
    }
}
