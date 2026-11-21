//! Bounded, RAM-only LRU answer cache.
//!
//! Entries are bounded both by count and by total bytes; TTLs are capped at
//! `max_cache_ttl` and aged on every hit. Nothing is ever written to disk and
//! [`DnsCache::flush`] drops everything (panic button).

use std::num::NonZeroUsize;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use hickory_proto::op::Message;
use hickory_proto::rr::{DNSClass, RecordType};
use lru::LruCache;

use crate::message::{age_ttls, name_key};

/// Default maximum number of cached answers.
pub const DEFAULT_CACHE_ENTRIES: usize = 8192;
/// Default byte budget for cached wire data.
pub const DEFAULT_CACHE_BYTES: usize = 8 * 1024 * 1024;
/// Answers larger than this are not cached.
const MAX_ENTRY_BYTES: usize = 16 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CacheKey {
    name: Box<[u8]>,
    qtype: u16,
    qclass: u16,
    checking_disabled: bool,
}

impl CacheKey {
    /// Key for the (single) question of `query`.
    pub fn for_query(query: &Message) -> Option<Self> {
        let q = query.queries().first()?;
        Some(Self {
            name: name_key(q.name()).into_boxed_slice(),
            qtype: u16::from(q.query_type()),
            qclass: u16::from(q.query_class()),
            checking_disabled: query.checking_disabled(),
        })
    }

    pub fn qtype(&self) -> RecordType {
        RecordType::from(self.qtype)
    }

    pub fn qclass(&self) -> DNSClass {
        DNSClass::from(self.qclass)
    }
}

#[derive(Debug)]
struct Entry {
    wire: Vec<u8>,
    stored: Instant,
    ttl: u32,
}

#[derive(Debug)]
struct Inner {
    lru: LruCache<CacheKey, Entry>,
    bytes: usize,
}

/// A cached answer ready to be finalised for the client.
#[derive(Debug, Clone)]
pub struct CacheHit {
    pub message: Message,
}

#[derive(Debug)]
pub struct DnsCache {
    inner: Mutex<Inner>,
    max_ttl: u32,
    max_bytes: usize,
}

impl DnsCache {
    pub fn new(max_entries: usize, max_bytes: usize, max_ttl: u32) -> Self {
        let cap = NonZeroUsize::new(max_entries.max(1)).unwrap_or(NonZeroUsize::MIN);
        Self {
            inner: Mutex::new(Inner {
                lru: LruCache::new(cap),
                bytes: 0,
            }),
            max_ttl,
            max_bytes,
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Look up a fresh answer; expired entries are evicted on access.
    pub fn get(&self, key: &CacheKey) -> Option<CacheHit> {
        let mut g = self.lock();
        let (wire, elapsed) = {
            let e = g.lru.get(key)?;
            let elapsed = e.stored.elapsed();
            if elapsed >= Duration::from_secs(u64::from(e.ttl)) {
                (None, elapsed)
            } else {
                (Some(e.wire.clone()), elapsed)
            }
        };
        let Some(wire) = wire else {
            if let Some(e) = g.lru.pop(key) {
                g.bytes -= e.wire.len();
            }
            return None;
        };
        drop(g);
        let mut message = Message::from_vec(&wire).ok()?;
        age_ttls(&mut message, elapsed.as_secs() as u32);
        Some(CacheHit { message })
    }

    /// Insert an answer with the given TTL (capped at `max_cache_ttl`).
    pub fn insert(&self, key: CacheKey, wire: Vec<u8>, ttl: u32) {
        let ttl = ttl.min(self.max_ttl);
        if ttl == 0 || wire.len() > MAX_ENTRY_BYTES || self.max_bytes == 0 {
            return;
        }
        let mut g = self.lock();
        let len = wire.len();
        // `push` returns either the replaced entry or the evicted LRU entry.
        if let Some((_, old)) = g.lru.push(
            key,
            Entry {
                wire,
                stored: Instant::now(),
                ttl,
            },
        ) {
            g.bytes -= old.wire.len();
        }
        g.bytes += len;
        while g.bytes > self.max_bytes {
            match g.lru.pop_lru() {
                Some((_, e)) => g.bytes -= e.wire.len(),
                None => break,
            }
        }
    }

    pub fn len(&self) -> usize {
        self.lock().lru.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Bytes of wire data currently held.
    pub fn bytes(&self) -> usize {
        self.lock().bytes
    }

    /// Drop every entry (and the memory behind it).
    pub fn flush(&self) {
        let mut g = self.lock();
        g.lru.clear();
        g.bytes = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::message::{encode, response_for, testutil::query};
    use hickory_proto::op::ResponseCode;
    use hickory_proto::rr::rdata::A;
    use hickory_proto::rr::{Name, RData, Record};

    fn answer(name: &str, ttl: u32) -> (CacheKey, Vec<u8>) {
        let q = Message::from_vec(&query(name, RecordType::A, 1, false)).unwrap();
        let mut r = response_for(&q, ResponseCode::NoError);
        r.add_answer(Record::from_rdata(
            Name::from_ascii(name).unwrap(),
            ttl,
            RData::A(A::new(192, 0, 2, 1)),
        ));
        (CacheKey::for_query(&q).unwrap(), encode(&r).unwrap())
    }

    #[test]
    fn hit_miss_and_case_insensitive() {
        let c = DnsCache::new(16, 1 << 20, 300);
        let (k, w) = answer("Example.COM.", 120);
        c.insert(k, w, 120);
        let (k2, _) = answer("example.com.", 1);
        let hit = c.get(&k2).unwrap();
        assert!(hit.message.answers()[0].ttl() <= 120);
        let (k3, _) = answer("other.example.", 1);
        assert!(c.get(&k3).is_none());
        c.flush();
        assert!(c.is_empty());
        assert_eq!(c.bytes(), 0);
    }

    #[test]
    fn bounded_by_count_and_bytes() {
        let c = DnsCache::new(4, 1 << 20, 300);
        for i in 0..10 {
            let (k, w) = answer(&format!("n{i}.example."), 60);
            c.insert(k, w, 60);
        }
        assert_eq!(c.len(), 4);
        let (k, w) = answer("one.example.", 60);
        let small = DnsCache::new(100, w.len() * 2, 300);
        for i in 0..10 {
            let (k, w) = answer(&format!("m{i}.example."), 60);
            small.insert(k, w, 60);
        }
        assert!(small.bytes() <= w.len() * 2);
        assert!(small.len() <= 2);
        // TTL zero is never cached.
        small.insert(k.clone(), w, 0);
        assert!(small.get(&k).is_none());
    }

    #[test]
    fn ttl_capped_and_expires() {
        let c = DnsCache::new(4, 1 << 20, 0);
        let (k, w) = answer("cap.example.", 600);
        c.insert(k.clone(), w, 600);
        assert!(c.get(&k).is_none(), "max_cache_ttl = 0 disables caching");
    }
}
