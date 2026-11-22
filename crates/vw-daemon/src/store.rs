//! Persistent client store (`paths::store_file()`, 0600 / SYSTEM+Administrators).
//!
//! The file is a `vw_core::config::ClientStore` with one extra top-level field,
//! `optimizer_cache`, holding optimizer decisions keyed by the salted network
//! fingerprint (ARCHITECTURE.md §10). Readers that only know `ClientStore`
//! ignore the extra field.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use vw_core::config::{Bytes32, ClientStore, NodeDescriptor, NodeKind, TransportKind};
use vw_core::ipc::NodeSummary;
use vw_core::probe::OptimizerDecision;
use vw_core::secret::{Key32, SecretVec};
use vw_core::{Result, VwError};

use crate::util::{write_protected, Access};

/// Decisions kept per network.
pub const MAX_CACHED_DECISIONS: usize = 32;

/// One cached optimizer decision.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CachedDecision {
    /// Hex `BLAKE3-keyed(network_salt, gateway MAC/IP || SSID)`.
    pub fingerprint: String,
    pub unix_time: u64,
    pub decision: OptimizerDecision,
}

/// On-disk layout.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct StoreFile {
    #[serde(flatten)]
    pub client: ClientStore,
    #[serde(default)]
    pub optimizer_cache: Vec<CachedDecision>,
}

/// Loaded store bound to its path.
#[derive(Debug)]
pub struct Store {
    path: PathBuf,
    pub data: StoreFile,
}

impl Store {
    /// Load (or start empty when missing). Fills in the WireGuard key and
    /// network salt on first use.
    pub fn load(path: &Path) -> Result<Self> {
        let mut data: StoreFile = match std::fs::read(path) {
            Ok(b) => serde_json::from_slice(&b)?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => StoreFile::default(),
            Err(e) => return Err(e.into()),
        };
        let mut dirty = false;
        if data.client.wg_private.is_none() {
            data.client.wg_private = Some(vw_wg::generate_private_key());
            dirty = true;
        }
        if data.client.network_salt.is_none() {
            data.client.network_salt = Some(Key32::random());
            dirty = true;
        }
        let s = Self {
            path: path.to_path_buf(),
            data,
        };
        if dirty && path.parent().is_some_and(Path::exists) {
            s.save()?;
        }
        Ok(s)
    }

    /// In-memory store (tests).
    pub fn in_memory(path: &Path) -> Self {
        let mut data = StoreFile::default();
        data.client.wg_private = Some(vw_wg::generate_private_key());
        data.client.network_salt = Some(Key32::random());
        Self {
            path: path.to_path_buf(),
            data,
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn save(&self) -> Result<()> {
        let json = zeroize::Zeroizing::new(serde_json::to_vec_pretty(&self.data)?);
        write_protected(&self.path, &json, Access::Private)
    }

    pub fn wg_private(&self) -> Key32 {
        self.data
            .client
            .wg_private
            .clone()
            .unwrap_or_else(Key32::zero)
    }

    pub fn salt(&self) -> [u8; 32] {
        self.data
            .client
            .network_salt
            .as_ref()
            .map(|k| *k.expose())
            .unwrap_or([0; 32])
    }

    /// Add or replace a node (by name).
    pub fn upsert_node(&mut self, n: NodeDescriptor) -> Result<()> {
        n.validate()?;
        if n.kind == NodeKind::Warp {
            return Err(VwError::Config(
                "WARP is registered with RegisterWarp, not imported".into(),
            ));
        }
        self.data.client.nodes.retain(|x| x.name != n.name);
        self.data.client.nodes.push(n);
        Ok(())
    }

    pub fn remove_node(&mut self, name: &str) -> Result<()> {
        let before = self.data.client.nodes.len();
        let removed: Vec<NodeDescriptor> = self
            .data
            .client
            .nodes
            .iter()
            .filter(|n| n.name == name)
            .cloned()
            .collect();
        self.data.client.nodes.retain(|n| n.name != name);
        if self.data.client.nodes.len() == before {
            return Err(VwError::Config(format!("no node named {name:?}")));
        }
        for n in removed {
            if let Some(id) = n.identity_key {
                self.data.client.f2f_tokens.retain(|(k, _)| *k != id);
            }
        }
        Ok(())
    }

    /// All nodes, WARP first when registered.
    pub fn all_nodes(&self) -> Vec<NodeDescriptor> {
        let mut v = Vec::new();
        if let Some(w) = &self.data.client.warp {
            v.push(w.to_node());
        }
        v.extend(self.data.client.nodes.iter().cloned());
        v
    }

    pub fn summaries(&self) -> Vec<NodeSummary> {
        self.all_nodes()
            .into_iter()
            .map(|n| NodeSummary {
                transports: {
                    let mut t: Vec<TransportKind> =
                        n.endpoints.iter().map(|e| e.transport).collect();
                    t.sort();
                    t.dedup();
                    t
                },
                post_quantum: n.supports_pq(),
                name: n.name,
                kind: n.kind,
                role: n.role,
                country: n.country,
            })
            .collect()
    }

    /// Whether the node is a friend's exit (we hold session tokens for it).
    pub fn is_f2f(&self, identity: &Option<Bytes32>) -> bool {
        identity.is_some_and(|id| {
            self.data
                .client
                .f2f_tokens
                .iter()
                .any(|(k, t)| *k == id && !t.is_empty())
        })
    }

    pub fn add_tokens(&mut self, identity: Bytes32, tokens: Vec<SecretVec>) {
        match self
            .data
            .client
            .f2f_tokens
            .iter_mut()
            .find(|(k, _)| *k == identity)
        {
            Some((_, v)) => v.extend(tokens),
            None => self.data.client.f2f_tokens.push((identity, tokens)),
        }
    }

    /// Remove and return one unspent session token for `identity`.
    pub fn take_token(&mut self, identity: &Bytes32) -> Option<SecretVec> {
        let (_, v) = self
            .data
            .client
            .f2f_tokens
            .iter_mut()
            .find(|(k, _)| k == identity)?;
        v.pop()
    }

    pub fn token_count(&self, identity: &Bytes32) -> usize {
        self.data
            .client
            .f2f_tokens
            .iter()
            .find(|(k, _)| k == identity)
            .map(|(_, v)| v.len())
            .unwrap_or(0)
    }

    pub fn cached_decision(&self, fp: &str, max_age_secs: u64) -> Option<OptimizerDecision> {
        let now = crate::util::unix_now();
        self.data
            .optimizer_cache
            .iter()
            .find(|c| c.fingerprint == fp && now.saturating_sub(c.unix_time) <= max_age_secs)
            .map(|c| c.decision.clone())
    }

    /// Drop the cached decision for a network (after it failed in practice).
    pub fn forget_decision(&mut self, fp: &str) {
        self.data.optimizer_cache.retain(|c| c.fingerprint != fp);
    }

    pub fn cache_decision(&mut self, fp: String, decision: OptimizerDecision) {
        self.data.optimizer_cache.retain(|c| c.fingerprint != fp);
        self.data.optimizer_cache.insert(
            0,
            CachedDecision {
                fingerprint: fp,
                unix_time: crate::util::unix_now(),
                decision,
            },
        );
        self.data.optimizer_cache.truncate(MAX_CACHED_DECISIONS);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vw_core::config::*;

    fn node(name: &str) -> NodeDescriptor {
        NodeDescriptor {
            version: 1,
            name: name.into(),
            kind: NodeKind::Voidwire,
            role: NodeRole::Both,
            wg_public_key: Bytes32([1; 32]),
            identity_key: Some(Bytes32([2; 32])),
            endpoints: vec![Endpoint {
                transport: TransportKind::NativeUdp,
                host: "192.0.2.1".into(),
                port: 51820,
                sni: None,
                path: None,
                cert_sha256: None,
            }],
            amnezia: None,
            country: Some("CH".into()),
            ipv6_exit: false,
            static_v4: None,
            static_v6: None,
            reserved: None,
            static_psk: None,
            token_keys: Vec::new(),
            client_private: None,
        }
    }

    #[test]
    fn roundtrip_with_cache_and_tokens() {
        let dir = std::env::temp_dir().join(format!(
            "vw-store-{}",
            hex::encode(rand::random::<[u8; 6]>())
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("store.json");
        let mut s = Store::load(&path).unwrap();
        assert!(path.exists(), "first load persists generated keys");
        s.upsert_node(node("a")).unwrap();
        s.upsert_node(node("a")).unwrap();
        s.add_tokens(Bytes32([2; 32]), vec![SecretVec::new(vec![1, 2, 3])]);
        s.cache_decision(
            "ff".into(),
            OptimizerDecision {
                hops: vec!["a".into()],
                transport: TransportKind::NativeUdp,
                mtu: 1420,
                mss_v4: 1380,
                daita: false,
                verdict: Default::default(),
                candidates: vec![],
                reason: "t".into(),
            },
        );
        s.save().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let m = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(m & 0o777, 0o600);
        }
        let mut b = Store::load(&path).unwrap();
        assert_eq!(b.data.client.nodes.len(), 1);
        assert_eq!(b.wg_private(), s.wg_private());
        assert_eq!(b.salt(), s.salt());
        assert!(b.is_f2f(&Some(Bytes32([2; 32]))));
        assert!(b.cached_decision("ff", 60).is_some());
        assert!(b.cached_decision("ee", 60).is_none());
        assert_eq!(
            b.take_token(&Bytes32([2; 32])).unwrap().expose(),
            &[1, 2, 3]
        );
        assert_eq!(b.summaries()[0].name, "a");
        b.remove_node("a").unwrap();
        assert!(b.remove_node("a").is_err());
        // Plain ClientStore readers still parse the file.
        let raw = std::fs::read(&path).unwrap();
        let _: ClientStore = serde_json::from_slice(&raw).unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
