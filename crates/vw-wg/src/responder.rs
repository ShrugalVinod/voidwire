//! Multi-peer WireGuard responder for `voidwire-node`.
//!
//! Routes incoming datagrams to peers: initiations by the (decrypted)
//! initiator static key, everything else by receiver index. Each peer owns a
//! unique 24-bit index prefix, so `receiver_index >> 8` identifies the peer.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::Instant;

use rand::rngs::OsRng;
use rand::RngCore;
use vw_core::secret::Key32;

use crate::error::WgError;
use crate::noise::{
    self, consume_initiation, static_secret, CookieChecker, LoadMeter, MacCheck, MessageType,
};
use crate::peer::{Decapsulated, Peer};
use crate::timers::ZERO_KEYS_AFTER;

/// Which initiator static keys the responder will handshake with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Admission {
    /// Only peers added with [`Responder::add_peer`].
    KnownPeersOnly,
    /// Any client static key (VoidWire nodes gate forwarding separately via
    /// VWCP). At most `max_unknown` auto-created peers are kept; idle ones
    /// without a session are evicted first.
    AcceptUnknown { max_unknown: usize },
}

/// Public view of one peer in the table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerHandle {
    pub remote_static: [u8; 32],
    /// Added explicitly (true) or auto-created under `AcceptUnknown` (false).
    pub known: bool,
    pub established: bool,
    pub last_handshake: Option<Instant>,
}

/// Outcome of [`Responder::decapsulate`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Routed {
    /// The peer the datagram belonged to (`None` for cookie replies sent
    /// before the initiator was identified). Replies go back to the source.
    pub peer: Option<[u8; 32]>,
    pub result: Decapsulated,
}

struct Entry {
    peer: Peer,
    known: bool,
    created: Instant,
}

/// Server-side WireGuard endpoint holding many peers.
pub struct Responder {
    local_static: Key32,
    local_public: [u8; 32],
    admission: Admission,
    checker: CookieChecker,
    load: LoadMeter,
    peers: HashMap<[u8; 32], Entry>,
    by_prefix: HashMap<u32, [u8; 32]>,
}

impl std::fmt::Debug for Responder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Responder")
            .field("admission", &self.admission)
            .field("peers", &self.peers.len())
            .finish_non_exhaustive()
    }
}

impl Responder {
    pub fn new(local_static: Key32, admission: Admission) -> Self {
        let local_public = noise::public_key(&local_static);
        Self {
            local_static,
            local_public,
            admission,
            checker: CookieChecker::new(&local_public),
            load: LoadMeter::default(),
            peers: HashMap::new(),
            by_prefix: HashMap::new(),
        }
    }

    /// Our static public key.
    pub fn public_key(&self) -> &[u8; 32] {
        &self.local_public
    }

    pub fn admission(&self) -> Admission {
        self.admission
    }

    /// Force cookie mode on/off for all handshakes, or `None` for automatic
    /// (rate-based) detection.
    pub fn set_under_load(&mut self, forced: Option<bool>) {
        self.load.force(forced);
    }

    fn alloc_prefix(&self) -> u32 {
        loop {
            let p = OsRng.next_u32() & 0x00ff_ffff;
            if !self.by_prefix.contains_key(&p) {
                return p;
            }
        }
    }

    fn insert(&mut self, remote_static: [u8; 32], mut peer: Peer, known: bool, now: Instant) {
        let prefix = self.alloc_prefix();
        peer.set_index_prefix(prefix);
        self.by_prefix.insert(prefix, remote_static);
        self.peers.insert(
            remote_static,
            Entry {
                peer,
                known,
                created: now,
            },
        );
    }

    /// Add (or promote to known) a peer. Returns it for further configuration.
    pub fn add_peer(
        &mut self,
        remote_static: [u8; 32],
        psk: Option<Key32>,
        reserved: [u8; 3],
    ) -> &mut Peer {
        if let Some(e) = self.peers.get_mut(&remote_static) {
            e.known = true;
            if let Some(psk) = psk {
                e.peer.set_psk(psk);
            }
            e.peer.set_reserved(reserved);
        } else {
            let peer = Peer::new_responder(self.local_static.clone(), remote_static, psk, reserved);
            self.insert(remote_static, peer, true, Instant::now());
        }
        &mut self
            .peers
            .get_mut(&remote_static)
            .expect("peer inserted above")
            .peer
    }

    pub fn remove_peer(&mut self, remote_static: &[u8; 32]) -> Option<Peer> {
        let e = self.peers.remove(remote_static)?;
        self.by_prefix.remove(&e.peer.index_prefix());
        Some(e.peer)
    }

    pub fn peer(&self, remote_static: &[u8; 32]) -> Option<&Peer> {
        self.peers.get(remote_static).map(|e| &e.peer)
    }

    pub fn peer_mut(&mut self, remote_static: &[u8; 32]) -> Option<&mut Peer> {
        self.peers.get_mut(remote_static).map(|e| &mut e.peer)
    }

    /// Snapshot of the peer table.
    pub fn peers(&self) -> Vec<PeerHandle> {
        self.peers
            .iter()
            .map(|(k, e)| PeerHandle {
                remote_static: *k,
                known: e.known,
                established: e.peer.session_established(),
                last_handshake: e.peer.last_handshake(),
            })
            .collect()
    }

    fn make_room(&mut self) -> Result<(), WgError> {
        let Admission::AcceptUnknown { max_unknown } = self.admission else {
            return Err(WgError::UnknownPeer);
        };
        let unknown = self.peers.values().filter(|e| !e.known).count();
        if unknown < max_unknown {
            return Ok(());
        }
        let victim = self
            .peers
            .iter()
            .filter(|(_, e)| !e.known && !e.peer.session_established())
            .min_by_key(|(_, e)| e.peer.last_handshake().unwrap_or(e.created))
            .map(|(k, _)| *k)
            .ok_or(WgError::PeerTableFull)?;
        self.remove_peer(&victim);
        Ok(())
    }

    fn route_index(&self, datagram: &[u8], offset: usize) -> Option<[u8; 32]> {
        let idx = u32::from_le_bytes(datagram[offset..offset + 4].try_into().ok()?);
        let key = self.by_prefix.get(&(idx >> 8))?;
        self.peers
            .get(key)
            .filter(|e| e.peer.owns_index(idx))
            .map(|_| *key)
    }

    /// Process one datagram from `src` (needed for cookie mode).
    pub fn decapsulate(
        &mut self,
        src: Option<SocketAddr>,
        datagram: &[u8],
        now: Instant,
    ) -> Result<Routed, WgError> {
        let kind = noise::message_type(datagram).ok_or(WgError::Malformed)?;
        match kind {
            MessageType::Initiation | MessageType::Response => {
                let under_load = self.load.record(now);
                if let MacCheck::SendCookie(c) =
                    self.checker
                        .check(datagram, src.as_ref(), under_load, [0; 3], now)?
                {
                    let peer = match kind {
                        MessageType::Response => self.route_index(datagram, 8),
                        _ => None,
                    };
                    return Ok(Routed {
                        peer,
                        result: Decapsulated::Network(vec![c]),
                    });
                }
            }
            MessageType::CookieReply | MessageType::Data => {}
        }
        match kind {
            MessageType::Initiation => {
                let ri = consume_initiation(
                    &static_secret(&self.local_static),
                    &self.local_public,
                    datagram,
                )?;
                let key = ri.remote_static;
                if !self.peers.contains_key(&key) {
                    self.make_room()?;
                    let peer = Peer::new_responder(self.local_static.clone(), key, None, [0; 3]);
                    self.insert(key, peer, false, now);
                }
                let e = self.peers.get_mut(&key).ok_or(WgError::UnknownPeer)?;
                let result = e.peer.handle_initiation(ri, now)?;
                Ok(Routed {
                    peer: Some(key),
                    result,
                })
            }
            MessageType::Response => {
                self.dispatch(datagram, 8, now, |p, d, n| p.handle_response(d, n))
            }
            MessageType::CookieReply => {
                self.dispatch(datagram, 4, now, |p, d, n| p.handle_cookie_reply(d, n))
            }
            MessageType::Data => self.dispatch(datagram, 4, now, |p, d, n| p.handle_data(d, n)),
        }
    }

    fn dispatch(
        &mut self,
        datagram: &[u8],
        offset: usize,
        now: Instant,
        f: impl FnOnce(&mut Peer, &[u8], Instant) -> Result<Decapsulated, WgError>,
    ) -> Result<Routed, WgError> {
        let key = self
            .route_index(datagram, offset)
            .ok_or(WgError::UnknownIndex)?;
        let e = self.peers.get_mut(&key).ok_or(WgError::UnknownIndex)?;
        let result = f(&mut e.peer, datagram, now)?;
        Ok(Routed {
            peer: Some(key),
            result,
        })
    }

    /// Encrypt a plaintext packet for one peer (queued if it has no session).
    pub fn encapsulate(
        &mut self,
        remote_static: &[u8; 32],
        plaintext: &[u8],
        now: Instant,
    ) -> Result<Vec<Vec<u8>>, WgError> {
        let e = self
            .peers
            .get_mut(remote_static)
            .ok_or(WgError::UnknownPeer)?;
        Ok(e.peer.encapsulate(plaintext, now))
    }

    /// Run every peer's timers; evicts auto-created peers whose keys were
    /// erased. Returns datagrams per peer.
    pub fn tick(&mut self, now: Instant) -> Vec<([u8; 32], Vec<Vec<u8>>)> {
        let mut out = Vec::new();
        let mut evict = Vec::new();
        for (k, e) in self.peers.iter_mut() {
            let d = e.peer.tick(now);
            if !d.is_empty() {
                out.push((*k, d));
            }
            let idle_since = e.peer.last_handshake().unwrap_or(e.created);
            if !e.known
                && !e.peer.session_established()
                && now.saturating_duration_since(idle_since) >= ZERO_KEYS_AFTER
            {
                evict.push(*k);
            }
        }
        for k in evict {
            self.remove_peer(&k);
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::noise::generate_private_key;

    #[test]
    fn known_only_rejects_strangers() {
        let server = generate_private_key();
        let spub = noise::public_key(&server);
        let mut r = Responder::new(server, Admission::KnownPeersOnly);
        let mut c = Peer::new_initiator(generate_private_key(), spub, None, [0; 3]);
        let init = c.tick(Instant::now());
        assert_eq!(
            r.decapsulate(None, &init[0], Instant::now()),
            Err(WgError::UnknownPeer)
        );
        r.add_peer(*c.local_public(), None, [0; 3]);
        let init = c.initiate_handshake(Instant::now()).unwrap();
        let routed = r.decapsulate(None, &init, Instant::now()).unwrap();
        assert_eq!(routed.peer, Some(*c.local_public()));
        assert!(matches!(routed.result, Decapsulated::Network(ref v) if v.len() == 1));
    }

    #[test]
    fn accept_unknown_caps_table() {
        let server = generate_private_key();
        let spub = noise::public_key(&server);
        let mut r = Responder::new(server, Admission::AcceptUnknown { max_unknown: 2 });
        let now = Instant::now();
        for _ in 0..5 {
            let mut c = Peer::new_initiator(generate_private_key(), spub, None, [0; 3]);
            let init = c.tick(now);
            r.decapsulate(None, &init[0], now).unwrap();
        }
        assert_eq!(r.peers().len(), 2);
        assert!(r.peers().iter().all(|h| !h.known));
    }
}
