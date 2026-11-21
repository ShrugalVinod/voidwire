//! AmneziaWG 1.0 obfuscation (sans-IO codec plus client/server wrappers).
//!
//! Wire format (ARCHITECTURE.md §9):
//! * before each handshake initiation the client sends `Jc` junk datagrams of
//!   random length in `[Jmin, Jmax]`;
//! * handshake initiation = `S1` random bytes ‖ message with the 4-byte type
//!   field (u32 LE) replaced by `H1`; response = `S2` random bytes ‖ `H2` ‖ …;
//!   cookie reply = `H3` ‖ …; transport data = `H4` ‖ …
//! * the receiver classifies by length (`148+S1`, `92+S2`, `64`) and then by
//!   the `H` value, and restores the standard type field (reserved bytes 0).

use std::net::SocketAddr;

use async_trait::async_trait;
use rand::{Rng, RngCore};
use vw_core::config::{AmneziaParams, TransportKind};
use vw_core::transport::StealthTransport;
use vw_core::{Result, VwError};

use crate::{PeerHandle, ServerTransport};

const INIT_LEN: usize = 148;
const RESP_LEN: usize = 92;
const COOKIE_LEN: usize = 64;
const MIN_DATA_LEN: usize = 32;

const TYPE_INIT: u8 = 1;
const TYPE_RESP: u8 = 2;
const TYPE_COOKIE: u8 = 3;
const TYPE_DATA: u8 = 4;

/// True if `b` starts with a standard WireGuard message type field
/// (`01 00 00 00` … `04 00 00 00`).
fn looks_like_wireguard(b: &[u8]) -> bool {
    b.len() >= 4 && (1..=4).contains(&u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

/// Sans-IO AmneziaWG encoder/decoder.
#[derive(Debug, Clone)]
pub struct AmneziaCodec {
    p: AmneziaParams,
}

impl AmneziaCodec {
    /// Build a codec; the parameters must pass [`AmneziaParams::validate`].
    pub fn new(params: AmneziaParams) -> Result<Self> {
        params.validate()?;
        Ok(Self { p: params })
    }

    pub fn params(&self) -> &AmneziaParams {
        &self.p
    }

    /// Fill `prefix` with random bytes such that the datagram (prefix ‖ rest)
    /// never begins with a standard WireGuard type field.
    fn random_prefix(prefix: &mut [u8], next: &[u8]) {
        let mut rng = rand::rngs::OsRng;
        loop {
            rng.fill_bytes(prefix);
            let mut head = [0u8; 4];
            let k = prefix.len().min(4);
            head[..k].copy_from_slice(&prefix[..k]);
            head[k..].copy_from_slice(&next[..4 - k]);
            if !looks_like_wireguard(&head) {
                return;
            }
        }
    }

    /// Obfuscate one standard WireGuard message.
    ///
    /// Fails for datagrams that are not well-formed WireGuard messages (wrong
    /// type or length), which a correct engine never produces.
    pub fn encode(&self, wg: &[u8]) -> Result<Vec<u8>> {
        let ty = *wg
            .first()
            .ok_or(VwError::Packet("empty WireGuard datagram"))?;
        let (pad, h) = match (ty, wg.len()) {
            (TYPE_INIT, INIT_LEN) => (self.p.s1 as usize, self.p.h1),
            (TYPE_RESP, RESP_LEN) => (self.p.s2 as usize, self.p.h2),
            (TYPE_COOKIE, COOKIE_LEN) => (0, self.p.h3),
            (TYPE_DATA, n) if n >= MIN_DATA_LEN => (0, self.p.h4),
            _ => return Err(VwError::Packet("not a WireGuard message")),
        };
        let mut out = vec![0u8; pad + wg.len()];
        let hb = h.to_le_bytes();
        Self::random_prefix(&mut out[..pad], &hb);
        out[pad..pad + 4].copy_from_slice(&hb);
        out[pad + 4..].copy_from_slice(&wg[4..]);
        Ok(out)
    }

    /// Classify an obfuscated datagram: `(prefix length, standard type)`.
    fn classify(&self, wire: &[u8]) -> Option<(usize, u8)> {
        let h_at = |off: usize| -> Option<u32> {
            let b = wire.get(off..off + 4)?;
            Some(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
        };
        let s1 = self.p.s1 as usize;
        let s2 = self.p.s2 as usize;
        let n = wire.len();
        if n == INIT_LEN + s1 && h_at(s1) == Some(self.p.h1) {
            return Some((s1, TYPE_INIT));
        }
        if n == RESP_LEN + s2 && h_at(s2) == Some(self.p.h2) {
            return Some((s2, TYPE_RESP));
        }
        if n == COOKIE_LEN && h_at(0) == Some(self.p.h3) {
            return Some((0, TYPE_COOKIE));
        }
        if n >= MIN_DATA_LEN && h_at(0) == Some(self.p.h4) {
            return Some((0, TYPE_DATA));
        }
        None
    }

    /// Restore a standard WireGuard message, or `None` for junk / foreign data.
    pub fn decode(&self, wire: &[u8]) -> Option<Vec<u8>> {
        let (off, ty) = self.classify(wire)?;
        let mut out = wire[off..].to_vec();
        out[..4].copy_from_slice(&[ty, 0, 0, 0]);
        Some(out)
    }

    /// In-place variant of [`Self::decode`]: rewrites `buf` so that the
    /// standard message starts at index 0 and returns its length.
    pub fn decode_in_place(&self, buf: &mut [u8]) -> Option<usize> {
        let (off, ty) = self.classify(buf)?;
        let len = buf.len() - off;
        buf.copy_within(off.., 0);
        buf[..4].copy_from_slice(&[ty, 0, 0, 0]);
        Some(len)
    }

    /// The `Jc` junk datagrams sent before a handshake initiation.
    pub fn junk_burst(&self) -> Vec<Vec<u8>> {
        let mut rng = rand::rngs::OsRng;
        (0..self.p.jc)
            .map(|_| {
                let len = rng.gen_range(self.p.jmin..=self.p.jmax) as usize;
                let mut j = vec![0u8; len];
                loop {
                    rng.fill_bytes(&mut j);
                    if !looks_like_wireguard(&j) {
                        break j;
                    }
                }
            })
            .collect()
    }
}

/// Client transport applying [`AmneziaCodec`] on top of `T` (normally
/// [`crate::NativeUdpTransport`]).
pub struct AmneziaWgTransport<T: StealthTransport> {
    codec: AmneziaCodec,
    inner: T,
}

impl<T: StealthTransport> AmneziaWgTransport<T> {
    pub fn new(inner: T, params: AmneziaParams) -> Result<Self> {
        Ok(Self {
            codec: AmneziaCodec::new(params)?,
            inner,
        })
    }

    pub fn inner(&self) -> &T {
        &self.inner
    }
}

#[async_trait]
impl<T: StealthTransport> StealthTransport for AmneziaWgTransport<T> {
    async fn send(&self, datagram: &[u8]) -> Result<()> {
        self.inner.send(&self.codec.encode(datagram)?).await
    }

    async fn recv(&self, buf: &mut [u8]) -> Result<usize> {
        loop {
            let n = self.inner.recv(buf).await?;
            if let Some(len) = self.codec.decode_in_place(&mut buf[..n]) {
                return Ok(len);
            }
        }
    }

    fn kind(&self) -> TransportKind {
        TransportKind::AmneziaWg
    }

    fn overhead(&self) -> u16 {
        self.inner.overhead()
    }

    fn remote_addr(&self) -> SocketAddr {
        self.inner.remote_addr()
    }

    async fn before_handshake(&self) -> Result<()> {
        for junk in self.codec.junk_burst() {
            self.inner.send(&junk).await?;
        }
        self.inner.before_handshake().await
    }

    async fn rebind(&self) -> Result<()> {
        self.inner.rebind().await
    }

    async fn close(&self) -> Result<()> {
        self.inner.close().await
    }
}

/// Server transport applying [`AmneziaCodec`] on top of `S` (normally
/// [`crate::UdpListener`]). Junk and undecodable datagrams are dropped.
pub struct AmneziaServer<S: ServerTransport> {
    codec: AmneziaCodec,
    inner: S,
}

impl<S: ServerTransport> AmneziaServer<S> {
    pub fn new(inner: S, params: AmneziaParams) -> Result<Self> {
        Ok(Self {
            codec: AmneziaCodec::new(params)?,
            inner,
        })
    }

    pub fn inner(&self) -> &S {
        &self.inner
    }
}

#[async_trait]
impl<S: ServerTransport> ServerTransport for AmneziaServer<S> {
    async fn recv_from(&self, buf: &mut [u8]) -> Result<(usize, PeerHandle)> {
        loop {
            let (n, peer) = self.inner.recv_from(buf).await?;
            if let Some(len) = self.codec.decode_in_place(&mut buf[..n]) {
                return Ok((len, peer));
            }
        }
    }

    async fn send_to(&self, datagram: &[u8], peer: &PeerHandle) -> Result<()> {
        self.inner
            .send_to(&self.codec.encode(datagram)?, peer)
            .await
    }

    fn kind(&self) -> TransportKind {
        TransportKind::AmneziaWg
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{NativeUdpTransport, SocketOptions, UdpListener};
    use std::time::Duration;

    fn wg_msg(ty: u8, len: usize) -> Vec<u8> {
        let mut m = vec![0u8; len];
        rand::rngs::OsRng.fill_bytes(&mut m);
        m[..4].copy_from_slice(&[ty, 0, 0, 0]);
        m
    }

    fn samples() -> Vec<Vec<u8>> {
        vec![
            wg_msg(1, 148),
            wg_msg(2, 92),
            wg_msg(3, 64),
            wg_msg(4, 32),
            wg_msg(4, 148),
            wg_msg(4, 1452),
        ]
    }

    #[test]
    fn never_looks_like_wireguard_and_round_trips() {
        for _ in 0..500 {
            let p = AmneziaParams::random();
            let c = AmneziaCodec::new(p).unwrap();
            for m in samples() {
                let wire = c.encode(&m).unwrap();
                assert!(!looks_like_wireguard(&wire), "{:02x?}", &wire[..4]);
                assert_eq!(c.decode(&wire).as_deref(), Some(&m[..]));
                let mut b = wire.clone();
                let n = c.decode_in_place(&mut b).unwrap();
                assert_eq!(&b[..n], &m[..]);
            }
            assert_eq!(
                c.encode(&wg_msg(1, 148)).unwrap().len(),
                148 + p.s1 as usize
            );
            assert_eq!(c.encode(&wg_msg(2, 92)).unwrap().len(), 92 + p.s2 as usize);
        }
    }

    #[test]
    fn tiny_padding_still_hides_type() {
        // With S1 < 4 the first bytes mix padding and H; the prefix is redrawn.
        let mut p = AmneziaParams::random();
        p.s1 = 1;
        // H1 = bytes 00 00 00 07: a 1-byte prefix in 1..=4 would read as a
        // standard type field, so ~1.5% of draws must be rejected.
        p.h1 = 0x0700_0000;
        for h in [&mut p.h2, &mut p.h3, &mut p.h4] {
            if *h == 0x0700_0000 {
                *h += 1;
            }
        }
        let c = AmneziaCodec::new(p).unwrap();
        for _ in 0..2000 {
            let w = c.encode(&wg_msg(1, 148)).unwrap();
            assert!(!looks_like_wireguard(&w));
        }
    }

    #[test]
    fn rejects_foreign_and_invalid() {
        let c = AmneziaCodec::new(AmneziaParams::random()).unwrap();
        for m in samples() {
            assert!(c.decode(&m).is_none(), "standard WG must not decode");
        }
        assert!(c.encode(&wg_msg(1, 100)).is_err());
        assert!(c.encode(&wg_msg(9, 64)).is_err());
        assert!(c.encode(&wg_msg(4, 16)).is_err());
        assert!(c.encode(&[]).is_err());
    }

    #[test]
    fn junk_lengths_in_range() {
        for _ in 0..200 {
            let p = AmneziaParams::random();
            let c = AmneziaCodec::new(p).unwrap();
            let burst = c.junk_burst();
            assert_eq!(burst.len(), p.jc as usize);
            for j in burst {
                assert!((p.jmin as usize..=p.jmax as usize).contains(&j.len()));
                assert!(!looks_like_wireguard(&j));
            }
        }
    }

    #[test]
    fn invalid_params_rejected() {
        let mut p = AmneziaParams::random();
        p.h2 = p.h1;
        assert!(AmneziaCodec::new(p).is_err());
    }

    #[tokio::test]
    async fn udp_end_to_end_drops_junk() {
        let p = AmneziaParams::random();
        let server = AmneziaServer::new(
            UdpListener::bind("127.0.0.1:0".parse().unwrap())
                .await
                .unwrap(),
            p,
        )
        .unwrap();
        let addr = server.inner().local_addr().unwrap();
        let udp = NativeUdpTransport::connect(addr, SocketOptions::default())
            .await
            .unwrap();
        let client = AmneziaWgTransport::new(udp, p).unwrap();
        assert_eq!(client.kind(), TransportKind::AmneziaWg);

        client.before_handshake().await.unwrap();
        let init = wg_msg(1, 148);
        client.send(&init).await.unwrap();
        let mut buf = [0u8; 2048];
        let (n, peer) = tokio::time::timeout(Duration::from_secs(5), server.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&buf[..n], &init[..], "junk must be skipped");

        let resp = wg_msg(2, 92);
        server.send_to(&resp, &peer).await.unwrap();
        let n = client.recv(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], &resp[..]);
    }
}
