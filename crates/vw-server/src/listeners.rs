//! Transport listeners multiplexed into one [`NodeCore`] (ARCHITECTURE.md §9).
//!
//! One UDP port carries both plain WireGuard and AmneziaWG: each datagram is
//! classified ([`classify`]) and the encoding is remembered in the
//! [`Remote`] so replies use the same one. MASQUE and TLS-WS listeners from
//! `vw-stealth` carry plain WireGuard datagrams.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::sync::watch;
use tokio::task::JoinSet;
use vw_core::config::AmneziaParams;
use vw_core::transport::TunDevice;
use vw_core::{Result, VwError};
use vw_stealth::{AmneziaCodec, PeerHandle, ServerTransport, UdpListener};
use vw_wg::noise::{
    COOKIE_REPLY_LEN, DATA_MIN_LEN, INITIATION_LEN, RESPONSE_LEN, TYPE_COOKIE_REPLY, TYPE_DATA,
    TYPE_INITIATION, TYPE_RESPONSE,
};

use crate::node::{Action, NodeCore};

/// Largest datagram / packet handled.
pub const MAX_PACKET: usize = 65_535;
/// Timer resolution of the node core.
pub const TICK_INTERVAL: Duration = Duration::from_millis(100);

/// Wire encoding of a datagram on the shared UDP port.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Encoding {
    Plain,
    Amnezia,
}

/// Where a WireGuard peer was last heard from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Remote {
    /// Index into [`Listeners`] (0 = shared UDP port when present).
    pub listener: usize,
    pub handle: PeerHandle,
    pub encoding: Encoding,
}

/// True for a well-formed standard WireGuard message (type field `N 0 0 0`
/// and the exact length of that message type).
pub fn is_plain_wireguard(b: &[u8]) -> bool {
    if b.len() < 4 || b[1..4] != [0, 0, 0] {
        return false;
    }
    match b[0] {
        TYPE_INITIATION => b.len() == INITIATION_LEN,
        TYPE_RESPONSE => b.len() == RESPONSE_LEN,
        TYPE_COOKIE_REPLY => b.len() == COOKIE_REPLY_LEN,
        TYPE_DATA => b.len() >= DATA_MIN_LEN && b.len() % 16 == 0,
        _ => false,
    }
}

/// Classify a datagram from the shared UDP port. AmneziaWG datagrams are
/// rewritten in place to standard WireGuard; returns the standard length and
/// encoding, or `None` for junk / foreign traffic.
pub fn classify(codec: &AmneziaCodec, buf: &mut [u8]) -> Option<(usize, Encoding)> {
    if let Some(n) = codec.decode_in_place(buf) {
        return Some((n, Encoding::Amnezia));
    }
    is_plain_wireguard(buf).then_some((buf.len(), Encoding::Plain))
}

/// All bound listeners.
pub struct Listeners {
    udp: Option<(UdpListener, AmneziaCodec)>,
    others: Vec<Arc<dyn ServerTransport>>,
}

impl Listeners {
    /// `udp`: the shared plain/AmneziaWG port; `others`: MASQUE, TLS-WS.
    pub fn new(
        udp: Option<(UdpListener, AmneziaParams)>,
        others: Vec<Arc<dyn ServerTransport>>,
    ) -> Result<Self> {
        let udp = match udp {
            Some((l, p)) => Some((l, AmneziaCodec::new(p)?)),
            None => None,
        };
        Ok(Self { udp, others })
    }

    fn offset(&self) -> usize {
        usize::from(self.udp.is_some())
    }

    /// Send one standard WireGuard datagram to a remote, re-encoding as needed.
    pub async fn send(&self, to: &Remote, datagram: &[u8]) -> Result<()> {
        if to.listener == 0 {
            if let Some((udp, codec)) = &self.udp {
                return match to.encoding {
                    Encoding::Plain => udp.send_to(datagram, &to.handle).await,
                    Encoding::Amnezia => udp.send_to(&codec.encode(datagram)?, &to.handle).await,
                };
            }
        }
        let t = self
            .others
            .get(to.listener - self.offset())
            .ok_or_else(|| VwError::Transport("unknown listener".into()))?;
        t.send_to(datagram, &to.handle).await
    }
}

/// Perform the actions produced by the core.
pub async fn dispatch(actions: Vec<Action<Remote>>, listeners: &Listeners, tun: &dyn TunDevice) {
    for a in actions {
        match a {
            Action::Send { to, datagram } => {
                if let Err(e) = listeners.send(&to, &datagram).await {
                    tracing::trace!("send failed: {e}");
                }
            }
            Action::Tun(pkt) => {
                if let Err(e) = tun.write_packet(&pkt).await {
                    tracing::trace!("tun write failed: {e}");
                }
            }
        }
    }
}

type Core = Arc<Mutex<NodeCore<Remote>>>;

fn with_core<T>(core: &Core, f: impl FnOnce(&mut NodeCore<Remote>) -> T) -> Option<T> {
    core.lock().ok().map(|mut c| f(&mut c))
}

/// Serve all listeners and the TUN until `shutdown` becomes true (or a
/// fatal I/O error occurs, which is returned).
pub async fn serve(
    core: Core,
    listeners: Arc<Listeners>,
    tun: Arc<dyn TunDevice>,
    mut shutdown: watch::Receiver<bool>,
) -> Result<()> {
    let mut set: JoinSet<Result<()>> = JoinSet::new();

    if listeners.udp.is_some() {
        let (core, ls, tun) = (core.clone(), listeners.clone(), tun.clone());
        set.spawn(async move {
            let mut buf = vec![0u8; MAX_PACKET];
            loop {
                let Some((udp, codec)) = &ls.udp else {
                    return Ok(());
                };
                let (n, handle) = udp.recv_from(&mut buf).await?;
                let Some((len, encoding)) = classify(codec, &mut buf[..n]) else {
                    continue;
                };
                let remote = Remote {
                    listener: 0,
                    handle,
                    encoding,
                };
                let src = Some(handle.remote_addr());
                let actions = with_core(&core, |c| {
                    c.on_datagram(remote, src, &buf[..len], Instant::now())
                })
                .unwrap_or_default();
                dispatch(actions, &ls, tun.as_ref()).await;
            }
        });
    }

    for (i, t) in listeners.others.iter().enumerate() {
        let index = i + listeners.offset();
        let (core, ls, tun, t) = (core.clone(), listeners.clone(), tun.clone(), t.clone());
        set.spawn(async move {
            let mut buf = vec![0u8; MAX_PACKET];
            loop {
                let (n, handle) = t.recv_from(&mut buf).await?;
                if !is_plain_wireguard(&buf[..n]) {
                    continue;
                }
                let remote = Remote {
                    listener: index,
                    handle,
                    encoding: Encoding::Plain,
                };
                let src = Some(handle.remote_addr());
                let actions = with_core(&core, |c| {
                    c.on_datagram(remote, src, &buf[..n], Instant::now())
                })
                .unwrap_or_default();
                dispatch(actions, &ls, tun.as_ref()).await;
            }
        });
    }

    {
        let (core, ls, tun) = (core.clone(), listeners.clone(), tun.clone());
        set.spawn(async move {
            let mut buf = vec![0u8; MAX_PACKET];
            loop {
                let n = tun.read_packet(&mut buf).await?;
                let actions = with_core(&core, |c| c.on_tun_packet(&buf[..n], Instant::now()))
                    .unwrap_or_default();
                dispatch(actions, &ls, tun.as_ref()).await;
            }
        });
    }

    {
        let (core, ls, tun) = (core.clone(), listeners.clone(), tun.clone());
        set.spawn(async move {
            let mut iv = tokio::time::interval(TICK_INTERVAL);
            iv.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                iv.tick().await;
                let actions = with_core(&core, |c| c.tick(Instant::now())).unwrap_or_default();
                dispatch(actions, &ls, tun.as_ref()).await;
            }
        });
    }

    let result = tokio::select! {
        _ = async {
            while !*shutdown.borrow() {
                if shutdown.changed().await.is_err() {
                    break;
                }
            }
        } => Ok(()),
        r = set.join_next() => match r {
            Some(Ok(Err(e))) => Err(e),
            Some(Err(e)) => Err(VwError::Transport(format!("listener task failed: {e}"))),
            _ => Ok(()),
        },
    };
    set.abort_all();
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_detection() {
        let mut init = vec![0u8; INITIATION_LEN];
        init[0] = 1;
        assert!(is_plain_wireguard(&init));
        assert!(!is_plain_wireguard(&init[..147]));
        let mut data = vec![0u8; 32];
        data[0] = 4;
        assert!(is_plain_wireguard(&data));
        data.push(0);
        assert!(!is_plain_wireguard(&data));
        let mut resv = vec![0u8; RESPONSE_LEN];
        resv[0] = 2;
        resv[2] = 9;
        assert!(!is_plain_wireguard(&resv));
        assert!(!is_plain_wireguard(&[5, 0, 0, 0]));
    }

    #[test]
    fn shared_port_classification() {
        let p = AmneziaParams::random();
        let codec = AmneziaCodec::new(p).unwrap();
        // Plain WireGuard initiation stays plain.
        let mut init = vec![0xAB; INITIATION_LEN];
        init[..4].copy_from_slice(&[1, 0, 0, 0]);
        let mut buf = init.clone();
        assert_eq!(
            classify(&codec, &mut buf),
            Some((INITIATION_LEN, Encoding::Plain))
        );
        assert_eq!(buf, init);
        // The same message AmneziaWG-encoded is detected and restored.
        let mut wire = codec.encode(&init).unwrap();
        assert_eq!(wire.len(), INITIATION_LEN + p.s1 as usize);
        let (n, enc) = classify(&codec, &mut wire).unwrap();
        assert_eq!(enc, Encoding::Amnezia);
        assert_eq!(&wire[..n], &init[..]);
        // Data packets in both encodings.
        let mut data = vec![0x11; 64];
        data[..4].copy_from_slice(&[4, 0, 0, 0]);
        let mut w = codec.encode(&data).unwrap();
        assert_ne!(&w[..4], &[4, 0, 0, 0]);
        assert_eq!(
            classify(&codec, &mut w).map(|x| x.1),
            Some(Encoding::Amnezia)
        );
        let mut d2 = data.clone();
        assert_eq!(
            classify(&codec, &mut d2).map(|x| x.1),
            Some(Encoding::Plain)
        );
        // AmneziaWG junk is dropped.
        for mut j in codec.junk_burst() {
            assert_eq!(classify(&codec, &mut j), None);
        }
    }
}
