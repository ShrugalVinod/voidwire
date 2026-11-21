//! TUN devices: the in-memory [`VirtualTunChannel`] and the real OS device
//! [`OsTun`] (macOS utun, Windows Wintun, Linux `/dev/net/tun`).

use std::net::{Ipv4Addr, Ipv6Addr};

use async_trait::async_trait;
use tokio::sync::{mpsc, Mutex};
use vw_core::consts::TUN_NAME;
use vw_core::transport::TunDevice;
use vw_core::{Result, VwError};

/// Queue depth of each direction of a [`VirtualTunChannel`].
pub const VIRTUAL_QUEUE_DEPTH: usize = 1024;

/// One end of an in-memory packet pipe. What one end writes, the other reads.
pub struct VirtualTunChannel {
    tx: mpsc::Sender<Vec<u8>>,
    rx: Mutex<mpsc::Receiver<Vec<u8>>>,
    mtu: u16,
    label: String,
}

impl std::fmt::Debug for VirtualTunChannel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VirtualTunChannel")
            .field("label", &self.label)
            .field("mtu", &self.mtu)
            .finish()
    }
}

impl VirtualTunChannel {
    /// Two connected ends, each rejecting packets larger than `mtu`.
    pub fn pair(mtu: u16) -> (Self, Self) {
        let (atx, brx) = mpsc::channel(VIRTUAL_QUEUE_DEPTH);
        let (btx, arx) = mpsc::channel(VIRTUAL_QUEUE_DEPTH);
        (
            Self {
                tx: atx,
                rx: Mutex::new(arx),
                mtu,
                label: "virtual-a".into(),
            },
            Self {
                tx: btx,
                rx: Mutex::new(brx),
                mtu,
                label: "virtual-b".into(),
            },
        )
    }

    /// Rename this end (reported by [`TunDevice::name`]).
    pub fn with_label(mut self, label: impl Into<String>) -> Self {
        self.label = label.into();
        self
    }
}

fn closed() -> VwError {
    VwError::Io(std::io::Error::new(
        std::io::ErrorKind::BrokenPipe,
        "virtual tun channel closed",
    ))
}

#[async_trait]
impl TunDevice for VirtualTunChannel {
    async fn read_packet(&self, buf: &mut [u8]) -> Result<usize> {
        let pkt = self.rx.lock().await.recv().await.ok_or_else(closed)?;
        let dst = buf
            .get_mut(..pkt.len())
            .ok_or(VwError::Packet("read buffer smaller than packet"))?;
        dst.copy_from_slice(&pkt);
        Ok(pkt.len())
    }

    async fn write_packet(&self, packet: &[u8]) -> Result<()> {
        if packet.len() > self.mtu as usize {
            return Err(VwError::Packet("packet exceeds tun mtu"));
        }
        self.tx.send(packet.to_vec()).await.map_err(|_| closed())
    }

    fn mtu(&self) -> u16 {
        self.mtu
    }

    fn name(&self) -> String {
        self.label.clone()
    }
}

/// Addressing for an OS TUN device.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OsTunConfig {
    pub mtu: u16,
    pub ipv4: Option<(Ipv4Addr, u8)>,
    pub ipv6: Option<(Ipv6Addr, u8)>,
}

/// A real layer-3 TUN interface (requires root / Administrator).
///
/// * macOS: a kernel-assigned `utunN`; the logical name stays `vw0`.
/// * Windows: a Wintun adapter named `vw0`; `wintun.dll` is loaded at runtime
///   from the directory of the running executable.
/// * Linux: `/dev/net/tun` interface named `vw0`.
pub struct OsTun {
    dev: tun_rs::AsyncDevice,
    mtu: u16,
    name: String,
}

impl std::fmt::Debug for OsTun {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OsTun")
            .field("name", &self.name)
            .field("mtu", &self.mtu)
            .finish()
    }
}

fn map_io(e: std::io::Error) -> VwError {
    if e.kind() == std::io::ErrorKind::PermissionDenied {
        VwError::Permission(format!("creating the tunnel device: {e}"))
    } else {
        VwError::Io(e)
    }
}

#[cfg(windows)]
fn wintun_path() -> Result<String> {
    let exe = std::env::current_exe()?;
    let dir = exe
        .parent()
        .ok_or_else(|| VwError::Config("executable has no parent directory".into()))?;
    let dll = dir.join("wintun.dll");
    if !dll.is_file() {
        return Err(VwError::Config(
            "wintun.dll not found next to the executable".into(),
        ));
    }
    Ok(dll.to_string_lossy().into_owned())
}

impl OsTun {
    /// Create, address and bring up the interface.
    pub fn create(cfg: &OsTunConfig) -> Result<Self> {
        let mut b = tun_rs::DeviceBuilder::new().mtu(cfg.mtu);
        #[cfg(any(target_os = "linux", windows))]
        {
            b = b.name(TUN_NAME);
        }
        #[cfg(windows)]
        {
            b = b.description("VoidWire").wintun_file(wintun_path()?);
        }
        if let Some((addr, prefix)) = cfg.ipv4 {
            b = b.ipv4(addr, prefix, None);
        }
        if let Some((addr, prefix)) = cfg.ipv6 {
            b = b.ipv6(addr, prefix);
        }
        let dev = b.build_async().map_err(map_io)?;
        let name = dev.name().unwrap_or_else(|_| TUN_NAME.to_string());
        let mtu = dev.mtu().unwrap_or(cfg.mtu);
        tracing::debug!(name = %name, mtu, "tunnel device created");
        Ok(Self { dev, mtu, name })
    }

    /// VoidWire's logical interface name (`vw0`) regardless of the OS name.
    pub fn logical_name(&self) -> &'static str {
        TUN_NAME
    }
}

#[async_trait]
impl TunDevice for OsTun {
    async fn read_packet(&self, buf: &mut [u8]) -> Result<usize> {
        self.dev.recv(buf).await.map_err(VwError::Io)
    }

    async fn write_packet(&self, packet: &[u8]) -> Result<()> {
        let n = self.dev.send(packet).await.map_err(VwError::Io)?;
        if n != packet.len() {
            return Err(VwError::Packet("short tun write"));
        }
        Ok(())
    }

    fn mtu(&self) -> u16 {
        self.mtu
    }

    fn name(&self) -> String {
        self.name.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn virtual_pair_roundtrip() {
        let (a, b) = VirtualTunChannel::pair(1280);
        a.write_packet(b"ping").await.unwrap();
        b.write_packet(b"pong").await.unwrap();
        let mut buf = [0u8; 1500];
        let n = b.read_packet(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"ping");
        let n = a.read_packet(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"pong");
        assert_eq!(a.mtu(), 1280);
        assert!(a.write_packet(&[0u8; 1281]).await.is_err());
        b.write_packet(&[1u8; 100]).await.unwrap();
        let mut small = [0u8; 10];
        assert!(a.read_packet(&mut small).await.is_err());
        assert_eq!(a.with_label("vw-test").name(), "vw-test");
    }

    #[tokio::test]
    async fn virtual_closed_end_errors() {
        let (a, b) = VirtualTunChannel::pair(1280);
        drop(b);
        assert!(a.write_packet(b"x").await.is_err());
        let mut buf = [0u8; 16];
        assert!(a.read_packet(&mut buf).await.is_err());
    }
}
