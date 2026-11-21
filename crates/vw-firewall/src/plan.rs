//! Platform-neutral description of the lockdown the kernel must enforce.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::PathBuf;
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use vw_core::config::FirewallSettings;
use vw_core::ipc::FirewallMatrix;
use vw_core::packet::{PROTO_TCP, PROTO_UDP};
use vw_core::{Result, VwError};

/// Transport protocol of a pinned endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Proto {
    Udp,
    Tcp,
}

impl Proto {
    /// Keyword used by nftables and pf.
    pub fn as_str(self) -> &'static str {
        match self {
            Proto::Udp => "udp",
            Proto::Tcp => "tcp",
        }
    }

    /// IANA protocol number.
    pub fn number(self) -> u8 {
        match self {
            Proto::Udp => PROTO_UDP,
            Proto::Tcp => PROTO_TCP,
        }
    }
}

/// A remote endpoint the daemon's own (marked / root / app-id) sockets may reach
/// outside the tunnel: the Hop 1 entry node.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct PinnedEndpoint {
    pub addr: SocketAddr,
    pub proto: Proto,
}

impl PinnedEndpoint {
    pub fn udp(addr: SocketAddr) -> Self {
        Self {
            addr,
            proto: Proto::Udp,
        }
    }

    pub fn tcp(addr: SocketAddr) -> Self {
        Self {
            addr,
            proto: Proto::Tcp,
        }
    }
}

/// The tunnel interface once it exists.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TunnelIface {
    /// Kernel interface name (`vw0` on Linux, `utunN` on macOS, the Wintun alias on Windows).
    pub name: String,
    /// Windows: the `NET_LUID` value of the Wintun adapter. Elsewhere: the
    /// interface index (informational).
    pub luid: Option<u64>,
    pub v4: Option<(Ipv4Addr, u8)>,
    pub v6: Option<(Ipv6Addr, u8)>,
}

impl TunnelIface {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            luid: None,
            v4: None,
            v6: None,
        }
    }
}

/// An IP network in CIDR notation; host bits are always cleared.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct IpCidr {
    addr: IpAddr,
    prefix: u8,
}

impl IpCidr {
    pub fn new(addr: IpAddr, prefix: u8) -> Result<Self> {
        let max = if addr.is_ipv4() { 32 } else { 128 };
        if prefix > max {
            return Err(VwError::Config(format!(
                "prefix length {prefix} exceeds {max}"
            )));
        }
        let addr = match addr {
            IpAddr::V4(a) => {
                let mask = v4_mask(prefix);
                IpAddr::V4(Ipv4Addr::from(u32::from(a) & mask))
            }
            IpAddr::V6(a) => {
                let mask = if prefix == 0 {
                    0
                } else {
                    u128::MAX << (128 - u32::from(prefix))
                };
                IpAddr::V6(Ipv6Addr::from(u128::from(a) & mask))
            }
        };
        Ok(Self { addr, prefix })
    }

    /// Single-host network (`/32` or `/128`).
    pub fn host(addr: IpAddr) -> Self {
        let prefix = if addr.is_ipv4() { 32 } else { 128 };
        Self { addr, prefix }
    }

    pub fn addr(&self) -> IpAddr {
        self.addr
    }

    pub fn prefix(&self) -> u8 {
        self.prefix
    }

    pub fn is_ipv4(&self) -> bool {
        self.addr.is_ipv4()
    }

    /// IPv4 netmask in host byte order (0 for IPv6 networks).
    pub fn v4_mask(&self) -> u32 {
        if self.is_ipv4() {
            v4_mask(self.prefix)
        } else {
            0
        }
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.addr, ip) {
            (IpAddr::V4(n), IpAddr::V4(a)) => u32::from(a) & v4_mask(self.prefix) == u32::from(n),
            (IpAddr::V6(n), IpAddr::V6(a)) => {
                let mask = if self.prefix == 0 {
                    0
                } else {
                    u128::MAX << (128 - u32::from(self.prefix))
                };
                u128::from(a) & mask == u128::from(n)
            }
            _ => false,
        }
    }
}

fn v4_mask(prefix: u8) -> u32 {
    if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - u32::from(prefix))
    }
}

impl fmt::Display for IpCidr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.addr, self.prefix)
    }
}

impl FromStr for IpCidr {
    type Err = VwError;

    fn from_str(s: &str) -> Result<Self> {
        let (a, p) = match s.split_once('/') {
            Some((a, p)) => (a, Some(p)),
            None => (s, None),
        };
        let addr: IpAddr = a
            .parse()
            .map_err(|_| VwError::Config("invalid CIDR address".into()))?;
        match p {
            Some(p) => {
                let prefix: u8 = p
                    .parse()
                    .map_err(|_| VwError::Config("invalid CIDR prefix".into()))?;
                Self::new(addr, prefix)
            }
            None => Ok(Self::host(addr)),
        }
    }
}

/// The two halves of the default route for each family (`0/1 + 128/1`,
/// `::/1 + 8000::/1`), used for split default routes over the tunnel.
pub fn split_default_prefixes(include_v6: bool) -> Vec<IpCidr> {
    let mut v = vec![
        IpCidr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 1).expect("valid"),
        IpCidr::new(IpAddr::V4(Ipv4Addr::new(128, 0, 0, 0)), 1).expect("valid"),
    ];
    if include_v6 {
        v.push(IpCidr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 1).expect("valid"));
        v.push(
            IpCidr::new(IpAddr::V6(Ipv6Addr::new(0x8000, 0, 0, 0, 0, 0, 0, 0)), 1).expect("valid"),
        );
    }
    v
}

/// Everything a backend needs to render and apply the lockdown.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LockdownPlan {
    pub settings: FirewallSettings,
    /// Endpoints reachable outside the tunnel by the daemon only.
    pub pinned: Vec<PinnedEndpoint>,
    /// `None` while booting / before the TUN exists (boot lock).
    pub tunnel: Option<TunnelIface>,
    /// Absolute path of `voidwired` (Windows WFP app-id permits).
    pub daemon_exe: Option<PathBuf>,
    /// Ranges reachable outside the tunnel when `settings.allow_lan` is set.
    pub lan_ranges: Vec<IpCidr>,
}

impl LockdownPlan {
    /// Plan with no tunnel and no pinned endpoints: block everything.
    pub fn new(settings: FirewallSettings) -> Self {
        Self {
            settings,
            pinned: Vec::new(),
            tunnel: None,
            daemon_exe: None,
            lan_ranges: Self::default_lan_ranges(),
        }
    }

    /// RFC 1918, IPv4 link-local and IPv6 link-local networks.
    pub fn default_lan_ranges() -> Vec<IpCidr> {
        [
            "10.0.0.0/8",
            "172.16.0.0/12",
            "192.168.0.0/16",
            "169.254.0.0/16",
            "fe80::/10",
        ]
        .iter()
        .map(|s| s.parse().expect("static CIDR"))
        .collect()
    }

    pub fn with_pinned(mut self, ep: PinnedEndpoint) -> Self {
        self.pinned.push(ep);
        self
    }

    pub fn with_tunnel(mut self, tunnel: TunnelIface) -> Self {
        self.tunnel = Some(tunnel);
        self
    }

    pub fn tunnel_has_v6(&self) -> bool {
        self.tunnel.as_ref().is_some_and(|t| t.v6.is_some())
    }

    /// Pinned endpoints sorted and de-duplicated (deterministic rendering).
    pub fn sorted_pinned(&self) -> Vec<PinnedEndpoint> {
        let mut v = self.pinned.clone();
        v.sort();
        v.dedup();
        v
    }

    /// LAN ranges actually permitted: empty unless `allow_lan`; IPv6 ranges are
    /// dropped under `strict_ipv6`. Sorted and de-duplicated.
    pub fn effective_lan(&self) -> Vec<IpCidr> {
        if !self.settings.allow_lan {
            return Vec::new();
        }
        let mut v: Vec<IpCidr> = self
            .lan_ranges
            .iter()
            .copied()
            .filter(|c| c.is_ipv4() || !self.settings.strict_ipv6)
            .collect();
        v.sort();
        v.dedup();
        v
    }

    /// True when at least one pinned endpoint is IPv6 (neighbour discovery
    /// must then be permitted on the physical link).
    pub fn has_v6_pinned(&self) -> bool {
        self.pinned.iter().any(|p| p.addr.is_ipv6())
    }

    /// Reject anything that could inject syntax into rule files or that the
    /// backends cannot express. Executors call this before rendering.
    pub fn validate(&self) -> Result<()> {
        if let Some(t) = &self.tunnel {
            validate_ifname(&t.name)?;
            if let Some((_, p)) = t.v4 {
                if p > 32 {
                    return Err(VwError::Config("tunnel IPv4 prefix > 32".into()));
                }
            }
            if let Some((_, p)) = t.v6 {
                if p > 128 {
                    return Err(VwError::Config("tunnel IPv6 prefix > 128".into()));
                }
            }
        }
        for p in &self.pinned {
            let ip = p.addr.ip();
            if p.addr.port() == 0 {
                return Err(VwError::Config("pinned endpoint port 0".into()));
            }
            if ip.is_unspecified() || ip.is_multicast() || ip.is_loopback() {
                return Err(VwError::Config(
                    "pinned endpoint must be a unicast, non-loopback address".into(),
                ));
            }
            if let IpAddr::V4(v4) = ip {
                if v4.is_broadcast() {
                    return Err(VwError::Config("pinned endpoint is broadcast".into()));
                }
            }
        }
        if let Some(exe) = &self.daemon_exe {
            if !exe.is_absolute() {
                return Err(VwError::Config(
                    "daemon_exe must be an absolute path".into(),
                ));
            }
        }
        Ok(())
    }
}

/// Interface names end up inside nft / pf rule text: allow only a safe charset.
pub fn validate_ifname(name: &str) -> Result<()> {
    let ok_len = (1..=15).contains(&name.len());
    let ok_chars = name
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'));
    if ok_len && ok_chars {
        Ok(())
    } else {
        Err(VwError::Config(
            "tunnel interface name must be 1-15 chars of [A-Za-z0-9_.-]".into(),
        ))
    }
}

/// Kernel-verified lockdown status (mirrors `vw_core::ipc::FirewallMatrix`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FirewallStatus {
    pub ipv4_locked: bool,
    pub ipv6_locked: bool,
    /// Non-tunnel DNS (any port 53/853) cannot leave the host.
    pub dns_vault: bool,
    pub stun_filter: bool,
    pub tunnelvision_guard: bool,
    pub boot_lock: bool,
    pub backend: String,
}

impl FirewallStatus {
    pub fn disarmed(backend: &str) -> Self {
        Self {
            ipv4_locked: false,
            ipv6_locked: false,
            dns_vault: false,
            stun_filter: false,
            tunnelvision_guard: false,
            boot_lock: false,
            backend: backend.to_string(),
        }
    }

    /// Status derived from kernel verification (`armed`) and the applied plan.
    ///
    /// Every backend renders a default-deny ruleset in which non-tunnel IPv4,
    /// IPv6 and DNS are dropped, so these follow `armed` directly. The STUN
    /// filter is kernel-level on Linux and userspace (`stun::StunFilter`) on
    /// macOS / Windows; both are reported by the setting.
    pub fn from_plan(
        backend: &str,
        plan: Option<&LockdownPlan>,
        armed: bool,
        tunnelvision_guard: bool,
    ) -> Self {
        if !armed {
            return Self::disarmed(backend);
        }
        let settings = plan.map(|p| p.settings.clone()).unwrap_or_default();
        Self {
            ipv4_locked: true,
            ipv6_locked: true,
            dns_vault: true,
            stun_filter: settings.block_webrtc_stun,
            tunnelvision_guard,
            boot_lock: settings.boot_lock,
            backend: backend.to_string(),
        }
    }
}

impl From<FirewallStatus> for FirewallMatrix {
    fn from(s: FirewallStatus) -> Self {
        FirewallMatrix {
            ipv4_locked: s.ipv4_locked,
            ipv6_locked: s.ipv6_locked,
            dns_vault: s.dns_vault,
            stun_filter: s.stun_filter,
            tunnelvision_guard: s.tunnelvision_guard,
            boot_lock: s.boot_lock,
            backend: s.backend,
        }
    }
}

#[cfg(test)]
pub(crate) mod test_plans {
    use super::*;

    /// Representative fully-featured plan used by the rendering tests.
    pub fn full() -> LockdownPlan {
        let mut tun = TunnelIface::new("vw0");
        tun.luid = Some(0x0006_0000_0100_0000);
        tun.v4 = Some((Ipv4Addr::new(100, 96, 0, 2), 32));
        LockdownPlan::new(FirewallSettings::default())
            .with_pinned(PinnedEndpoint::udp("198.51.100.7:51820".parse().unwrap()))
            .with_pinned(PinnedEndpoint::tcp("[2001:db8::7]:443".parse().unwrap()))
            .with_tunnel(tun)
    }

    pub fn boot() -> LockdownPlan {
        LockdownPlan::new(FirewallSettings::default())
            .with_pinned(PinnedEndpoint::udp("198.51.100.7:51820".parse().unwrap()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cidr_normalises_and_contains() {
        let c: IpCidr = "192.168.7.9/16".parse().unwrap();
        assert_eq!(c.to_string(), "192.168.0.0/16");
        assert!(c.contains("192.168.200.1".parse().unwrap()));
        assert!(!c.contains("192.169.0.1".parse().unwrap()));
        let v6: IpCidr = "fe80::1234/10".parse().unwrap();
        assert_eq!(v6.to_string(), "fe80::/10");
        assert!("10.0.0.0/33".parse::<IpCidr>().is_err());
        assert_eq!("10.1.2.3".parse::<IpCidr>().unwrap().prefix(), 32);
        assert_eq!(c.v4_mask(), 0xffff_0000);
    }

    #[test]
    fn validate_rejects_injection() {
        let mut p = test_plans::full();
        assert!(p.validate().is_ok());
        p.tunnel.as_mut().unwrap().name = "vw0\" accept; flush ruleset".into();
        assert!(p.validate().is_err());
        let mut p = test_plans::full();
        p.pinned
            .push(PinnedEndpoint::udp("0.0.0.0:51820".parse().unwrap()));
        assert!(p.validate().is_err());
        let mut p = test_plans::full();
        p.daemon_exe = Some("voidwired.exe".into());
        assert!(p.validate().is_err());
    }

    #[test]
    fn effective_lan_respects_settings() {
        let mut p = test_plans::full();
        assert!(p.effective_lan().is_empty());
        p.settings.allow_lan = true;
        assert!(p.effective_lan().iter().all(|c| c.is_ipv4()));
        p.settings.strict_ipv6 = false;
        assert!(p.effective_lan().iter().any(|c| !c.is_ipv4()));
    }

    #[test]
    fn status_maps_to_matrix() {
        let p = test_plans::full();
        let s = FirewallStatus::from_plan("nftables", Some(&p), true, true);
        let m: FirewallMatrix = s.into();
        assert!(m.ipv4_locked && m.ipv6_locked && m.stun_filter && m.boot_lock);
        assert_eq!(m.backend, "nftables");
        let d: FirewallMatrix = FirewallStatus::from_plan("pf", Some(&p), false, true).into();
        assert!(!d.ipv4_locked && !d.tunnelvision_guard);
    }

    #[test]
    fn split_prefixes() {
        let v: Vec<String> = split_default_prefixes(true)
            .iter()
            .map(|c| c.to_string())
            .collect();
        assert_eq!(v, ["0.0.0.0/1", "128.0.0.0/1", "::/1", "8000::/1"]);
    }
}
