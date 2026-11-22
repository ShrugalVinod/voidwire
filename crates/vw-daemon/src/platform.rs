//! Every operating-system side effect of the daemon behind [`Platform`].
//!
//! [`OsPlatform`] is the real implementation (macOS pf/utun/networksetup,
//! Windows WFP/Wintun/IP Helper/netsh, Linux nftables/tun/ip). Tests run the
//! whole controller against in-memory platforms and a test firewall backend,
//! so development never touches this machine's firewall, routes or DNS.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::num::NonZeroU32;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use vw_core::config::{Endpoint, WarpAccount};
use vw_core::consts::{DNS_PORT, DNS_VAULT_V4, DNS_VAULT_V6, FW_MARK};
use vw_core::transport::{StealthTransport, TunDevice};
use vw_core::{Result, VwError};
use vw_dns::{DnsServer, DnsVault};
use vw_firewall::{FirewallBackend, TunnelIface};
use vw_leakaudit::canary::{EgressOutcome, EgressProbe, EgressProto};
use vw_stealth::{ConnectOptions, SocketOptions};
use vw_wg::OsTunConfig;

/// Physical network as seen right now (for fingerprints and link changes).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NetworkIdentity {
    pub gateway: Option<IpAddr>,
    pub gateway_mac: Option<String>,
    pub ssid: Option<String>,
    pub interface: Option<String>,
    pub interface_index: Option<u32>,
}

impl NetworkIdentity {
    /// `BLAKE3-keyed(salt, gateway MAC/IP || SSID)` as hex.
    pub fn fingerprint(&self, salt: &[u8; 32]) -> String {
        let gw = self
            .gateway_mac
            .clone()
            .or_else(|| self.gateway.map(|g| g.to_string()))
            .unwrap_or_default();
        let material = format!("{gw}\x00{}", self.ssid.as_deref().unwrap_or(""));
        blake3::keyed_hash(salt, material.as_bytes())
            .to_hex()
            .to_string()
    }
}

/// An exec namespace handed to the engine (Linux).
pub struct ExecNamespace {
    pub name: String,
    pub tun: Arc<dyn TunDevice>,
    /// Keeps the namespace alive; dropping it destroys the namespace.
    pub guard: Box<dyn std::any::Any + Send + Sync>,
}

/// OS hooks used by the controller.
#[async_trait]
pub trait Platform: Send + Sync + 'static {
    /// Platform label for `StatusReport.platform`.
    fn label(&self) -> String;
    /// The kernel firewall backend (created once at start).
    fn firewall(&self) -> Box<dyn FirewallBackend>;
    fn state_dir(&self) -> PathBuf;
    fn daemon_exe(&self) -> Option<PathBuf>;
    /// Socket options for transport sockets (mark + physical interface).
    async fn socket_options(&self) -> SocketOptions;
    async fn connect(
        &self,
        ep: &Endpoint,
        opts: &ConnectOptions,
    ) -> Result<Box<dyn StealthTransport>>;
    /// Bootstrap DNS (the caller pins `BOOTSTRAP_DOH` while armed).
    async fn resolve(&self, host: &str, marked: bool) -> Result<Vec<IpAddr>>;
    fn create_tun(&self, cfg: &OsTunConfig) -> Result<(Arc<dyn TunDevice>, TunnelIface)>;
    /// Split routes over the tunnel plus pinned host routes.
    async fn install_routes(&self, tun: &TunnelIface, pinned: &[IpAddr], v6: bool) -> Result<()>;
    async fn restore_routes(&self) -> Result<()>;
    /// Point the system resolver at the vault.
    async fn apply_dns(&self, tun: &TunnelIface) -> Result<()>;
    async fn restore_dns(&self) -> Result<()>;
    /// Bind the vault on its addresses (adding them locally first).
    async fn start_vault(&self, vault: Arc<DnsVault>, tun: &TunnelIface) -> Result<Vec<DnsServer>>;
    /// Flush OS resolver caches and the ARP / neighbour table.
    async fn flush_caches(&self) -> Result<()>;
    async fn network_identity(&self, probe_dst: IpAddr) -> NetworkIdentity;
    async fn egress_probe(&self, probe: &EgressProbe) -> EgressOutcome;
    /// Resolve through the OS resolver; true when it answered at all.
    async fn system_resolve(&self, name: &str) -> bool;
    /// `https://1.1.1.1/cdn-cgi/trace` (marked: outside the tunnel).
    async fn https_trace(&self, marked: bool) -> Result<String>;
    async fn warp_register(&self, pins: Vec<SocketAddr>, marked: bool) -> Result<WarpAccount>;
    async fn warp_delete(
        &self,
        acct: &WarpAccount,
        pins: Vec<SocketAddr>,
        marked: bool,
    ) -> Result<()>;
    /// Create an isolated exec namespace (Linux); `None` elsewhere.
    async fn exec_namespace(
        &self,
        id: &str,
        v4: (Ipv4Addr, u8),
        mtu: u16,
    ) -> Result<Option<ExecNamespace>>;
}

/// The real platform.
pub struct OsPlatform {
    state_dir: PathBuf,
    routes: Arc<Mutex<RouteState>>,
    dns: Arc<Mutex<vw_firewall::sysdns::SystemDns>>,
}

#[derive(Default)]
struct RouteState {
    #[cfg(target_os = "macos")]
    split: Option<vw_firewall::macos::routes::SplitRoutes>,
    #[cfg(windows)]
    split: Option<vw_firewall::windows::routes::SplitRoutes>,
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

async fn blocking<T: Send + 'static>(f: impl FnOnce() -> Result<T> + Send + 'static) -> Result<T> {
    tokio::task::spawn_blocking(f)
        .await
        .map_err(|e| VwError::Config(format!("worker failed: {e}")))?
}

impl OsPlatform {
    pub fn new(state_dir: PathBuf) -> Self {
        let dns = vw_firewall::sysdns::SystemDns::new(&state_dir);
        Self {
            state_dir,
            routes: Arc::default(),
            dns: Arc::new(Mutex::new(dns)),
        }
    }

    fn https(marked: bool, pins: Vec<SocketAddr>) -> Result<vw_freecloud::http::HttpsClient> {
        let c = vw_freecloud::http::HttpsClient::new()?.with_mark(marked.then_some(FW_MARK));
        Ok(if pins.is_empty() {
            c
        } else {
            c.with_pinned(pins)
        })
    }
}

#[async_trait]
impl Platform for OsPlatform {
    fn label(&self) -> String {
        format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH)
    }

    fn firewall(&self) -> Box<dyn FirewallBackend> {
        vw_firewall::platform_backend()
    }

    fn state_dir(&self) -> PathBuf {
        self.state_dir.clone()
    }

    fn daemon_exe(&self) -> Option<PathBuf> {
        std::env::current_exe().ok()
    }

    async fn socket_options(&self) -> SocketOptions {
        let id = self
            .network_identity(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)))
            .await;
        SocketOptions {
            fw_mark: true,
            interface_index: id.interface_index.and_then(NonZeroU32::new),
        }
    }

    async fn connect(
        &self,
        ep: &Endpoint,
        opts: &ConnectOptions,
    ) -> Result<Box<dyn StealthTransport>> {
        vw_stealth::connect(ep, opts).await
    }

    async fn resolve(&self, host: &str, marked: bool) -> Result<Vec<IpAddr>> {
        if let Ok(ip) = host
            .trim_matches(|c| c == '[' || c == ']')
            .parse::<IpAddr>()
        {
            return Ok(vec![ip]);
        }
        vw_freecloud::http::bootstrap_resolve(host, marked.then_some(FW_MARK)).await
    }

    fn create_tun(&self, cfg: &OsTunConfig) -> Result<(Arc<dyn TunDevice>, TunnelIface)> {
        let dev = vw_wg::OsTun::create(cfg)?;
        let mut iface = TunnelIface::new(dev.name());
        iface.v4 = cfg.ipv4;
        iface.v6 = cfg.ipv6;
        #[cfg(windows)]
        {
            iface.luid = Some(sys::luid_for_alias(&iface.name)?);
        }
        Ok((Arc::new(dev), iface))
    }

    async fn install_routes(&self, tun: &TunnelIface, pinned: &[IpAddr], v6: bool) -> Result<()> {
        let routes = self.routes.clone();
        let (tun, pinned) = (tun.clone(), pinned.to_vec());
        blocking(move || {
            let mut st = lock(&routes);
            #[cfg(target_os = "macos")]
            {
                if let Some(mut old) = st.split.take() {
                    old.restore()?;
                }
                st.split = Some(vw_firewall::macos::routes::SplitRoutes::install(
                    &tun.name, &pinned, v6,
                )?);
            }
            #[cfg(windows)]
            {
                if let Some(mut old) = st.split.take() {
                    old.restore()?;
                }
                let luid = tun
                    .luid
                    .ok_or_else(|| VwError::Config("tunnel adapter has no LUID".into()))?;
                st.split = Some(vw_firewall::windows::routes::SplitRoutes::install(
                    luid, &pinned, v6,
                )?);
                vw_firewall::windows::routes::set_interface_metric(luid, false, 1)?;
                if v6 {
                    vw_firewall::windows::routes::set_interface_metric(luid, true, 1)?;
                }
            }
            // Linux: policy routing (table 51820) is installed atomically by
            // the nftables backend together with the lockdown.
            let _ = (&mut st, &tun, &pinned, v6);
            Ok(())
        })
        .await
    }

    async fn restore_routes(&self) -> Result<()> {
        let routes = self.routes.clone();
        blocking(move || {
            let mut st = lock(&routes);
            #[cfg(any(target_os = "macos", windows))]
            if let Some(mut s) = st.split.take() {
                s.restore()?;
            }
            let _ = &mut st;
            Ok(())
        })
        .await
    }

    async fn apply_dns(&self, tun: &TunnelIface) -> Result<()> {
        let (dns, tun) = (self.dns.clone(), tun.clone());
        blocking(move || lock(&dns).apply(Some(&tun))).await
    }

    async fn restore_dns(&self) -> Result<()> {
        let dns = self.dns.clone();
        blocking(move || lock(&dns).restore()).await
    }

    async fn start_vault(&self, vault: Arc<DnsVault>, tun: &TunnelIface) -> Result<Vec<DnsServer>> {
        sys::add_vault_addresses(tun).await?;
        let mut v = Vec::new();
        let v4 = SocketAddr::new(IpAddr::V4(DNS_VAULT_V4), DNS_PORT);
        v.push(vw_dns::serve_udp(vault.clone(), v4).await?);
        v.push(vw_dns::serve_tcp(vault.clone(), v4).await?);
        let v6 = SocketAddr::new(IpAddr::V6(DNS_VAULT_V6), DNS_PORT);
        // IPv6 may be disabled on the host; the IPv4 vault is mandatory.
        match vw_dns::serve_udp(vault.clone(), v6).await {
            Ok(s) => {
                v.push(s);
                if let Ok(t) = vw_dns::serve_tcp(vault, v6).await {
                    v.push(t);
                }
            }
            Err(e) => tracing::debug!(error = %e, "IPv6 vault listener unavailable"),
        }
        Ok(v)
    }

    async fn flush_caches(&self) -> Result<()> {
        blocking(vw_firewall::sysdns::flush_caches).await?;
        sys::flush_neighbours().await
    }

    async fn network_identity(&self, probe_dst: IpAddr) -> NetworkIdentity {
        sys::network_identity(probe_dst).await
    }

    async fn egress_probe(&self, probe: &EgressProbe) -> EgressOutcome {
        let id = self.network_identity(probe.target.ip()).await;
        physical_probe(probe, &id).await
    }

    async fn system_resolve(&self, name: &str) -> bool {
        // getaddrinfo: NXDOMAIN is an answer too (the vault replies NXDOMAIN
        // for canary names); only a timeout means the resolver never replied.
        let fut = tokio::net::lookup_host((name.to_string(), 443));
        match tokio::time::timeout(Duration::from_secs(4), fut).await {
            Ok(Ok(_)) => true,
            Ok(Err(e)) => e.kind() != std::io::ErrorKind::TimedOut,
            Err(_) => false,
        }
    }

    async fn https_trace(&self, marked: bool) -> Result<String> {
        let pin = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 443);
        let c = Self::https(marked, vec![pin])?;
        let r = c
            .request(
                hyper::Method::GET,
                "https://1.1.1.1/cdn-cgi/trace",
                &[],
                None,
            )
            .await?;
        if r.status != 200 {
            return Err(VwError::Transport(format!("trace HTTP {}", r.status)));
        }
        Ok(String::from_utf8_lossy(&r.body).into_owned())
    }

    async fn warp_register(&self, pins: Vec<SocketAddr>, marked: bool) -> Result<WarpAccount> {
        vw_freecloud::WarpRegistrar::new(Self::https(marked, pins)?)
            .register(true)
            .await
    }

    async fn warp_delete(
        &self,
        acct: &WarpAccount,
        pins: Vec<SocketAddr>,
        marked: bool,
    ) -> Result<()> {
        vw_freecloud::WarpRegistrar::new(Self::https(marked, pins)?)
            .delete(acct)
            .await
    }

    async fn exec_namespace(
        &self,
        id: &str,
        v4: (Ipv4Addr, u8),
        mtu: u16,
    ) -> Result<Option<ExecNamespace>> {
        #[cfg(target_os = "linux")]
        {
            sys::exec_namespace(id, v4, mtu).await.map(Some)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (id, v4, mtu);
            Ok(None)
        }
    }
}

/// Unmarked probe bound to the physical interface (canary).
pub async fn physical_probe(probe: &EgressProbe, id: &NetworkIdentity) -> EgressOutcome {
    use socket2::{Domain, Protocol, Socket, Type};
    let domain = Domain::for_address(probe.target);
    let (ty, proto) = match probe.proto {
        EgressProto::Udp => (Type::DGRAM, Protocol::UDP),
        EgressProto::Tcp => (Type::STREAM, Protocol::TCP),
    };
    let sock = match Socket::new(domain, ty, Some(proto)) {
        Ok(s) => s,
        Err(e) => return EgressOutcome::Blocked(format!("socket: {}", e.kind())),
    };
    if let Err(e) = sys::bind_physical(&sock, id, probe.target.is_ipv6()) {
        // Cannot bind to the physical interface: the probe would follow the
        // routes into the tunnel and prove nothing. Report as no reply.
        tracing::debug!(error = %e, "cannot bind probe to physical interface");
    }
    let _ = sock.set_nonblocking(true);
    match probe.proto {
        EgressProto::Tcp => {
            let ts = tokio::net::TcpSocket::from_std_stream(sock.into());
            match tokio::time::timeout(Duration::from_secs(3), ts.connect(probe.target)).await {
                Ok(Ok(_)) => EgressOutcome::Reached(1),
                Ok(Err(e)) => EgressOutcome::Blocked(format!("connect: {}", e.kind())),
                Err(_) => EgressOutcome::NoReply,
            }
        }
        EgressProto::Udp => {
            let std_sock: std::net::UdpSocket = sock.into();
            let Ok(u) = tokio::net::UdpSocket::from_std(std_sock) else {
                return EgressOutcome::Blocked("socket conversion".into());
            };
            if let Err(e) = u.send_to(&probe.payload, probe.target).await {
                return EgressOutcome::Blocked(format!("send: {}", e.kind()));
            }
            let mut buf = [0u8; 1500];
            match tokio::time::timeout(Duration::from_millis(1500), u.recv_from(&mut buf)).await {
                Ok(Ok((n, _))) => EgressOutcome::Reached(n),
                Ok(Err(e)) => EgressOutcome::Blocked(format!("recv: {}", e.kind())),
                Err(_) => EgressOutcome::NoReply,
            }
        }
    }
}

// ───────────────────────────── per-OS code ─────────────────────────────

fn parse_kv<'a>(text: &'a str, key: &str) -> Option<&'a str> {
    text.lines()
        .filter_map(|l| l.split_once(':'))
        .find(|(k, _)| k.trim() == key)
        .map(|(_, v)| v.trim())
        .filter(|v| !v.is_empty())
}

/// First MAC address (`aa:bb:..` or `aa-bb-..`) in `text`, lower-case with colons.
pub fn find_mac(text: &str) -> Option<String> {
    text.split(|c: char| c.is_whitespace() || c == '(' || c == ')')
        .find(|w| {
            let parts: Vec<&str> = w.split([':', '-']).collect();
            parts.len() == 6
                && parts
                    .iter()
                    .all(|p| (1..=2).contains(&p.len()) && p.chars().all(|c| c.is_ascii_hexdigit()))
        })
        .map(|w| {
            w.split([':', '-'])
                .map(|p| format!("{:0>2}", p.to_ascii_lowercase()))
                .collect::<Vec<_>>()
                .join(":")
        })
}

/// `default <gw> ... <iface>` from `netstat -rn -f inet` (macOS).
pub fn parse_netstat_default(out: &str) -> (Option<IpAddr>, Option<String>) {
    for l in out.lines() {
        let f: Vec<&str> = l.split_whitespace().collect();
        if f.first() == Some(&"default") && f.len() >= 4 {
            let gw = f[1].split('%').next().and_then(|g| g.parse().ok());
            if gw.is_some() {
                return (gw, f.last().map(|s| s.to_string()));
            }
        }
    }
    (None, None)
}

/// `default via <gw> dev <iface>` from `ip route show default` (Linux).
pub fn parse_ip_route_default(out: &str) -> (Option<IpAddr>, Option<String>) {
    let f: Vec<&str> = out.split_whitespace().collect();
    let after = |k: &str| f.iter().position(|w| *w == k).and_then(|i| f.get(i + 1));
    (
        after("via").and_then(|g| g.parse().ok()),
        after("dev").map(|s| s.to_string()),
    )
}

#[cfg(unix)]
fn if_index(name: &str) -> Option<u32> {
    nix::net::if_::if_nametoindex(name).ok()
}

#[cfg(target_os = "macos")]
mod sys {
    use super::*;
    use crate::util::{run, run_ok};

    pub async fn add_vault_addresses(_tun: &TunnelIface) -> Result<()> {
        let v4 = DNS_VAULT_V4.to_string();
        run_ok(
            "/sbin/ifconfig",
            &["lo0", "alias", &v4, "netmask", "255.255.255.255"],
        )
        .await?;
        let v6 = DNS_VAULT_V6.to_string();
        let _ = run(
            "/sbin/ifconfig",
            &["lo0", "inet6", &v6, "prefixlen", "128", "alias"],
        )
        .await;
        Ok(())
    }

    pub async fn flush_neighbours() -> Result<()> {
        run_ok("/usr/sbin/arp", &["-a", "-d"]).await.map(drop)
    }

    pub async fn network_identity(_probe: IpAddr) -> NetworkIdentity {
        let mut id = NetworkIdentity::default();
        if let Ok(o) = run("/usr/sbin/netstat", &["-rn", "-f", "inet"]).await {
            let (gw, ifc) = parse_netstat_default(&o.stdout);
            id.gateway = gw;
            id.interface = ifc;
        }
        if let Some(gw) = id.gateway {
            if let Ok(o) = run("/usr/sbin/arp", &["-n", &gw.to_string()]).await {
                id.gateway_mac = find_mac(&o.stdout);
            }
        }
        if let Some(i) = id.interface.clone() {
            id.interface_index = if_index(&i);
            if let Ok(o) = run("/usr/sbin/networksetup", &["-getairportnetwork", &i]).await {
                id.ssid = parse_kv(&o.stdout, "Current Wi-Fi Network").map(str::to_string);
            }
            if id.ssid.is_none() {
                if let Ok(o) = run("/usr/sbin/ipconfig", &["getsummary", &i]).await {
                    id.ssid = o
                        .stdout
                        .lines()
                        .find(|l| l.trim_start().starts_with("SSID :"))
                        .and_then(|l| l.split_once(':'))
                        .map(|(_, v)| v.trim().to_string());
                }
            }
        }
        id
    }

    pub fn bind_physical(
        s: &socket2::Socket,
        id: &NetworkIdentity,
        v6: bool,
    ) -> std::io::Result<()> {
        let idx = id
            .interface_index
            .and_then(NonZeroU32::new)
            .ok_or_else(|| std::io::Error::other("no physical interface"))?;
        if v6 {
            s.bind_device_by_index_v6(Some(idx))
        } else {
            s.bind_device_by_index_v4(Some(idx))
        }
    }
}

#[cfg(target_os = "linux")]
mod sys {
    use super::*;
    use crate::util::{run, run_ok};

    const IP: &str = "/usr/sbin/ip";

    fn ip() -> &'static str {
        ["/usr/sbin/ip", "/sbin/ip", "/usr/bin/ip", "/bin/ip"]
            .into_iter()
            .find(|p| std::path::Path::new(p).exists())
            .unwrap_or(IP)
    }

    pub async fn add_vault_addresses(_tun: &TunnelIface) -> Result<()> {
        let v4 = format!("{DNS_VAULT_V4}/32");
        run_ok(ip(), &["addr", "replace", &v4, "dev", "lo"]).await?;
        let v6 = format!("{DNS_VAULT_V6}/128");
        let _ = run(ip(), &["-6", "addr", "replace", &v6, "dev", "lo"]).await;
        Ok(())
    }

    pub async fn flush_neighbours() -> Result<()> {
        run_ok(ip(), &["neigh", "flush", "all"]).await.map(drop)
    }

    pub async fn network_identity(_probe: IpAddr) -> NetworkIdentity {
        let mut id = NetworkIdentity::default();
        if let Ok(o) = run(ip(), &["route", "show", "default"]).await {
            let (gw, dev) = parse_ip_route_default(&o.stdout);
            id.gateway = gw;
            id.interface = dev;
        }
        if let Some(gw) = id.gateway {
            if let Ok(o) = run(ip(), &["neigh", "show", &gw.to_string()]).await {
                id.gateway_mac = find_mac(&o.stdout);
            }
        }
        if let Some(i) = id.interface.clone() {
            id.interface_index = if_index(&i);
            for iw in ["/usr/sbin/iw", "/sbin/iw", "/usr/bin/iw"] {
                if let Ok(o) = run(iw, &["dev", &i, "link"]).await {
                    id.ssid = parse_kv(&o.stdout, "SSID").map(str::to_string);
                    break;
                }
            }
        }
        id
    }

    pub fn bind_physical(
        s: &socket2::Socket,
        id: &NetworkIdentity,
        _v6: bool,
    ) -> std::io::Result<()> {
        let name = id
            .interface
            .as_deref()
            .ok_or_else(|| std::io::Error::other("no physical interface"))?;
        s.bind_device(Some(name.as_bytes()))
    }

    /// Async TUN over the namespace's `/dev/net/tun` descriptor.
    struct FdTun {
        fd: tokio::io::unix::AsyncFd<std::fs::File>,
        name: String,
        mtu: u16,
    }

    #[async_trait]
    impl TunDevice for FdTun {
        async fn read_packet(&self, buf: &mut [u8]) -> Result<usize> {
            use std::io::Read;
            loop {
                let mut g = self.fd.readable().await?;
                match g.try_io(|f| f.get_ref().read(buf)) {
                    Ok(r) => return Ok(r?),
                    Err(_would_block) => continue,
                }
            }
        }
        async fn write_packet(&self, packet: &[u8]) -> Result<()> {
            use std::io::Write;
            loop {
                let mut g = self.fd.writable().await?;
                match g.try_io(|f| f.get_ref().write(packet)) {
                    Ok(r) => {
                        r?;
                        return Ok(());
                    }
                    Err(_would_block) => continue,
                }
            }
        }
        fn mtu(&self) -> u16 {
            self.mtu
        }
        fn name(&self) -> String {
            self.name.clone()
        }
    }

    pub async fn exec_namespace(id: &str, v4: (Ipv4Addr, u8), mtu: u16) -> Result<ExecNamespace> {
        use vw_firewall::linux::netns::{IsolatedNamespace, NsAddressing};
        let id = id.to_string();
        let mut ns = tokio::task::spawn_blocking(move || {
            IsolatedNamespace::create_with(&id, NsAddressing { v4, v6: None, mtu })
        })
        .await
        .map_err(|e| VwError::Firewall(format!("netns worker: {e}")))??;
        let fd = ns
            .take_tun_fd()
            .ok_or_else(|| VwError::Firewall("namespace has no TUN".into()))?;
        let file = std::fs::File::from(fd);
        let flags = nix::fcntl::fcntl(&file, nix::fcntl::FcntlArg::F_GETFL)
            .map_err(|e| VwError::Firewall(format!("fcntl: {e}")))?;
        let flags = nix::fcntl::OFlag::from_bits_truncate(flags) | nix::fcntl::OFlag::O_NONBLOCK;
        nix::fcntl::fcntl(&file, nix::fcntl::FcntlArg::F_SETFL(flags))
            .map_err(|e| VwError::Firewall(format!("fcntl: {e}")))?;
        // The AsyncFd owns `file` for its whole lifetime, so the I/O-safety
        // concern behind the deprecation (borrowed raw fds) does not apply.
        #[allow(deprecated)]
        let fd = tokio::io::unix::AsyncFd::new(file)?;
        let tun = FdTun {
            fd,
            name: vw_firewall::linux::netns::NS_TUN_NAME.into(),
            mtu,
        };
        Ok(ExecNamespace {
            name: ns.name().to_string(),
            tun: Arc::new(tun),
            guard: Box::new(Mutex::new(ns)),
        })
    }
}

#[cfg(windows)]
mod sys {
    use super::*;
    use crate::util::{run, run_ok};
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        ConvertInterfaceAliasToLuid, ConvertInterfaceLuidToIndex,
    };
    use windows_sys::Win32::NetworkManagement::Ndis::NET_LUID_LH;

    pub fn luid_for_alias(alias: &str) -> Result<u64> {
        let wide: Vec<u16> = alias.encode_utf16().chain(std::iter::once(0)).collect();
        let mut luid = NET_LUID_LH { Value: 0 };
        // SAFETY: `wide` is a NUL-terminated UTF-16 string alive for the call
        // and `luid` is a valid, writable NET_LUID_LH.
        let rc = unsafe { ConvertInterfaceAliasToLuid(wide.as_ptr(), &mut luid) };
        if rc != 0 {
            return Err(VwError::Config(format!(
                "ConvertInterfaceAliasToLuid failed ({rc})"
            )));
        }
        // SAFETY: `Value` spans the whole NET_LUID_LH union.
        Ok(unsafe { luid.Value })
    }

    fn index_for_luid(luid: u64) -> Option<u32> {
        let l = NET_LUID_LH { Value: luid };
        let mut idx = 0u32;
        // SAFETY: both pointers reference live locals for the duration of the call.
        let rc = unsafe { ConvertInterfaceLuidToIndex(&l, &mut idx) };
        (rc == 0).then_some(idx)
    }

    pub async fn add_vault_addresses(tun: &TunnelIface) -> Result<()> {
        let name = format!("name={}", tun.name);
        let a4 = format!("address={DNS_VAULT_V4}");
        // Already present after a reconnect: ignore the error then.
        let _ = run(
            "netsh",
            &[
                "interface",
                "ipv4",
                "add",
                "address",
                &name,
                &a4,
                "mask=255.255.255.255",
            ],
        )
        .await;
        let a6 = format!("address={DNS_VAULT_V6}/128");
        let _ = run(
            "netsh",
            &["interface", "ipv6", "add", "address", &name, &a6],
        )
        .await;
        Ok(())
    }

    pub async fn flush_neighbours() -> Result<()> {
        run_ok("netsh", &["interface", "ip", "delete", "arpcache"])
            .await
            .map(drop)
    }

    pub async fn network_identity(probe: IpAddr) -> NetworkIdentity {
        let mut id = NetworkIdentity::default();
        if let Ok((luid, gw)) = vw_firewall::windows::routes::best_route(probe) {
            id.gateway = gw;
            id.interface_index = index_for_luid(luid);
        }
        if let Some(gw) = id.gateway {
            if let Ok(o) = run("arp", &["-a", &gw.to_string()]).await {
                id.gateway_mac = find_mac(&o.stdout);
            }
        }
        if let Ok(o) = run("netsh", &["wlan", "show", "interfaces"]).await {
            id.ssid = parse_kv(&o.stdout, "SSID").map(str::to_string);
        }
        id
    }

    pub fn bind_physical(
        s: &socket2::Socket,
        id: &NetworkIdentity,
        v6: bool,
    ) -> std::io::Result<()> {
        use std::os::windows::io::AsRawSocket;
        use windows_sys::Win32::Networking::WinSock::setsockopt;
        const IPPROTO_IP: i32 = 0;
        const IPPROTO_IPV6: i32 = 41;
        const IP_UNICAST_IF: i32 = 31;
        const IPV6_UNICAST_IF: i32 = 31;
        let idx = id
            .interface_index
            .ok_or_else(|| std::io::Error::other("no physical interface"))?;
        // IPv4 takes the index in network byte order, IPv6 in host order.
        let (level, opt, val) = if v6 {
            (IPPROTO_IPV6, IPV6_UNICAST_IF, idx)
        } else {
            (IPPROTO_IP, IP_UNICAST_IF, idx.to_be())
        };
        // SAFETY: the socket handle is owned by `s` and alive; `val` is a u32
        // local whose address and size are passed exactly.
        let rc = unsafe {
            setsockopt(
                s.as_raw_socket() as usize,
                level,
                opt,
                (&val as *const u32).cast(),
                std::mem::size_of::<u32>() as i32,
            )
        };
        if rc != 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }
}

#[cfg(not(any(target_os = "macos", target_os = "linux", windows)))]
mod sys {
    use super::*;

    pub async fn add_vault_addresses(_tun: &TunnelIface) -> Result<()> {
        Err(VwError::Unsupported("vault addresses"))
    }
    pub async fn flush_neighbours() -> Result<()> {
        Err(VwError::Unsupported("neighbour flush"))
    }
    pub async fn network_identity(_probe: IpAddr) -> NetworkIdentity {
        NetworkIdentity::default()
    }
    pub fn bind_physical(
        _s: &socket2::Socket,
        _id: &NetworkIdentity,
        _v6: bool,
    ) -> std::io::Result<()> {
        Err(std::io::Error::other("unsupported"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parsers() {
        let ns = "Routing tables\n\nInternet:\nDestination        Gateway            Flags               Netif Expire\ndefault            192.168.1.1        UGScg                 en0       \n0/1                utun4              USc                 utun4\n";
        assert_eq!(
            parse_netstat_default(ns),
            (Some("192.168.1.1".parse().unwrap()), Some("en0".into()))
        );
        assert_eq!(
            parse_ip_route_default("default via 10.0.0.1 dev wlan0 proto dhcp metric 600\n"),
            (Some("10.0.0.1".parse().unwrap()), Some("wlan0".into()))
        );
        assert_eq!(
            find_mac("? (192.168.1.1) at 4:d9:f5:a:b:c on en0 ifscope [ethernet]"),
            Some("04:d9:f5:0a:0b:0c".into())
        );
        assert_eq!(
            find_mac("  192.168.1.1   aa-bb-cc-dd-ee-ff   dynamic"),
            Some("aa:bb:cc:dd:ee:ff".into())
        );
        assert_eq!(
            parse_kv("    SSID                   : Home\n", "SSID"),
            Some("Home")
        );
    }

    #[test]
    fn fingerprint_is_salted_and_stable() {
        let id = NetworkIdentity {
            gateway_mac: Some("aa:bb:cc:dd:ee:ff".into()),
            ssid: Some("Home".into()),
            ..Default::default()
        };
        let a = id.fingerprint(&[1; 32]);
        assert_eq!(a, id.fingerprint(&[1; 32]));
        assert_ne!(a, id.fingerprint(&[2; 32]));
        assert!(!a.contains("aa:bb"));
    }
}
