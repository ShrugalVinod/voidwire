//! `voidwire exec` isolation: a network namespace `vw-ns-<id>` whose only
//! non-loopback interface is a TUN device owned by the daemon. Processes in
//! the namespace can reach nothing but the userspace engine reading that TUN.

use std::ffi::OsStr;
use std::fs::{File, OpenOptions};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd};
use std::path::PathBuf;
use std::process::Command;

use nix::sched::CloneFlags;
use vw_core::consts::{DNS_VAULT_V4, DNS_VAULT_V6, PROVISIONAL_V4, SAFE_TUNNEL_MTU};
use vw_core::{Result, VwError};

use super::IP_PATHS;
use crate::cmd::{resolve, run, run_ok};

/// Name of the TUN interface inside every isolated namespace.
pub const NS_TUN_NAME: &str = "vwns0";

const IFF_TUN: libc_short = 0x0001;
const IFF_NO_PI: libc_short = 0x1000;
#[allow(non_camel_case_types)]
type libc_short = nix::libc::c_short;

/// `struct ifreq` as used by `TUNSETIFF` (name + flags, padded to 40 bytes).
#[repr(C)]
struct IfReqFlags {
    name: [nix::libc::c_char; 16],
    flags: libc_short,
    _pad: [u8; 22],
}

// TUNSETIFF = _IOW('T', 202, int)
nix::ioctl_write_ptr_bad!(
    tun_set_iff,
    nix::request_code_write!(b'T', 202, std::mem::size_of::<nix::libc::c_int>()),
    IfReqFlags
);

/// Addressing of the TUN inside the namespace.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NsAddressing {
    pub v4: (Ipv4Addr, u8),
    pub v6: Option<(Ipv6Addr, u8)>,
    pub mtu: u16,
}

impl Default for NsAddressing {
    /// The provisional client address; the daemon should pass the address the
    /// node assigned via [`IsolatedNamespace::create_with`] so no source
    /// rewriting is needed.
    fn default() -> Self {
        Self {
            v4: (PROVISIONAL_V4, 32),
            v6: None,
            mtu: SAFE_TUNNEL_MTU,
        }
    }
}

/// A live isolated namespace. Dropping it destroys the namespace.
#[derive(Debug)]
pub struct IsolatedNamespace {
    name: String,
    ip: String,
    tun: Option<OwnedFd>,
    destroyed: bool,
}

/// Namespace ids become part of a path and an `ip netns` name.
pub fn validate_ns_id(id: &str) -> Result<()> {
    let ok = (1..=32).contains(&id.len())
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
    if ok {
        Ok(())
    } else {
        Err(VwError::Config(
            "namespace id must be 1-32 chars of [A-Za-z0-9_-]".into(),
        ))
    }
}

pub fn ns_name(id: &str) -> String {
    format!("vw-ns-{id}")
}

fn netns_etc_dir(name: &str) -> PathBuf {
    PathBuf::from("/etc/netns").join(name)
}

/// `resolv.conf` used by `ip netns exec` inside the namespace.
pub fn ns_resolv_conf(v6: bool) -> String {
    let mut s = format!("# VoidWire isolated namespace\nnameserver {DNS_VAULT_V4}\n");
    if v6 {
        s.push_str(&format!("nameserver {DNS_VAULT_V6}\n"));
    }
    s
}

/// Open `/dev/net/tun` from a thread that has joined `ns_path`, so the TUN
/// netdev is created inside that namespace. The fd stays usable from any
/// thread of the daemon afterwards.
fn open_tun_in(ns_path: PathBuf, ifname: &'static str) -> Result<OwnedFd> {
    std::thread::spawn(move || -> Result<OwnedFd> {
        let ns = File::open(&ns_path)?;
        nix::sched::setns(ns.as_fd(), CloneFlags::CLONE_NEWNET)
            .map_err(|e| VwError::Firewall(format!("setns: {e}")))?;
        let tun = OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/net/tun")?;
        let mut req = IfReqFlags {
            name: [0; 16],
            flags: IFF_TUN | IFF_NO_PI,
            _pad: [0; 22],
        };
        for (d, s) in req.name.iter_mut().zip(ifname.bytes()) {
            *d = s as nix::libc::c_char;
        }
        // SAFETY: `tun` is an open /dev/net/tun descriptor owned by this
        // scope, and `req` is a properly initialised, NUL-terminated
        // `struct ifreq` layout that outlives the call; TUNSETIFF only reads
        // (and may write back the name into) that buffer.
        unsafe { tun_set_iff(tun.as_raw_fd(), &req) }
            .map_err(|e| VwError::Firewall(format!("TUNSETIFF: {e}")))?;
        Ok(OwnedFd::from(tun))
    })
    .join()
    .map_err(|_| VwError::Firewall("netns worker thread panicked".into()))?
}

impl IsolatedNamespace {
    /// Create `vw-ns-<id>` with default addressing.
    pub fn create(id: &str) -> Result<Self> {
        Self::create_with(id, NsAddressing::default())
    }

    pub fn create_with(id: &str, addr: NsAddressing) -> Result<Self> {
        validate_ns_id(id)?;
        let name = ns_name(id);
        let ip = resolve("ip", &IP_PATHS);
        // Remove a stale namespace left by a crash; absence is not an error.
        run(&ip, &["netns", "del", &name], None)?;
        run_ok(&ip, &["netns", "add", &name], None)?;
        let mut ns = Self {
            name,
            ip,
            tun: None,
            destroyed: false,
        };
        if let Err(e) = ns.setup(addr) {
            let _ = ns.destroy();
            return Err(e);
        }
        tracing::debug!(ns = %ns.name, "isolated namespace ready");
        Ok(ns)
    }

    fn ip_ns(&self, rest: &[&str]) -> Result<()> {
        let mut argv = vec!["-n", self.name.as_str()];
        argv.extend_from_slice(rest);
        run_ok(&self.ip, &argv, None).map(drop)
    }

    fn setup(&mut self, addr: NsAddressing) -> Result<()> {
        let ns_path = PathBuf::from("/var/run/netns").join(&self.name);
        self.tun = Some(open_tun_in(ns_path, NS_TUN_NAME)?);
        self.ip_ns(&["link", "set", "lo", "up"])?;
        let mtu = addr.mtu.to_string();
        self.ip_ns(&["link", "set", "dev", NS_TUN_NAME, "mtu", &mtu, "up"])?;
        let v4 = format!("{}/{}", addr.v4.0, addr.v4.1);
        self.ip_ns(&["-4", "addr", "add", &v4, "dev", NS_TUN_NAME])?;
        self.ip_ns(&["-4", "route", "add", "default", "dev", NS_TUN_NAME])?;
        if let Some((a, p)) = addr.v6 {
            let v6 = format!("{a}/{p}");
            self.ip_ns(&["-6", "addr", "add", &v6, "dev", NS_TUN_NAME, "nodad"])?;
            self.ip_ns(&["-6", "route", "add", "default", "dev", NS_TUN_NAME])?;
        }
        let dir = netns_etc_dir(&self.name);
        std::fs::create_dir_all(&dir)?;
        std::fs::write(dir.join("resolv.conf"), ns_resolv_conf(addr.v6.is_some()))?;
        Ok(())
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    /// Borrow the TUN fd (packets written by namespace processes appear here).
    pub fn tun_fd(&self) -> Option<BorrowedFd<'_>> {
        self.tun.as_ref().map(|f| f.as_fd())
    }

    /// Hand the TUN fd to the daemon's packet engine.
    pub fn take_tun_fd(&mut self) -> Option<OwnedFd> {
        self.tun.take()
    }

    /// A `Command` that runs `program args...` inside the namespace via
    /// `ip netns exec` (which also bind-mounts the namespace `resolv.conf`).
    /// The caller decides credentials, stdio and whether to spawn or wait.
    pub fn exec_in<I, S>(&self, program: impl AsRef<OsStr>, args: I) -> Command
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        let mut c = Command::new(&self.ip);
        c.arg("netns")
            .arg("exec")
            .arg(&self.name)
            .arg(program)
            .args(args);
        c
    }

    /// Delete the namespace and its `/etc/netns` directory. Idempotent.
    pub fn destroy(&mut self) -> Result<()> {
        if self.destroyed {
            return Ok(());
        }
        self.tun = None;
        let out = run(&self.ip, &["netns", "del", &self.name], None)?;
        if !out.success && !out.stderr.contains("No such file") {
            return Err(VwError::Firewall(format!(
                "ip netns del failed: {}",
                crate::cmd::scrub_addresses(out.stderr.trim())
            )));
        }
        let dir = netns_etc_dir(&self.name);
        if dir.exists() {
            std::fs::remove_dir_all(&dir)?;
        }
        self.destroyed = true;
        tracing::debug!(ns = %self.name, "isolated namespace destroyed");
        Ok(())
    }
}

impl Drop for IsolatedNamespace {
    fn drop(&mut self) {
        if let Err(e) = self.destroy() {
            tracing::warn!(error = %e, "failed to destroy isolated namespace");
        }
    }
}

/// Whether `ip` is a valid in-namespace source address for `addr`.
pub fn addressing_matches(addr: &NsAddressing, ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(a) => a == addr.v4.0,
        IpAddr::V6(a) => addr.v6.is_some_and(|(v, _)| v == a),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_and_names() {
        assert!(validate_ns_id("abc-1_2").is_ok());
        assert!(validate_ns_id("../x").is_err());
        assert!(validate_ns_id("").is_err());
        assert_eq!(ns_name("7"), "vw-ns-7");
        assert!(ns_resolv_conf(true).contains("nameserver fd00:564f:4944::1"));
        assert!(addressing_matches(
            &NsAddressing::default(),
            IpAddr::V4(PROVISIONAL_V4)
        ));
    }
}
