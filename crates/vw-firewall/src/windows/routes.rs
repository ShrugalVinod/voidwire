//! Windows routing via IP Helper: split default routes over the Wintun
//! adapter, host routes keeping pinned endpoints on the original gateway,
//! and interface metrics.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::ptr;

use serde::{Deserialize, Serialize};
use vw_core::{Result, VwError};
use windows_sys::Win32::Foundation::{ERROR_NOT_FOUND, ERROR_OBJECT_ALREADY_EXISTS, NO_ERROR};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    CreateIpForwardEntry2, DeleteIpForwardEntry2, GetBestRoute2, GetIpInterfaceEntry,
    InitializeIpForwardEntry, InitializeIpInterfaceEntry, SetIpInterfaceEntry, IP_ADDRESS_PREFIX,
    MIB_IPFORWARD_ROW2, MIB_IPINTERFACE_ROW,
};
use windows_sys::Win32::NetworkManagement::Ndis::NET_LUID_LH;
use windows_sys::Win32::Networking::WinSock::{
    AF_INET, AF_INET6, IN6_ADDR, IN6_ADDR_0, IN_ADDR, IN_ADDR_0, MIB_IPPROTO_NETMGMT, SOCKADDR_IN,
    SOCKADDR_IN6, SOCKADDR_IN6_0, SOCKADDR_INET,
};

use crate::plan::{split_default_prefixes, IpCidr};

fn win(rc: u32, what: &str) -> Result<()> {
    if rc == NO_ERROR {
        Ok(())
    } else {
        Err(VwError::Firewall(format!("{what} failed: {rc}")))
    }
}

fn sockaddr(ip: IpAddr) -> SOCKADDR_INET {
    let mut s = SOCKADDR_INET::default();
    match ip {
        IpAddr::V4(a) => {
            s.Ipv4 = SOCKADDR_IN {
                sin_family: AF_INET,
                sin_port: 0,
                sin_addr: IN_ADDR {
                    // Network byte order: the in-memory bytes are the octets.
                    S_un: IN_ADDR_0 {
                        S_addr: u32::from_ne_bytes(a.octets()),
                    },
                },
                sin_zero: [0; 8],
            }
        }
        IpAddr::V6(a) => {
            s.Ipv6 = SOCKADDR_IN6 {
                sin6_family: AF_INET6,
                sin6_port: 0,
                sin6_flowinfo: 0,
                sin6_addr: IN6_ADDR {
                    u: IN6_ADDR_0 { Byte: a.octets() },
                },
                Anonymous: SOCKADDR_IN6_0 { sin6_scope_id: 0 },
            }
        }
    }
    s
}

fn from_sockaddr(s: &SOCKADDR_INET) -> Option<IpAddr> {
    // SAFETY: every SOCKADDR_INET variant starts with the address family, so
    // reading `si_family` is always valid; the matching variant is then read.
    unsafe {
        match s.si_family {
            AF_INET => Some(IpAddr::V4(Ipv4Addr::from(
                s.Ipv4.sin_addr.S_un.S_addr.to_ne_bytes(),
            ))),
            AF_INET6 => Some(IpAddr::V6(Ipv6Addr::from(s.Ipv6.sin6_addr.u.Byte))),
            _ => None,
        }
    }
}

fn unspecified_like(dest: IpAddr) -> IpAddr {
    match dest {
        IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        IpAddr::V6(_) => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
    }
}

fn row(luid: u64, dest: IpCidr, next_hop: Option<IpAddr>, metric: u32) -> MIB_IPFORWARD_ROW2 {
    let mut r = MIB_IPFORWARD_ROW2::default();
    // SAFETY: `r` is a valid, writable MIB_IPFORWARD_ROW2.
    unsafe { InitializeIpForwardEntry(&mut r) };
    r.InterfaceLuid = NET_LUID_LH { Value: luid };
    r.DestinationPrefix = IP_ADDRESS_PREFIX {
        Prefix: sockaddr(dest.addr()),
        PrefixLength: dest.prefix(),
    };
    r.NextHop = sockaddr(next_hop.unwrap_or_else(|| unspecified_like(dest.addr())));
    r.Metric = metric;
    r.Protocol = MIB_IPPROTO_NETMGMT;
    r
}

/// Add a route (`next_hop = None` means on-link). Existing routes are fine.
pub fn add_route(luid: u64, dest: IpCidr, next_hop: Option<IpAddr>, metric: u32) -> Result<()> {
    let r = row(luid, dest, next_hop, metric);
    // SAFETY: `r` is fully initialised and valid for the call.
    let rc = unsafe { CreateIpForwardEntry2(&r) };
    if rc == ERROR_OBJECT_ALREADY_EXISTS {
        return Ok(());
    }
    win(rc, "CreateIpForwardEntry2")
}

/// Delete a route added by [`add_route`]. Missing routes are fine.
pub fn delete_route(luid: u64, dest: IpCidr, next_hop: Option<IpAddr>) -> Result<()> {
    let r = row(luid, dest, next_hop, 0);
    // SAFETY: `r` is fully initialised and valid for the call.
    let rc = unsafe { DeleteIpForwardEntry2(&r) };
    if rc == ERROR_NOT_FOUND {
        return Ok(());
    }
    win(rc, "DeleteIpForwardEntry2")
}

/// Interface LUID and next hop the stack would use for `dest` right now.
pub fn best_route(dest: IpAddr) -> Result<(u64, Option<IpAddr>)> {
    let d = sockaddr(dest);
    let mut best = MIB_IPFORWARD_ROW2::default();
    let mut src = SOCKADDR_INET::default();
    // SAFETY: all pointers reference live locals; null LUID / source mean
    // "any", as documented for GetBestRoute2.
    let rc = unsafe { GetBestRoute2(ptr::null(), 0, ptr::null(), &d, 0, &mut best, &mut src) };
    win(rc, "GetBestRoute2")?;
    // SAFETY: `Value` covers the whole NET_LUID_LH union.
    let luid = unsafe { best.InterfaceLuid.Value };
    let nh = from_sockaddr(&best.NextHop).filter(|a| !a.is_unspecified());
    Ok((luid, nh))
}

/// Pin an interface metric (disables automatic metric). Lowest wins.
pub fn set_interface_metric(luid: u64, v6: bool, metric: u32) -> Result<()> {
    let mut r = MIB_IPINTERFACE_ROW::default();
    // SAFETY: `r` is a valid, writable MIB_IPINTERFACE_ROW.
    unsafe { InitializeIpInterfaceEntry(&mut r) };
    r.Family = if v6 { AF_INET6 } else { AF_INET };
    r.InterfaceLuid = NET_LUID_LH { Value: luid };
    // SAFETY: `r` identifies the interface by family + LUID.
    win(
        unsafe { GetIpInterfaceEntry(&mut r) },
        "GetIpInterfaceEntry",
    )?;
    r.UseAutomaticMetric = false;
    r.Metric = metric;
    if !v6 {
        // SetIpInterfaceEntry rejects IPv4 rows with a non-zero site prefix.
        r.SitePrefixLength = 0;
    }
    // SAFETY: `r` was filled by GetIpInterfaceEntry and modified in place.
    win(
        unsafe { SetIpInterfaceEntry(&mut r) },
        "SetIpInterfaceEntry",
    )
}

/// A route VoidWire added.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WinRoute {
    pub luid: u64,
    pub dest: IpCidr,
    pub next_hop: Option<IpAddr>,
}

/// Split default routes over the tunnel plus pinned host routes.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SplitRoutes {
    pub added: Vec<WinRoute>,
}

impl SplitRoutes {
    pub fn install(tunnel_luid: u64, pinned: &[IpAddr], include_v6: bool) -> Result<Self> {
        let mut me = Self::default();
        let mut pins = pinned.to_vec();
        pins.sort();
        pins.dedup();
        // Resolve the physical path for every endpoint before touching routes.
        let mut plan = Vec::new();
        for ip in pins {
            let (luid, nh) = best_route(ip)?;
            plan.push(WinRoute {
                luid,
                dest: IpCidr::host(ip),
                next_hop: nh,
            });
        }
        for dest in split_default_prefixes(include_v6) {
            plan.push(WinRoute {
                luid: tunnel_luid,
                dest,
                next_hop: None,
            });
        }
        for r in plan {
            if let Err(e) = add_route(r.luid, r.dest, r.next_hop, 0) {
                let _ = me.restore();
                return Err(e);
            }
            me.added.push(r);
        }
        tracing::debug!(routes = me.added.len(), "split routes installed");
        Ok(me)
    }

    pub fn restore(&mut self) -> Result<()> {
        while let Some(r) = self.added.pop() {
            delete_route(r.luid, r.dest, r.next_hop)?;
        }
        Ok(())
    }
}
