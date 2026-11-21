//! Workspace-wide constants. Never hard-code these values elsewhere.

use std::net::{Ipv4Addr, Ipv6Addr};

/// Firewall mark ("VOID") applied to the daemon's own outbound sockets.
pub const FW_MARK: u32 = 0x564f_4944;
/// Dedicated policy-routing table (Linux).
pub const ROUTE_TABLE: u32 = 51820;
/// Priority of the VoidWire `ip rule` entries (Linux).
pub const RULE_PREF: u32 = 50;
/// Logical tunnel interface name.
pub const TUN_NAME: &str = "vw0";

/// Local encrypted DNS vault (intercepted in userspace, never leaves the host).
pub const DNS_VAULT_V4: Ipv4Addr = Ipv4Addr::new(100, 64, 0, 1);
pub const DNS_VAULT_V6: Ipv6Addr = Ipv6Addr::new(0xfd00, 0x564f, 0x4944, 0, 0, 0, 0, 1);
pub const DNS_PORT: u16 = 53;
pub const DOT_PORT: u16 = 853;

/// Gateway address of a `voidwire-node` inside the tunnel.
pub const NODE_GATEWAY_V4: Ipv4Addr = Ipv4Addr::new(100, 96, 0, 1);
pub const NODE_GATEWAY_V6: Ipv6Addr = Ipv6Addr::new(0xfd00, 0x564f, 0x4944, 1, 0, 0, 0, 1);
/// Client address pool handed out by nodes.
pub const CLIENT_POOL_V4: (Ipv4Addr, u8) = (Ipv4Addr::new(100, 96, 0, 0), 12);
pub const CLIENT_POOL_V6: (Ipv6Addr, u8) =
    (Ipv6Addr::new(0xfd00, 0x564f, 0x4944, 1, 0, 0, 0, 0), 64);
/// Source address used before VWCP assigns a real one.
pub const PROVISIONAL_V4: Ipv4Addr = Ipv4Addr::new(100, 111, 255, 254);

/// In-tunnel PQ control protocol port on the node gateway.
pub const VWCP_PORT: u16 = 51821;
/// PQ pre-shared key rotation interval.
pub const PQ_ROTATE_SECS: u64 = 120;

/// RFC 5389 STUN magic cookie.
pub const STUN_MAGIC: u32 = 0x2112_A442;

/// Default WireGuard MTU and the conservative MTU for nested / stealth paths.
pub const BASE_TUNNEL_MTU: u16 = 1420;
pub const SAFE_TUNNEL_MTU: u16 = 1280;
/// DAITA packet size buckets.
pub const DAITA_BUCKETS: [u16; 5] = [128, 256, 512, 1024, 1280];
/// Normalised outbound TTL / hop limit.
pub const TTL_NORMAL: u8 = 64;

pub const DEFAULT_NODE_UDP_PORT: u16 = 51820;
pub const DEFAULT_TLS_PORT: u16 = 443;
pub const DEFAULT_MASQUE_PORT: u16 = 443;

/// Cloudflare WARP consumer API.
pub const WARP_API_BASE: &str = "https://api.cloudflareclient.com/v0a2158";
pub const WARP_ENDPOINT_HOST: &str = "engage.cloudflareclient.com";
pub const WARP_ENDPOINT_PORT: u16 = 2408;

/// Observer address used by leak tests (TEST-NET-3).
pub const LEAK_OBSERVER_V4: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 99);

/// IPC protocol version.
pub const IPC_VERSION: u32 = 1;
/// Maximum IPC frame size.
pub const IPC_MAX_FRAME: usize = 1 << 20;

/// Effective TCP MSS for a given inner MTU.
pub const fn mss_for_mtu(mtu: u16, ipv6: bool) -> u16 {
    if ipv6 {
        mtu.saturating_sub(60)
    } else {
        mtu.saturating_sub(40)
    }
}

/// Smallest DAITA bucket that fits `len`, or `len` itself if larger than all buckets.
pub fn daita_bucket(len: usize) -> usize {
    DAITA_BUCKETS
        .iter()
        .map(|b| *b as usize)
        .find(|b| *b >= len)
        .unwrap_or(len)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mark_spells_void() {
        assert_eq!(&FW_MARK.to_be_bytes(), b"VOID");
    }

    #[test]
    fn mss_values() {
        assert_eq!(mss_for_mtu(1280, false), 1240);
        assert_eq!(mss_for_mtu(1280, true), 1220);
    }

    #[test]
    fn buckets() {
        assert_eq!(daita_bucket(1), 128);
        assert_eq!(daita_bucket(128), 128);
        assert_eq!(daita_bucket(129), 256);
        assert_eq!(daita_bucket(1280), 1280);
        assert_eq!(daita_bucket(1400), 1400);
    }
}
