//! Windows Filtering Platform policy as a pure Rust data model.
//!
//! `render(plan)` produces every filter VoidWire installs; the `cfg(windows)`
//! layer (`crate::windows::wfp`) only converts each [`FilterSpec`] into an
//! `FWPM_FILTER0`. Compiled on every OS so the policy is unit-tested on macOS.
//!
//! WFP arbitration: inside our sublayer the highest-weight matching filter
//! decides; across sublayers a block always beats a permit, so our block-all
//! filters hold even if other software adds permits in its own sublayer.
//!
//! Two filter sets are produced:
//! * **persistent** (`FWPM_FILTER_FLAG_PERSISTENT`) in our provider/sublayer,
//!   surviving daemon crashes and reboots once BFE is running;
//! * **boot-time** (`FWPM_FILTER_FLAG_BOOTTIME`, when `boot_lock`), enforced by
//!   tcpip.sys before BFE starts. Boot-time objects may only reference
//!   built-in objects, so these live in the default sublayer without a
//!   provider and are deleted by their fixed keys.

use std::net::IpAddr;
use std::path::PathBuf;

use vw_core::packet::{PROTO_ICMPV6, PROTO_UDP};

use crate::linux::nft::{ICMPV6_ROUTER_ADVERT, LOCAL_DISCOVERY_PORTS};
use crate::plan::{IpCidr, LockdownPlan};

/// VoidWire WFP provider key.
pub const PROVIDER_KEY: u128 = 0x564f_4944_7766_4f50_9a1c_3e5b_2d71_c0a1;
/// VoidWire WFP sublayer key.
pub const SUBLAYER_KEY: u128 = 0x564f_4944_7766_534c_8b27_41d9_6e0f_52b3;
/// Sublayer weight (maximum: evaluated before lower-weight sublayers).
pub const SUBLAYER_WEIGHT: u16 = u16::MAX;

/// Mirrors of the WFP flag values (checked against windows-sys at compile
/// time on Windows).
pub const FWPM_FILTER_FLAG_PERSISTENT: u32 = 0x0000_0001;
pub const FWPM_FILTER_FLAG_BOOTTIME: u32 = 0x0000_0002;

/// ICMPv6 neighbour discovery types (router solicit, neighbour solicit/advert).
pub const NDP_TYPES_OUT: [u8; 3] = [133, 135, 136];
pub const NDP_TYPES_IN: [u8; 2] = [135, 136];

// Filter weights (0..=15, higher wins inside our sublayer).
pub const W_LOOPBACK: u8 = 15;
pub const W_HARD_BLOCK: u8 = 14;
pub const W_TUNNEL: u8 = 12;
pub const W_PINNED: u8 = 10;
pub const W_INFRA: u8 = 10;
pub const W_LAN: u8 = 8;
pub const W_BLOCK_ALL: u8 = 0;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Layer {
    AleAuthConnectV4,
    AleAuthConnectV6,
    AleAuthRecvAcceptV4,
    AleAuthRecvAcceptV6,
    OutboundTransportV4,
    OutboundTransportV6,
}

impl Layer {
    pub const ALL: [Layer; 6] = [
        Layer::AleAuthConnectV4,
        Layer::AleAuthConnectV6,
        Layer::AleAuthRecvAcceptV4,
        Layer::AleAuthRecvAcceptV6,
        Layer::OutboundTransportV4,
        Layer::OutboundTransportV6,
    ];

    pub fn is_v6(self) -> bool {
        matches!(
            self,
            Layer::AleAuthConnectV6 | Layer::AleAuthRecvAcceptV6 | Layer::OutboundTransportV6
        )
    }

    /// ALE layers carry the application id; transport layers do not.
    pub fn is_ale(self) -> bool {
        !matches!(
            self,
            Layer::OutboundTransportV4 | Layer::OutboundTransportV6
        )
    }

    pub fn is_outbound(self) -> bool {
        !matches!(
            self,
            Layer::AleAuthRecvAcceptV4 | Layer::AleAuthRecvAcceptV6
        )
    }

    /// The `FWPM_LAYER_*` constant name.
    pub fn wfp_name(self) -> &'static str {
        match self {
            Layer::AleAuthConnectV4 => "FWPM_LAYER_ALE_AUTH_CONNECT_V4",
            Layer::AleAuthConnectV6 => "FWPM_LAYER_ALE_AUTH_CONNECT_V6",
            Layer::AleAuthRecvAcceptV4 => "FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4",
            Layer::AleAuthRecvAcceptV6 => "FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6",
            Layer::OutboundTransportV4 => "FWPM_LAYER_OUTBOUND_TRANSPORT_V4",
            Layer::OutboundTransportV6 => "FWPM_LAYER_OUTBOUND_TRANSPORT_V6",
        }
    }

    fn short(self) -> &'static str {
        match self {
            Layer::AleAuthConnectV4 => "connect v4",
            Layer::AleAuthConnectV6 => "connect v6",
            Layer::AleAuthRecvAcceptV4 => "recv-accept v4",
            Layer::AleAuthRecvAcceptV6 => "recv-accept v6",
            Layer::OutboundTransportV4 => "out-transport v4",
            Layer::OutboundTransportV6 => "out-transport v6",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FilterAction {
    Permit,
    Block,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Persistence {
    Persistent,
    BootTime,
}

/// A filter condition. Conditions on different fields are ANDed.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Condition {
    /// `FWPM_CONDITION_FLAGS` has `FWP_CONDITION_FLAG_IS_LOOPBACK`.
    Loopback,
    /// `FWPM_CONDITION_IP_LOCAL_INTERFACE` == NET_LUID.
    LocalInterface(u64),
    /// `FWPM_CONDITION_ALE_APP_ID` of this executable.
    AppId(PathBuf),
    /// `FWPM_CONDITION_IP_REMOTE_ADDRESS` == address.
    RemoteAddr(IpAddr),
    /// `FWPM_CONDITION_IP_REMOTE_ADDRESS` within network.
    RemoteNet(IpCidr),
    /// `FWPM_CONDITION_IP_REMOTE_PORT`.
    RemotePort(u16),
    /// `FWPM_CONDITION_IP_LOCAL_PORT` (also the ICMP type for ICMP traffic).
    LocalPort(u16),
    /// `FWPM_CONDITION_IP_PROTOCOL`.
    Protocol(u8),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FilterSpec {
    /// Deterministic filter key (derived from the filter's content).
    pub key: u128,
    pub name: String,
    pub layer: Layer,
    pub action: FilterAction,
    pub weight: u8,
    pub persistence: Persistence,
    pub conditions: Vec<Condition>,
}

impl FilterSpec {
    fn new(
        name: &str,
        layer: Layer,
        action: FilterAction,
        weight: u8,
        persistence: Persistence,
        conditions: Vec<Condition>,
    ) -> Self {
        let key = filter_key(layer, action, weight, persistence, &conditions);
        Self {
            key,
            name: format!("VoidWire: {name} ({})", layer.short()),
            layer,
            action,
            weight,
            persistence,
            conditions,
        }
    }

    /// `FWPM_FILTER0.flags`.
    pub fn flags(&self) -> u32 {
        match self.persistence {
            Persistence::Persistent => FWPM_FILTER_FLAG_PERSISTENT,
            Persistence::BootTime => FWPM_FILTER_FLAG_BOOTTIME,
        }
    }

    /// Persistent filters live in our provider + sublayer; boot-time ones in
    /// the default sublayer without a provider.
    pub fn in_our_sublayer(&self) -> bool {
        self.persistence == Persistence::Persistent
    }
}

/// BLAKE3 of a canonical description, truncated to 128 bits.
fn filter_key(
    layer: Layer,
    action: FilterAction,
    weight: u8,
    persistence: Persistence,
    conditions: &[Condition],
) -> u128 {
    let desc = format!("{layer:?}|{action:?}|{weight}|{persistence:?}|{conditions:?}");
    let mut h = blake3::Hasher::new_derive_key("voidwire wfp filter key v1");
    h.update(desc.as_bytes());
    let out = h.finalize();
    let mut b = [0u8; 16];
    b.copy_from_slice(&out.as_bytes()[..16]);
    u128::from_be_bytes(b)
}

fn block_all(layer: Layer, persistence: Persistence) -> FilterSpec {
    FilterSpec::new(
        "block all",
        layer,
        FilterAction::Block,
        W_BLOCK_ALL,
        persistence,
        Vec::new(),
    )
}

fn permit_loopback(layer: Layer, persistence: Persistence) -> FilterSpec {
    FilterSpec::new(
        "permit loopback",
        layer,
        FilterAction::Permit,
        W_LOOPBACK,
        persistence,
        vec![Condition::Loopback],
    )
}

fn permit_dhcp(layer: Layer, persistence: Persistence) -> FilterSpec {
    let (client, server) = if layer.is_v6() { (546, 547) } else { (68, 67) };
    FilterSpec::new(
        if layer.is_v6() {
            "permit DHCPv6"
        } else {
            "permit DHCP"
        },
        layer,
        FilterAction::Permit,
        W_INFRA,
        persistence,
        vec![
            Condition::Protocol(PROTO_UDP),
            Condition::LocalPort(client),
            Condition::RemotePort(server),
        ],
    )
}

/// Key of the persistent block-all filter at a layer (plan-independent; used
/// to verify kernel state).
pub fn block_all_key(layer: Layer) -> u128 {
    block_all(layer, Persistence::Persistent).key
}

/// Boot-time filters: loopback + DHCPv4 permits and block-all at the four ALE
/// layers. Plan-independent, so their keys are fixed.
pub fn render_boot_time() -> Vec<FilterSpec> {
    let mut v = Vec::new();
    for layer in Layer::ALL.into_iter().filter(|l| l.is_ale()) {
        v.push(permit_loopback(layer, Persistence::BootTime));
        if !layer.is_v6() {
            v.push(permit_dhcp(layer, Persistence::BootTime));
        }
        v.push(block_all(layer, Persistence::BootTime));
    }
    v
}

/// Every boot-time filter key (deleted on disarm whether or not installed).
pub fn boot_time_keys() -> Vec<u128> {
    render_boot_time().into_iter().map(|f| f.key).collect()
}

/// Persistent filters for `plan`.
pub fn render_persistent(plan: &LockdownPlan) -> Vec<FilterSpec> {
    use Persistence::Persistent as P;
    let s = &plan.settings;
    let pinned = plan.sorted_pinned();
    let lan = plan.effective_lan();
    let mut v = Vec::new();
    for layer in Layer::ALL {
        v.push(permit_loopback(layer, P));

        if s.block_mdns_netbios && layer.is_outbound() {
            for port in LOCAL_DISCOVERY_PORTS {
                v.push(FilterSpec::new(
                    &format!("block local discovery port {port}"),
                    layer,
                    FilterAction::Block,
                    W_HARD_BLOCK,
                    P,
                    vec![Condition::RemotePort(port)],
                ));
            }
        }
        if s.block_router_adverts && layer == Layer::AleAuthRecvAcceptV6 {
            v.push(FilterSpec::new(
                "block router advertisements",
                layer,
                FilterAction::Block,
                W_HARD_BLOCK,
                P,
                vec![
                    Condition::Protocol(PROTO_ICMPV6),
                    Condition::LocalPort(u16::from(ICMPV6_ROUTER_ADVERT)),
                ],
            ));
        }

        if let Some(t) = &plan.tunnel {
            if let Some(luid) = t.luid {
                if !layer.is_v6() || t.v6.is_some() {
                    v.push(FilterSpec::new(
                        "permit tunnel interface",
                        layer,
                        FilterAction::Permit,
                        W_TUNNEL,
                        P,
                        vec![Condition::LocalInterface(luid)],
                    ));
                }
            }
        }

        for ep in pinned.iter().filter(|e| e.addr.is_ipv6() == layer.is_v6()) {
            let mut c = Vec::new();
            if layer.is_ale() {
                if let Some(exe) = &plan.daemon_exe {
                    c.push(Condition::AppId(exe.clone()));
                }
            }
            c.push(Condition::RemoteAddr(ep.addr.ip()));
            c.push(Condition::RemotePort(ep.addr.port()));
            c.push(Condition::Protocol(ep.proto.number()));
            v.push(FilterSpec::new(
                "permit pinned endpoint",
                layer,
                FilterAction::Permit,
                W_PINNED,
                P,
                c,
            ));
        }

        if !layer.is_v6() || !s.strict_ipv6 {
            v.push(permit_dhcp(layer, P));
        }

        if layer.is_v6() && plan.has_v6_pinned() {
            let types: &[u8] = if layer.is_outbound() {
                &NDP_TYPES_OUT
            } else {
                &NDP_TYPES_IN
            };
            for t in types {
                v.push(FilterSpec::new(
                    &format!("permit neighbour discovery type {t}"),
                    layer,
                    FilterAction::Permit,
                    W_INFRA,
                    P,
                    vec![
                        Condition::Protocol(PROTO_ICMPV6),
                        Condition::LocalPort(u16::from(*t)),
                    ],
                ));
            }
        }

        for net in lan.iter().filter(|n| n.is_ipv4() != layer.is_v6()) {
            v.push(FilterSpec::new(
                "permit LAN",
                layer,
                FilterAction::Permit,
                W_LAN,
                P,
                vec![Condition::RemoteNet(*net)],
            ));
        }

        v.push(block_all(layer, P));
    }
    v
}

/// Complete filter set for `plan` (persistent, plus boot-time when enabled).
pub fn render(plan: &LockdownPlan) -> Vec<FilterSpec> {
    let mut v = render_persistent(plan);
    if plan.settings.boot_lock {
        v.extend(render_boot_time());
    }
    v
}

/// 128-bit key as a canonical GUID string (for diagnostics).
pub fn guid_string(k: u128) -> String {
    let b = k.to_be_bytes();
    format!(
        "{:08x}-{:04x}-{:04x}-{:04x}-{:012x}",
        u32::from_be_bytes([b[0], b[1], b[2], b[3]]),
        u16::from_be_bytes([b[4], b[5]]),
        u16::from_be_bytes([b[6], b[7]]),
        u16::from_be_bytes([b[8], b[9]]),
        k & 0xffff_ffff_ffff
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plan::test_plans;
    use std::collections::HashSet;

    fn blocks_at(v: &[FilterSpec], layer: Layer, p: Persistence) -> usize {
        v.iter()
            .filter(|f| {
                f.layer == layer
                    && f.action == FilterAction::Block
                    && f.conditions.is_empty()
                    && f.persistence == p
            })
            .count()
    }

    #[test]
    fn block_all_at_v4_and_v6_layers() {
        let v = render(&test_plans::full());
        for layer in Layer::ALL {
            assert_eq!(
                blocks_at(&v, layer, Persistence::Persistent),
                1,
                "{layer:?}"
            );
            assert!(v
                .iter()
                .any(|f| f.layer == layer && f.conditions == [Condition::Loopback]));
        }
        for layer in [
            Layer::AleAuthConnectV4,
            Layer::AleAuthConnectV6,
            Layer::AleAuthRecvAcceptV4,
            Layer::AleAuthRecvAcceptV6,
        ] {
            assert_eq!(blocks_at(&v, layer, Persistence::BootTime), 1, "{layer:?}");
        }
        let block = v
            .iter()
            .find(|f| f.key == block_all_key(Layer::AleAuthConnectV6))
            .unwrap();
        assert_eq!(block.weight, W_BLOCK_ALL);
    }

    #[test]
    fn persistent_and_boot_time_flags() {
        let v = render(&test_plans::full());
        assert!(v.iter().any(|f| f.flags() == FWPM_FILTER_FLAG_PERSISTENT));
        assert!(v.iter().any(|f| f.flags() == FWPM_FILTER_FLAG_BOOTTIME));
        assert!(v.iter().all(|f| f.flags() == 1 || f.flags() == 2));
        assert!(v
            .iter()
            .filter(|f| f.persistence == Persistence::BootTime)
            .all(|f| !f.in_our_sublayer()));
        let mut p = test_plans::full();
        p.settings.boot_lock = false;
        assert!(render(&p)
            .iter()
            .all(|f| f.persistence == Persistence::Persistent));
    }

    #[test]
    fn pinned_endpoint_permits_use_app_id_on_ale_only() {
        let mut p = test_plans::full();
        p.daemon_exe = Some(PathBuf::from(r"C:\Program Files\VoidWire\voidwired.exe"));
        let v = render(&p);
        let pinned: Vec<&FilterSpec> = v
            .iter()
            .filter(|f| f.conditions.contains(&Condition::RemotePort(51820)))
            .collect();
        assert_eq!(pinned.len(), 3); // connect, recv-accept, transport (v4)
        for f in &pinned {
            assert!(!f.layer.is_v6());
            assert_eq!(f.action, FilterAction::Permit);
            assert!(f
                .conditions
                .contains(&Condition::RemoteAddr("198.51.100.7".parse().unwrap())));
            assert!(f.conditions.contains(&Condition::Protocol(17)));
            assert_eq!(
                f.conditions
                    .iter()
                    .any(|c| matches!(c, Condition::AppId(_))),
                f.layer.is_ale()
            );
        }
        let tcp6 = v
            .iter()
            .filter(|f| f.conditions.contains(&Condition::RemotePort(443)) && f.layer.is_v6())
            .count();
        assert_eq!(tcp6, 3);
    }

    #[test]
    fn tunnel_permit_by_luid_v4_only_without_tunnel_v6() {
        let v = render(&test_plans::full());
        let luid = Condition::LocalInterface(0x0006_0000_0100_0000);
        let layers: Vec<Layer> = v
            .iter()
            .filter(|f| f.conditions.contains(&luid))
            .map(|f| f.layer)
            .collect();
        assert_eq!(layers.len(), 3);
        assert!(layers.iter().all(|l| !l.is_v6()));
    }

    #[test]
    fn local_discovery_blocks_outweigh_tunnel() {
        let v = render(&test_plans::full());
        let mdns: Vec<&FilterSpec> = v
            .iter()
            .filter(|f| f.conditions == [Condition::RemotePort(5353)])
            .collect();
        assert_eq!(mdns.len(), 4); // connect + transport, v4 + v6
        assert!(mdns
            .iter()
            .all(|f| f.action == FilterAction::Block && f.weight > W_TUNNEL));
        for port in [137u16, 138, 5355] {
            assert!(v
                .iter()
                .any(|f| f.conditions == [Condition::RemotePort(port)]));
        }
        assert!(v.iter().any(|f| f.layer == Layer::AleAuthRecvAcceptV6
            && f.action == FilterAction::Block
            && f.conditions.contains(&Condition::LocalPort(134))));
    }

    #[test]
    fn boot_lock_plan_blocks_everything_but_pinned() {
        let v = render_persistent(&test_plans::boot());
        let permits: HashSet<&str> = v
            .iter()
            .filter(|f| f.action == FilterAction::Permit)
            .map(|f| f.name.split(" (").next().unwrap())
            .collect();
        let expected: HashSet<&str> = [
            "VoidWire: permit loopback",
            "VoidWire: permit pinned endpoint",
            "VoidWire: permit DHCP",
        ]
        .into_iter()
        .collect();
        assert_eq!(permits, expected);
    }

    #[test]
    fn keys_unique_and_deterministic() {
        let a = render(&test_plans::full());
        let keys: HashSet<u128> = a.iter().map(|f| f.key).collect();
        assert_eq!(keys.len(), a.len());
        let mut p = test_plans::full();
        p.pinned.reverse();
        assert_eq!(render(&p), a);
        assert!(!keys.contains(&PROVIDER_KEY) && !keys.contains(&SUBLAYER_KEY));
        assert_eq!(boot_time_keys(), boot_time_keys());
        assert_eq!(
            guid_string(PROVIDER_KEY),
            "564f4944-7766-4f50-9a1c-3e5b2d71c0a1"
        );
    }

    #[test]
    fn lan_permits_only_when_allowed() {
        let mut p = test_plans::full();
        assert!(!render(&p).iter().any(|f| f.name.contains("LAN")));
        p.settings.allow_lan = true;
        let v = render(&p);
        assert!(v
            .iter()
            .any(|f| f.conditions == [Condition::RemoteNet("192.168.0.0/16".parse().unwrap())]));
        assert!(!v.iter().any(|f| f.name.contains("LAN") && f.layer.is_v6()));
    }
}
