//! Gateway / transport optimizer (ARCHITECTURE.md §10, PROMPT.md §A.4).
//!
//! 1. [`build_candidates`]: imported nodes × their transports + a sample of
//!    WARP anycast endpoints, filtered by profile, country and transport.
//! 2. [`probe_all`]: real probes with bounded concurrency and timeouts —
//!    transport connect + WireGuard handshake (3 attempts), 20 in-tunnel ICMP
//!    echoes (RTT / jitter / loss) to the node gateway (or 1.1.1.1 through
//!    WARP / generic servers) and a packet-train dispersion bandwidth estimate.
//! 3. [`network_verdict`]: DPI inference from which transports failed.
//! 4. [`rank_paths`]: hop selection per profile, scored with
//!    `vw_core::probe::score`, then [`mtu_for`] / MSS.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use vw_core::config::{
    Endpoint, NodeDescriptor, NodeKind, NodeRole, Profile, TransportKind, WarpAccount,
};
use vw_core::consts::{
    mss_for_mtu, BASE_TUNNEL_MTU, NODE_GATEWAY_V4, PROVISIONAL_V4, SAFE_TUNNEL_MTU,
};
use vw_core::probe::{score, NetworkVerdict, OptimizerDecision, ProbeResult};
use vw_core::secret::Key32;
use vw_core::{Result, VwError};
use vw_firewall::PinnedEndpoint;
use vw_stealth::{ConnectOptions, SocketOptions};
use vw_wg::Peer;

use crate::link::{echo_series, packet_train, DirectSession};
use crate::platform::Platform;

/// Name prefix of WARP hops; `#i` selects `warp::candidate_endpoints()[i]`.
pub const WARP_HOP: &str = "Cloudflare WARP";
/// WARP endpoints probed per run.
pub const WARP_SAMPLE: usize = 4;
/// Concurrent candidate probes.
pub const PROBE_CONCURRENCY: usize = 4;
/// ICMP echoes per candidate.
pub const ECHO_PROBES: u16 = 20;
/// Packets in the dispersion train.
pub const TRAIN_LEN: u16 = 16;
/// Throughput assumed for a reachable gateway that answers no ICMP
/// (generic servers); keeps it selectable but ranked low.
pub const NOMINAL_MBPS: f64 = 10.0;
/// Wire overhead of one nested hop: IPv4 + UDP + WireGuard data header/tag.
pub const NESTED_HOP_OVERHEAD: u16 = 20 + 8 + 32;
/// Background re-evaluation period and the improvement needed to re-switch.
pub const REEVALUATE_EVERY: Duration = Duration::from_secs(30 * 60);
pub const SWITCH_GAIN: f64 = 1.2;

/// One `(gateway, transport)` to probe.
#[derive(Debug, Clone)]
pub struct Candidate {
    /// Hop name (`WARP_HOP#i` for WARP endpoints).
    pub name: String,
    pub node: NodeDescriptor,
    pub endpoint: Endpoint,
    /// Resolved wire address (filled by [`resolve_candidates`]).
    pub addr: Option<SocketAddr>,
}

impl Candidate {
    pub fn transport(&self) -> TransportKind {
        self.endpoint.transport
    }

    pub fn pin(&self) -> Option<PinnedEndpoint> {
        self.addr.map(|a| pin_for(self.transport(), a))
    }
}

/// Firewall pin for a transport's wire address.
pub fn pin_for(t: TransportKind, addr: SocketAddr) -> PinnedEndpoint {
    match t {
        TransportKind::TlsWebsocket => PinnedEndpoint::tcp(addr),
        _ => PinnedEndpoint::udp(addr),
    }
}

/// WARP node with its endpoint replaced by candidate `i`.
pub fn warp_node(acct: &WarpAccount, i: usize) -> (String, NodeDescriptor) {
    let eps = vw_freecloud::warp::candidate_endpoints(acct, WARP_SAMPLE.max(i + 1));
    let mut n = acct.to_node();
    if let Some(ep) = eps.get(i) {
        n.endpoints[0].host = ep.ip().to_string();
        n.endpoints[0].port = ep.port();
    }
    (format!("{WARP_HOP}#{i}"), n)
}

fn country_ok(n: &NodeDescriptor, cc: Option<&str>) -> bool {
    cc.is_none_or(|c| {
        n.country
            .as_deref()
            .is_some_and(|x| x.eq_ignore_ascii_case(c))
    })
}

/// Candidates for `profile`. `f2f` tells which nodes are friends' exits.
pub fn build_candidates(
    nodes: &[NodeDescriptor],
    warp: Option<&WarpAccount>,
    profile: Profile,
    transport: Option<TransportKind>,
) -> Vec<Candidate> {
    let mut v = Vec::new();
    let stealth_only = matches!(profile, Profile::Stealth);
    if !stealth_only {
        if let Some(acct) = warp {
            if transport.is_none_or(|t| t == TransportKind::NativeUdp) {
                for i in 0..WARP_SAMPLE {
                    let (name, node) = warp_node(acct, i);
                    v.push(Candidate {
                        name,
                        endpoint: node.endpoints[0].clone(),
                        node,
                        addr: None,
                    });
                }
            }
        }
    }
    if profile != Profile::Warp {
        for n in nodes.iter().filter(|n| n.kind != NodeKind::Warp) {
            for ep in &n.endpoints {
                if stealth_only && !ep.transport.is_stealth() {
                    continue;
                }
                if transport.is_some_and(|t| t != ep.transport) {
                    continue;
                }
                v.push(Candidate {
                    name: n.name.clone(),
                    node: n.clone(),
                    endpoint: ep.clone(),
                    addr: None,
                });
            }
        }
    }
    v
}

/// Resolve every candidate's wire address (hostnames via the platform's
/// bootstrap resolver). Unresolvable candidates are dropped.
pub async fn resolve_candidates(
    platform: &dyn Platform,
    mut cands: Vec<Candidate>,
    marked: bool,
) -> Vec<Candidate> {
    for c in cands.iter_mut() {
        let host = c.endpoint.host.trim_matches(|x| x == '[' || x == ']');
        c.addr = match host.parse::<IpAddr>() {
            Ok(ip) => Some(SocketAddr::new(ip, c.endpoint.port)),
            Err(_) => platform
                .resolve(host, marked)
                .await
                .ok()
                .and_then(|v| v.into_iter().next())
                .map(|ip| SocketAddr::new(ip, c.endpoint.port)),
        };
    }
    cands.retain(|c| c.addr.is_some());
    cands
}

/// Static key / PSK / reserved bytes for a node.
#[derive(Clone)]
pub struct Keys {
    pub client: Key32,
    pub warp: Option<WarpAccount>,
}

/// Build the WireGuard initiator for `node`.
pub fn peer_for(node: &NodeDescriptor, keys: &Keys) -> Peer {
    let (key, reserved) = match (&node.kind, &keys.warp) {
        (NodeKind::Warp, Some(w)) => (w.private_key.clone(), w.client_id),
        _ => (
            node.client_private
                .clone()
                .unwrap_or_else(|| keys.client.clone()),
            node.reserved.unwrap_or([0; 3]),
        ),
    };
    Peer::new_initiator(key, node.wg_public_key.0, node.static_psk.clone(), reserved)
}

/// Source address and ICMP target inside a node's tunnel before VWCP.
pub fn probe_addrs(node: &NodeDescriptor) -> (Ipv4Addr, Ipv4Addr) {
    match node.kind {
        NodeKind::Voidwire => (PROVISIONAL_V4, NODE_GATEWAY_V4),
        _ => (
            node.static_v4.unwrap_or(PROVISIONAL_V4),
            Ipv4Addr::new(1, 1, 1, 1),
        ),
    }
}

/// Probe one candidate for real.
pub async fn probe_candidate(
    platform: &dyn Platform,
    c: &Candidate,
    keys: &Keys,
    socket: SocketOptions,
) -> ProbeResult {
    let mut r = ProbeResult {
        node_name: c.name.clone(),
        transport: c.transport(),
        reachable: false,
        handshake_ms: None,
        rtt_ms: None,
        jitter_ms: None,
        loss: 1.0,
        throughput_mbps: None,
        post_quantum: c.node.supports_pq(),
        score: 0.0,
    };
    let opts = ConnectOptions {
        amnezia: c.node.amnezia,
        socket,
        resolved: c.addr,
        masque_target: None,
        connect_timeout: Duration::from_secs(5),
    };
    let transport = match tokio::time::timeout(
        Duration::from_secs(6),
        platform.connect(&c.endpoint, &opts),
    )
    .await
    {
        Ok(Ok(t)) => t,
        Ok(Err(e)) => {
            tracing::info!(candidate = %c.name, transport = ?c.transport(), "probe: transport connect failed: {}", vw_firewall::scrub_addresses(&e.to_string()));
            return r;
        }
        Err(_) => {
            tracing::info!(candidate = %c.name, transport = ?c.transport(), "probe: transport connect timed out");
            return r;
        }
    };
    let mut s = DirectSession::new(peer_for(&c.node, keys), transport);
    let hs = match s.handshake(3, Duration::from_secs(2)).await {
        Ok(hs) => hs,
        Err(e) => {
            tracing::info!(candidate = %c.name, transport = ?c.transport(), "probe: WireGuard handshake failed: {}", vw_firewall::scrub_addresses(&e.to_string()));
            s.close().await;
            return r;
        }
    };
    tracing::info!(candidate = %c.name, transport = ?c.transport(), ms = hs.as_millis() as u64, "probe: handshake ok");
    r.reachable = true;
    r.handshake_ms = Some(hs.as_secs_f64() * 1000.0);
    let (src, dst) = probe_addrs(&c.node);
    let id: u16 = rand::random();
    match echo_series(
        &mut s,
        src,
        dst,
        id,
        ECHO_PROBES,
        Duration::from_millis(500),
    )
    .await
    {
        Ok(st) if !st.rtts_ms.is_empty() => {
            r.rtt_ms = st.mean_rtt();
            r.jitter_ms = st.jitter();
            r.loss = st.loss();
            let ip_len = 1200usize.min(c.node_mtu() as usize);
            r.throughput_mbps = packet_train(
                &mut s,
                src,
                dst,
                id.wrapping_add(1),
                TRAIN_LEN,
                ip_len,
                Duration::from_secs(2),
            )
            .await
            .ok()
            .flatten()
            .or(Some(NOMINAL_MBPS));
        }
        _ => {
            r.rtt_ms = r.handshake_ms;
            r.loss = 0.0;
            r.throughput_mbps = Some(NOMINAL_MBPS);
        }
    }
    s.close().await;
    r
}

impl Candidate {
    fn node_mtu(&self) -> u16 {
        BASE_TUNNEL_MTU.saturating_sub(self.transport().overhead())
    }
}

/// Probe all candidates with bounded concurrency; results align with `cands`.
pub async fn probe_all(
    platform: Arc<dyn Platform>,
    cands: &[Candidate],
    keys: &Keys,
) -> Vec<ProbeResult> {
    let socket = platform.socket_options().await;
    let sem = Arc::new(tokio::sync::Semaphore::new(PROBE_CONCURRENCY));
    let mut set = tokio::task::JoinSet::new();
    for (i, c) in cands.iter().cloned().enumerate() {
        let (p, k, s, sem) = (platform.clone(), keys.clone(), socket.clone(), sem.clone());
        set.spawn(async move {
            let _permit = sem.acquire_owned().await;
            (i, probe_candidate(p.as_ref(), &c, &k, s).await)
        });
    }
    let mut out: Vec<Option<ProbeResult>> = vec![None; cands.len()];
    while let Some(j) = set.join_next().await {
        if let Ok((i, r)) = j {
            out[i] = Some(r);
        }
    }
    out.into_iter()
        .zip(cands)
        .map(|(r, c)| {
            r.unwrap_or(ProbeResult {
                node_name: c.name.clone(),
                transport: c.transport(),
                reachable: false,
                handshake_ms: None,
                rtt_ms: None,
                jitter_ms: None,
                loss: 1.0,
                throughput_mbps: None,
                post_quantum: c.node.supports_pq(),
                score: 0.0,
            })
        })
        .collect()
}

/// DPI verdict from per-node transport outcomes.
pub fn network_verdict(results: &[ProbeResult]) -> NetworkVerdict {
    let mut v = NetworkVerdict::default();
    let mut names: Vec<&str> = results.iter().map(|r| r.node_name.as_str()).collect();
    names.sort();
    names.dedup();
    for n in names {
        let get = |t: TransportKind| {
            results
                .iter()
                .find(|r| r.node_name == n && r.transport == t)
                .map(|r| r.reachable)
        };
        let udp = get(TransportKind::NativeUdp);
        let awg = get(TransportKind::AmneziaWg);
        let quic = get(TransportKind::MasqueQuic);
        let tls = get(TransportKind::TlsWebsocket);
        let any_ok = [udp, awg, quic, tls].contains(&Some(true));
        if udp == Some(false) && (tls == Some(true) || quic == Some(true)) {
            v.udp_hostile = true;
        }
        if quic == Some(false) && any_ok {
            v.quic_blocked = true;
        }
        if udp == Some(false) && awg == Some(true) {
            v.wg_signature_filtered = true;
        }
    }
    v
}

/// Re-score results under the verdict (stealth bonus on hostile networks).
pub fn apply_scores(results: &mut [ProbeResult], v: &NetworkVerdict) {
    let hostile = v.udp_hostile || v.wg_signature_filtered;
    for r in results.iter_mut() {
        r.score = if r.reachable {
            score(
                r.throughput_mbps.unwrap_or(0.0),
                r.rtt_ms.unwrap_or(f64::MAX / 4.0),
                r.loss,
                r.post_quantum,
                hostile && r.transport.is_stealth(),
            )
        } else {
            0.0
        };
    }
}

/// Effective inner MTU for a path.
pub fn mtu_for(hops: usize, transport: TransportKind) -> u16 {
    let nested = NESTED_HOP_OVERHEAD.saturating_mul(hops.saturating_sub(1) as u16);
    let mtu = BASE_TUNNEL_MTU
        .saturating_sub(nested)
        .saturating_sub(transport.overhead());
    if hops > 1 || transport.is_stealth() {
        mtu.min(SAFE_TUNNEL_MTU)
    } else {
        mtu
    }
}

/// A selected path: `hops[0]` is the entry (its candidate's transport is the
/// wire transport), the last hop is the exit.
#[derive(Debug, Clone)]
pub struct RankedPath {
    pub hops: Vec<Candidate>,
    pub score: f64,
    pub rtt_ms: f64,
}

impl RankedPath {
    pub fn transport(&self) -> TransportKind {
        self.hops[0].transport()
    }

    pub fn names(&self) -> Vec<String> {
        self.hops.iter().map(|h| h.name.clone()).collect()
    }

    pub fn exit(&self) -> &Candidate {
        &self.hops[self.hops.len() - 1]
    }
}

fn can_enter(n: &NodeDescriptor) -> bool {
    n.kind == NodeKind::Warp || matches!(n.role, NodeRole::Entry | NodeRole::Both)
}

fn can_exit(n: &NodeDescriptor) -> bool {
    n.kind != NodeKind::Warp && matches!(n.role, NodeRole::Exit | NodeRole::Both)
}

/// Rank every admissible path for `profile`, best first.
pub fn rank_paths(
    profile: Profile,
    country: Option<&str>,
    is_f2f: &dyn Fn(&NodeDescriptor) -> bool,
    cands: &[Candidate],
    results: &[ProbeResult],
    verdict: &NetworkVerdict,
) -> Vec<RankedPath> {
    let ok: Vec<(usize, &Candidate, &ProbeResult)> = cands
        .iter()
        .zip(results)
        .enumerate()
        .filter(|(_, (_, r))| r.reachable && r.score > 0.0)
        .map(|(i, (c, r))| (i, c, r))
        .collect();
    // Best measurement per node, for inner hops (always UDP inside the tunnel).
    let best_inner = |name: &str| -> Option<(&Candidate, &ProbeResult)> {
        ok.iter()
            .filter(|(_, c, _)| c.name == name)
            .max_by(|a, b| a.2.score.total_cmp(&b.2.score))
            .map(|(_, c, r)| (*c, *r))
    };
    let mut node_names: Vec<&str> = ok
        .iter()
        .filter(|(_, c, _)| c.node.kind != NodeKind::Warp)
        .map(|(_, c, _)| c.name.as_str())
        .collect();
    node_names.sort();
    node_names.dedup();
    let exits: Vec<&str> = node_names
        .iter()
        .copied()
        .filter(|n| {
            best_inner(n).is_some_and(|(c, _)| {
                can_exit(&c.node)
                    && country_ok(&c.node, country)
                    && (profile != Profile::F2f || is_f2f(&c.node))
            })
        })
        .collect();
    let hostile = verdict.udp_hostile || verdict.wg_signature_filtered;
    let entry_ok = |c: &Candidate| {
        can_enter(&c.node)
            && match profile {
                Profile::Stealth | Profile::MaxAnonymity => c.transport().is_stealth(),
                _ => true,
            }
    };

    let mut paths = Vec::new();
    let mut push = |hops: Vec<(&Candidate, &ProbeResult)>| {
        let rtt: f64 = hops.iter().map(|(_, r)| r.rtt_ms.unwrap_or(0.0)).sum();
        let loss = 1.0 - hops.iter().map(|(_, r)| 1.0 - r.loss).product::<f64>();
        let tput = hops
            .iter()
            .map(|(_, r)| r.throughput_mbps.unwrap_or(0.0))
            .fold(f64::INFINITY, f64::min);
        let exit = hops[hops.len() - 1].0;
        let entry = hops[0].0;
        let s = score(
            tput,
            rtt,
            loss,
            exit.node.supports_pq(),
            hostile && entry.transport().is_stealth(),
        );
        paths.push(RankedPath {
            hops: hops.iter().map(|(c, _)| (*c).clone()).collect(),
            score: s,
            rtt_ms: rtt,
        });
    };

    // Single-hop paths.
    let single_allowed = matches!(
        profile,
        Profile::Auto | Profile::Stealth | Profile::F2f | Profile::Warp
    );
    for (_, c, r) in &ok {
        let warp = c.node.kind == NodeKind::Warp;
        let allowed = match profile {
            Profile::Warp => warp,
            Profile::Auto => warp || exits.contains(&c.name.as_str()),
            Profile::Stealth | Profile::F2f => {
                !warp && entry_ok(c) && exits.contains(&c.name.as_str())
            }
            _ => false,
        };
        if single_allowed && allowed && (warp || country_ok(&c.node, country)) {
            push(vec![(*c, *r)]);
        }
    }
    // Two-hop paths.
    if profile != Profile::Warp {
        for (_, e, er) in ok.iter().filter(|(_, c, _)| entry_ok(c)) {
            for x in &exits {
                if *x == e.name {
                    continue;
                }
                if let Some(xr) = best_inner(x) {
                    push(vec![(*e, *er), xr]);
                }
            }
        }
    }
    // Three-hop paths (Max Anonymity).
    if profile == Profile::MaxAnonymity {
        for (_, e, er) in ok.iter().filter(|(_, c, _)| entry_ok(c)) {
            for m in node_names.iter().filter(|m| **m != e.name) {
                for x in exits.iter().filter(|x| **x != e.name && **x != *m) {
                    if let (Some(mr), Some(xr)) = (best_inner(m), best_inner(x)) {
                        push(vec![(*e, *er), mr, xr]);
                    }
                }
            }
        }
    }
    let want_hops = |p: &RankedPath| match profile {
        Profile::Multihop => p.hops.len() == 2,
        Profile::MaxAnonymity => true,
        _ => true,
    };
    paths.retain(want_hops);
    // Preference order: Auto prefers two hops when a node exists; Max
    // Anonymity prefers the most hops; then score.
    let pref = |p: &RankedPath| -> usize {
        match profile {
            Profile::Auto => {
                usize::from(p.hops.len() == 2) * 2
                    + usize::from(p.hops.len() == 1 && p.hops[0].node.kind != NodeKind::Warp)
            }
            Profile::MaxAnonymity => p.hops.len(),
            _ => 0,
        }
    };
    paths.sort_by(|a, b| pref(b).cmp(&pref(a)).then(b.score.total_cmp(&a.score)));
    paths
}

/// Build the decision shown to users from the best path.
pub fn decision_for(
    path: &RankedPath,
    daita: bool,
    verdict: NetworkVerdict,
    candidates: Vec<ProbeResult>,
) -> OptimizerDecision {
    let mtu = mtu_for(path.hops.len(), path.transport());
    let pq = path.exit().node.supports_pq();
    OptimizerDecision {
        hops: path.names(),
        transport: path.transport(),
        mtu,
        mss_v4: mss_for_mtu(mtu, false),
        daita,
        verdict,
        candidates,
        reason: format!(
            "{} hop(s) via {}; score {:.1}; {}{}",
            path.hops.len(),
            path.transport().label(),
            path.score,
            if pq {
                "post-quantum exit"
            } else {
                "classical WireGuard (no PQ)"
            },
            if verdict.udp_hostile || verdict.wg_signature_filtered {
                "; DPI detected, stealth preferred"
            } else {
                ""
            }
        ),
    }
}

/// Re-create a path from a cached decision (names + transport).
pub fn path_from_decision(d: &OptimizerDecision, cands: &[Candidate]) -> Option<RankedPath> {
    let mut hops = Vec::new();
    for (i, name) in d.hops.iter().enumerate() {
        let c = cands
            .iter()
            .filter(|c| &c.name == name)
            .find(|c| i > 0 || c.transport() == d.transport)
            .or_else(|| cands.iter().find(|c| &c.name == name))?;
        hops.push(c.clone());
    }
    (!hops.is_empty()).then(|| RankedPath {
        hops,
        score: 0.0,
        rtt_ms: 0.0,
    })
}

/// Whether a new best path justifies switching.
pub fn should_switch(current: f64, new: f64) -> bool {
    new >= current * SWITCH_GAIN && new > 0.0
}

/// No admissible path.
pub fn no_path(profile: Profile) -> VwError {
    VwError::Config(format!(
        "no reachable gateway satisfies profile {} (import a node or register WARP)",
        profile.label()
    ))
}

/// Convenience used by tests and the controller.
pub fn best(paths: &[RankedPath], profile: Profile) -> Result<&RankedPath> {
    paths.first().ok_or_else(|| no_path(profile))
}

#[cfg(test)]
mod tests {
    use super::*;
    use vw_core::config::{Bytes32, Endpoint};

    fn node(name: &str, kind: NodeKind, role: NodeRole, ts: &[TransportKind]) -> NodeDescriptor {
        NodeDescriptor {
            version: 1,
            name: name.into(),
            kind,
            role,
            wg_public_key: Bytes32([3; 32]),
            identity_key: (kind == NodeKind::Voidwire).then_some(Bytes32([4; 32])),
            endpoints: ts
                .iter()
                .map(|t| Endpoint {
                    transport: *t,
                    host: "192.0.2.1".into(),
                    port: 443,
                    sni: None,
                    path: None,
                    cert_sha256: None,
                })
                .collect(),
            amnezia: None,
            country: Some("CH".into()),
            ipv6_exit: false,
            static_v4: None,
            static_v6: None,
            reserved: None,
            static_psk: None,
            token_keys: vec![],
            client_private: None,
        }
    }

    fn res(c: &Candidate, ok: bool, mbps: f64, rtt: f64) -> ProbeResult {
        ProbeResult {
            node_name: c.name.clone(),
            transport: c.transport(),
            reachable: ok,
            handshake_ms: ok.then_some(rtt),
            rtt_ms: ok.then_some(rtt),
            jitter_ms: None,
            loss: if ok { 0.0 } else { 1.0 },
            throughput_mbps: ok.then_some(mbps),
            post_quantum: c.node.supports_pq(),
            score: 0.0,
        }
    }

    fn cands_of(nodes: &[NodeDescriptor]) -> Vec<Candidate> {
        build_candidates(nodes, None, Profile::Auto, None)
    }

    #[test]
    fn mtu_math() {
        assert_eq!(mtu_for(1, TransportKind::NativeUdp), 1420);
        assert_eq!(mtu_for(1, TransportKind::AmneziaWg), 1280);
        assert_eq!(mtu_for(2, TransportKind::NativeUdp), 1280);
        assert_eq!(mtu_for(3, TransportKind::TlsWebsocket), 1420 - 120 - 35);
        assert_eq!(
            mss_for_mtu(mtu_for(2, TransportKind::NativeUdp), false),
            1240
        );
    }

    #[test]
    fn verdicts() {
        let n = node("a", NodeKind::Voidwire, NodeRole::Both, &TransportKind::ALL);
        let c = cands_of(&[n]);
        let r: Vec<ProbeResult> = c
            .iter()
            .map(|c| {
                let ok = matches!(
                    c.transport(),
                    TransportKind::AmneziaWg | TransportKind::TlsWebsocket
                );
                res(c, ok, 50.0, 20.0)
            })
            .collect();
        let v = network_verdict(&r);
        assert!(v.udp_hostile && v.quic_blocked && v.wg_signature_filtered);
        let all_ok: Vec<ProbeResult> = c.iter().map(|c| res(c, true, 50.0, 20.0)).collect();
        assert_eq!(network_verdict(&all_ok), NetworkVerdict::default());
    }

    #[test]
    fn auto_prefers_two_hops_and_scores() {
        let a = node(
            "a",
            NodeKind::Voidwire,
            NodeRole::Both,
            &[TransportKind::NativeUdp],
        );
        let b = node(
            "b",
            NodeKind::Voidwire,
            NodeRole::Exit,
            &[TransportKind::NativeUdp],
        );
        let c = cands_of(&[a, b]);
        let mut r: Vec<ProbeResult> = c.iter().map(|c| res(c, true, 100.0, 10.0)).collect();
        let v = network_verdict(&r);
        apply_scores(&mut r, &v);
        let paths = rank_paths(Profile::Auto, None, &|_| false, &c, &r, &v);
        assert_eq!(paths[0].names(), vec!["a", "b"]);
        let d = decision_for(&paths[0], false, v, r.clone());
        assert_eq!(d.mtu, 1280);
        assert_eq!(d.mss_v4, 1240);
        // Multihop never returns single hops; Stealth finds nothing on UDP-only nodes.
        assert!(rank_paths(Profile::Multihop, None, &|_| false, &c, &r, &v)
            .iter()
            .all(|p| p.hops.len() == 2));
        assert!(rank_paths(Profile::Stealth, None, &|_| false, &c, &r, &v).is_empty());
        // F2F: exit must be a friend's node.
        let f = rank_paths(Profile::F2f, None, &|n| n.name == "b", &c, &r, &v);
        assert!(!f.is_empty() && f.iter().all(|p| p.exit().name == "b"));
        // Country filter.
        assert!(rank_paths(Profile::Auto, Some("DE"), &|_| false, &c, &r, &v).is_empty());
    }

    #[test]
    fn faster_path_wins_and_switch_threshold() {
        let a = node(
            "a",
            NodeKind::Voidwire,
            NodeRole::Both,
            &[TransportKind::NativeUdp],
        );
        let b = node(
            "b",
            NodeKind::Voidwire,
            NodeRole::Both,
            &[TransportKind::NativeUdp],
        );
        let c = cands_of(&[a, b]);
        let mut r = vec![res(&c[0], true, 300.0, 20.0), res(&c[1], true, 30.0, 20.0)];
        let v = network_verdict(&r);
        apply_scores(&mut r, &v);
        assert!(r[0].score > r[1].score);
        let p = rank_paths(Profile::Stealth, None, &|_| false, &c, &r, &v);
        assert!(p.is_empty());
        assert!(should_switch(10.0, 12.0));
        assert!(!should_switch(10.0, 11.9));
    }

    #[test]
    fn max_anonymity_uses_three_stealth_hops() {
        let ts = [TransportKind::NativeUdp, TransportKind::TlsWebsocket];
        let nodes: Vec<_> = ["a", "b", "c"]
            .iter()
            .map(|n| node(n, NodeKind::Voidwire, NodeRole::Both, &ts))
            .collect();
        let c = cands_of(&nodes);
        let mut r: Vec<ProbeResult> = c.iter().map(|c| res(c, true, 80.0, 15.0)).collect();
        let v = network_verdict(&r);
        apply_scores(&mut r, &v);
        let p = rank_paths(Profile::MaxAnonymity, None, &|_| false, &c, &r, &v);
        assert_eq!(p[0].hops.len(), 3);
        assert!(p[0].transport().is_stealth());
        let d = decision_for(&p[0], true, v, vec![]);
        let back = path_from_decision(&d, &c).unwrap();
        assert_eq!(back.names(), p[0].names());
        assert_eq!(back.transport(), p[0].transport());
    }
}
