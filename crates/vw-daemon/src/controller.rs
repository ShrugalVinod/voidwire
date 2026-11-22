//! The Iron Dome driver: owns the FSM and runs the client lifecycle.
//!
//! Invariants enforced here (ARCHITECTURE.md §2, CLAUDE.md):
//! * the firewall is armed (and the boot-lock marker written) before any
//!   resolution, probe or connection happens;
//! * the pipeline gate opens only in `TunnelActive` / `KeyRotating`, and
//!   `TunnelActive` is entered only from `CanaryAuditing` after a passing
//!   canary;
//! * every failure (handshake, canary, rotation, transport loss, link loss,
//!   panic) moves to `FailsafeLockdown` and leaves the firewall armed;
//! * only an explicit user request (`Disarm`, or `Down` without
//!   `keep_lockdown`) removes the lockdown.

use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock, Weak};
use std::time::{Duration, Instant};

use tokio_util::sync::CancellationToken;
use vw_core::config::{NodeDescriptor, NodeKind, Profile, Settings, TransportKind};
use vw_core::ipc::{
    AuditCheck, AuditReport, DaemonEvent, ExecTicket, FirewallMatrix, HopInfo, NodeSummary,
    StatusReport,
};
use vw_core::probe::OptimizerDecision;
use vw_core::state::{DomeEvent, DomeState, IronDome};
use vw_core::telemetry::Counters;
use vw_core::uri::{decode_node, F2F_PREFIX, NODE_PREFIX};
use vw_core::{Result, VwError};
use vw_dns::DnsVault;
use vw_firewall::{FirewallBackend, LockdownPlan, PinnedEndpoint, TunnelIface};
use vw_leakaudit::canary::{ip_hash, run_canary, trace_field, CanaryContext, ExitIdentity};

use crate::canary_hooks::DaemonHooks;
use crate::events::EventHub;
use crate::link::{vwcp_handshake, vwcp_redeem, DirectSession};
use crate::optimizer::{self, Candidate, Keys, RankedPath};
use crate::pipeline::Gate;
use crate::platform::Platform;
use crate::store::Store;
use crate::tunnel::{initial_epoch, ActiveTunnel, TunnelSpec};
use crate::util::{ephemeral_port, unix_now};

/// No authenticated packet for this long → link lost (3 × keepalive).
pub const LINK_TIMEOUT: Duration = Duration::from_secs(30);
/// Link / default-route polling period.
pub const MONITOR_EVERY: Duration = Duration::from_secs(2);
/// Cached decisions younger than this are reused without probing.
pub const DECISION_MAX_AGE: u64 = 30 * 60;
/// Session tokens requested per invite redemption.
pub const REDEEM_TOKENS: u8 = 32;

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

#[derive(Debug, Clone, Copy)]
struct UpParams {
    profile: Profile,
    country: Option<[u8; 2]>,
    transport: Option<TransportKind>,
    /// BLAKE3 of the chosen gateway's name (keeps the struct `Copy`).
    gateway: Option<[u8; 32]>,
}

/// Gateway name that selects Cloudflare WARP itself.
pub const WARP_GATEWAY: &str = "Cloudflare WARP";

fn gateway_id(name: &str) -> [u8; 32] {
    *blake3::hash(name.as_bytes()).as_bytes()
}

impl UpParams {
    fn country(&self) -> Option<String> {
        self.country
            .map(|c| String::from_utf8_lossy(&c).into_owned())
    }
}

#[derive(Default)]
struct Info {
    desired: Option<UpParams>,
    profile: Option<Profile>,
    decision: Option<OptimizerDecision>,
    ranked: Vec<RankedPath>,
    baseline_ip: Option<[u8; 32]>,
    network_fp: Option<String>,
    last_optimize: Option<Instant>,
}

/// The daemon core. Shared as `Arc<Controller>`.
pub struct Controller {
    platform: Arc<dyn Platform>,
    dome: Mutex<IronDome>,
    gate: Arc<Gate>,
    firewall: Arc<Mutex<Box<dyn FirewallBackend>>>,
    plan: Mutex<Option<LockdownPlan>>,
    pub events: EventHub,
    pub counters: Arc<Counters>,
    store: tokio::sync::Mutex<Store>,
    ops: tokio::sync::Mutex<()>,
    tunnel: tokio::sync::Mutex<Option<ActiveTunnel>>,
    vault: Mutex<Option<Arc<DnsVault>>>,
    cancel: Mutex<CancellationToken>,
    info: Mutex<Info>,
    generation: AtomicU64,
    ip_salt: [u8; 32],
    started: Instant,
    /// Upper bound for each canary hook call.
    pub canary_timeout: Duration,
}

static GLOBAL: OnceLock<Mutex<Weak<Controller>>> = OnceLock::new();

/// Install a panic hook that fires `Fault` (firewall stays armed).
pub fn install_panic_hook(c: &Arc<Controller>) {
    *lock(GLOBAL.get_or_init(|| Mutex::new(Weak::new()))) = Arc::downgrade(c);
    let prev = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        if let Some(c) = GLOBAL
            .get()
            .and_then(|g| g.try_lock().ok().and_then(|w| w.upgrade()))
        {
            c.fault_from_panic();
        }
        prev(info);
    }));
}

impl Controller {
    pub fn new(platform: Arc<dyn Platform>, store: Store) -> Arc<Self> {
        Self::with_events(platform, store, EventHub::new())
    }

    /// Like [`Controller::new`] with an existing event hub (log forwarding).
    pub fn with_events(platform: Arc<dyn Platform>, store: Store, events: EventHub) -> Arc<Self> {
        let firewall = Arc::new(Mutex::new(platform.firewall()));
        let c = Arc::new(Self {
            platform,
            dome: Mutex::new(IronDome::new()),
            gate: Arc::new(Gate::default()),
            firewall,
            plan: Mutex::new(None),
            events,
            counters: Arc::new(Counters::default()),
            store: tokio::sync::Mutex::new(store),
            ops: tokio::sync::Mutex::new(()),
            tunnel: tokio::sync::Mutex::new(None),
            vault: Mutex::new(None),
            cancel: Mutex::new(CancellationToken::new()),
            info: Mutex::new(Info::default()),
            generation: AtomicU64::new(0),
            ip_salt: rand::random(),
            started: Instant::now(),
            canary_timeout: Duration::from_secs(8),
        });
        c.spawn_telemetry();
        c
    }

    pub fn state(&self) -> DomeState {
        lock(&self.dome).state()
    }

    pub fn history(&self) -> Vec<(DomeState, DomeEvent, DomeState)> {
        lock(&self.dome).history().to_vec()
    }

    pub fn gate(&self) -> &Arc<Gate> {
        &self.gate
    }

    fn marker(&self) -> PathBuf {
        self.platform.state_dir().join("lockdown.armed")
    }

    /// Fire an FSM event, update the gate and broadcast the change.
    fn fire(&self, ev: DomeEvent) -> Result<DomeState> {
        let (from, to) = {
            let mut d = lock(&self.dome);
            let from = d.state();
            let to = d.fire(ev)?;
            self.gate.set_open(to.traffic_allowed());
            (from, to)
        };
        if from != to {
            tracing::info!(from = ?from, to = ?to, event = ?ev, "iron dome transition");
            self.events.emit(DaemonEvent::StateChanged { from, to });
        }
        Ok(to)
    }

    fn fault_from_panic(&self) {
        let fired = match self.dome.try_lock() {
            Ok(mut d) => {
                let from = d.state();
                let r = d.fire(DomeEvent::Fault).ok().map(|to| (from, to));
                self.gate.set_open(d.state().traffic_allowed());
                r
            }
            Err(_) => {
                self.gate.set_open(false);
                None
            }
        };
        if let Some((from, to)) = fired {
            self.events.emit(DaemonEvent::StateChanged { from, to });
        }
    }

    // ───────────────────────── firewall ─────────────────────────

    async fn settings(&self) -> Settings {
        self.store.lock().await.data.client.settings.clone()
    }

    async fn base_plan(&self) -> LockdownPlan {
        let mut p = LockdownPlan::new(self.settings().await.firewall);
        p.daemon_exe = self.platform.daemon_exe();
        p
    }

    async fn apply_plan(&self, plan: LockdownPlan) -> Result<()> {
        let arm = lock(&self.plan).is_none();
        let fw = self.firewall.clone();
        let p2 = plan.clone();
        tokio::task::spawn_blocking(move || {
            let mut f = lock(&fw);
            if arm {
                f.arm(&p2)
            } else {
                f.update(&p2)
            }
        })
        .await
        .map_err(|e| VwError::Firewall(format!("firewall worker: {e}")))??;
        *lock(&self.plan) = Some(plan);
        Ok(())
    }

    /// Current plan with `pins` and an optional tunnel.
    async fn update_pins(
        &self,
        pins: Vec<PinnedEndpoint>,
        tunnel: Option<TunnelIface>,
    ) -> Result<()> {
        let mut p = self.base_plan().await;
        p.pinned = pins;
        p.tunnel = tunnel;
        self.apply_plan(p).await
    }

    fn current_plan(&self) -> Option<LockdownPlan> {
        lock(&self.plan).clone()
    }

    /// Arm the lockdown (no pins) and write the boot-lock marker.
    async fn engage_lock(&self) -> Result<()> {
        let plan = self.base_plan().await;
        let boot = plan.settings.boot_lock;
        self.apply_plan(plan).await?;
        if boot {
            crate::util::write_protected(&self.marker(), b"armed\n", crate::util::Access::Private)?;
        }
        Ok(())
    }

    // ───────────────────────── startup ─────────────────────────

    /// Daemon start: boot lock when the marker exists, then reconnect.
    pub async fn start(self: &Arc<Self>) -> Result<()> {
        self.ensure_vault().await;
        if self.marker().exists() {
            tracing::info!("boot lock marker present: arming lockdown before anything else");
            self.fire(DomeEvent::Arm)?;
            if let Err(e) = self.engage_lock().await {
                tracing::error!(error = %e, "boot lock failed");
                self.fire(DomeEvent::Fault)?;
                return Err(e);
            }
            let profile = self.settings().await.default_profile;
            let me = self.clone();
            tokio::spawn(async move {
                if let Err(e) = me.up(profile, None, None, None).await {
                    tracing::warn!(error = %e, "automatic reconnect after boot lock failed");
                }
            });
        }
        Ok(())
    }

    async fn ensure_vault(self: &Arc<Self>) -> Option<Arc<DnsVault>> {
        if let Some(v) = lock(&self.vault).clone() {
            return Some(v);
        }
        let settings = self.settings().await;
        let up = vw_dns::UpstreamOptions::production()
            .and_then(|o| vw_dns::upstream::from_settings(&settings.dns, &o));
        let up = match up {
            Ok(u) => u,
            Err(e) => {
                tracing::warn!(error = %e, "DNS vault upstreams unavailable");
                return None;
            }
        };
        let v = Arc::new(DnsVault::new(
            settings.dns.clone(),
            Arc::new(up),
            self.counters.clone(),
        ));
        v.set_inspector(settings.live_inspector);
        *lock(&self.vault) = Some(v.clone());
        self.spawn_inspector(v.clone());
        Some(v)
    }

    fn spawn_inspector(self: &Arc<Self>, v: Arc<DnsVault>) {
        let mut rx = v.subscribe();
        let me = Arc::downgrade(self);
        tokio::spawn(async move {
            loop {
                match rx.recv().await {
                    Ok(ev) => {
                        let Some(c) = me.upgrade() else { return };
                        if c.store.lock().await.data.client.settings.live_inspector {
                            c.events.emit(DaemonEvent::DnsInspect {
                                name: ev.name,
                                category: ev.category,
                                blocked: ev.blocked,
                            });
                        }
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(_) => return,
                }
            }
        });
    }

    fn spawn_telemetry(self: &Arc<Self>) {
        let me = Arc::downgrade(self);
        if tokio::runtime::Handle::try_current().is_err() {
            return;
        }
        tokio::spawn(async move {
            let mut iv = tokio::time::interval(Duration::from_secs(1));
            loop {
                iv.tick().await;
                let Some(c) = me.upgrade() else { return };
                if c.events.has_subscribers() {
                    c.events.emit(DaemonEvent::Telemetry(c.counters.snapshot()));
                }
            }
        });
    }

    fn new_cancel(&self) -> CancellationToken {
        let mut g = lock(&self.cancel);
        g.cancel();
        *g = CancellationToken::new();
        g.clone()
    }

    fn cancel_inflight(&self) {
        lock(&self.cancel).cancel();
    }

    // ───────────────────────── Up ─────────────────────────

    /// Connect with `profile` (cancellable by Down / Disarm / Panic).
    pub async fn up(
        self: &Arc<Self>,
        profile: Profile,
        country: Option<String>,
        transport: Option<TransportKind>,
        gateway: Option<String>,
    ) -> Result<()> {
        let gateway = match gateway.as_deref().map(str::trim).filter(|g| !g.is_empty()) {
            Some(g) => {
                let known = g == WARP_GATEWAY
                    || self
                        .store
                        .lock()
                        .await
                        .data
                        .client
                        .nodes
                        .iter()
                        .any(|n| n.name == g);
                if !known {
                    return Err(VwError::Config(format!("no gateway named '{g}'")));
                }
                Some(gateway_id(g))
            }
            None => None,
        };
        let country = match country {
            Some(c) if c.len() == 2 && c.is_ascii() => {
                let b = c.to_ascii_uppercase().into_bytes();
                Some([b[0], b[1]])
            }
            Some(_) => {
                return Err(VwError::Config(
                    "country must be an ISO 3166 alpha-2 code".into(),
                ))
            }
            None => None,
        };
        let params = UpParams {
            profile,
            country,
            transport,
            gateway,
        };
        lock(&self.info).desired = Some(params);
        let token = self.new_cancel();
        let _ops = self.ops.lock().await;
        tokio::select! {
            r = self.connect_flow(params) => r,
            _ = token.cancelled() => Err(VwError::Config("connect cancelled".into())),
        }
    }

    async fn connect_flow(self: &Arc<Self>, p: UpParams) -> Result<()> {
        // 1. Lock first.
        match self.state() {
            DomeState::Disarmed => {
                // Cloudflare already sees the real IP when WARP is used, so
                // only then is a pre-arm baseline fetched from it.
                let warp = self.store.lock().await.data.client.warp.is_some();
                if warp && matches!(p.profile, Profile::Warp | Profile::Auto) {
                    self.capture_baseline().await;
                }
                self.fire(DomeEvent::Arm)?;
                if let Err(e) = self.engage_lock().await {
                    self.fire(DomeEvent::Fault)?;
                    return Err(e);
                }
                self.fire(DomeEvent::LockEngaged)?;
            }
            DomeState::ArmingBootLock => {
                self.fire(DomeEvent::LockEngaged)?;
            }
            DomeState::FailsafeLockdown => {
                self.fire(DomeEvent::Retry)?;
            }
            DomeState::TunnelActive | DomeState::KeyRotating => {
                self.teardown().await;
                self.fire(DomeEvent::DownKeepLockdown)?;
                self.fire(DomeEvent::Retry)?;
            }
            s => return Err(VwError::Config(format!("cannot connect while {s:?}"))),
        }
        // 2. Handshaking.
        let tunnel = match self.handshake_phase(p).await {
            Ok(t) => t,
            Err(e) => {
                tracing::warn!(error = %e, "handshake failed; failsafe lockdown");
                self.fire(DomeEvent::HandshakeFailed)?;
                return Err(e);
            }
        };
        self.fire(DomeEvent::HandshakeComplete)?;
        // 3. Canary.
        let mut tunnel = tunnel;
        let report = match self.prepare_host(&mut tunnel).await {
            Ok(()) => self.canary(&tunnel).await,
            Err(e) => {
                tracing::warn!(error = %e, "host configuration failed");
                failed_report("host-config", &e.to_string())
            }
        };
        self.events.emit(DaemonEvent::Audit(report.clone()));
        if !report.passed {
            tunnel.shutdown().await;
            let _ = self.platform.restore_routes().await;
            self.fire(DomeEvent::CanaryFailed)?;
            return Err(VwError::Config("canary audit failed; lockdown kept".into()));
        }
        self.fire(DomeEvent::CanaryPassed)?;
        lock(&self.info).profile = Some(p.profile);
        let gen = self.generation.fetch_add(1, Ordering::SeqCst) + 1;
        *self.tunnel.lock().await = Some(tunnel);
        self.spawn_monitor(gen);
        Ok(())
    }

    async fn capture_baseline(&self) {
        match tokio::time::timeout(Duration::from_secs(5), self.platform.https_trace(true)).await {
            Ok(Ok(body)) => {
                if let Some(ip) = trace_field(&body, "ip") {
                    lock(&self.info).baseline_ip = Some(ip_hash(&self.ip_salt, ip));
                }
            }
            _ => tracing::debug!("pre-arm public IP baseline unavailable"),
        }
    }

    async fn keys(&self) -> Keys {
        let s = self.store.lock().await;
        Keys {
            client: s.wg_private(),
            warp: s.data.client.warp.clone(),
        }
    }

    /// Candidates → probes (pinned) → path → tunnel.
    async fn handshake_phase(self: &Arc<Self>, p: UpParams) -> Result<ActiveTunnel> {
        let (path, decision) = self.choose_path(p, None).await?;
        let pin = path.hops[0]
            .pin()
            .ok_or_else(|| VwError::Config("entry unresolved".into()))?;
        self.update_pins(vec![pin], None).await?;
        self.build_tunnel(path, decision.daita, Vec::new()).await
    }

    async fn build_tunnel(
        self: &Arc<Self>,
        path: RankedPath,
        daita: bool,
        known_psks: Vec<(vw_core::config::Bytes32, vw_core::secret::Key32)>,
    ) -> Result<ActiveTunnel> {
        let settings = self.settings().await;
        let tokens = self.tokens_for(&path).await?;
        let mut daita_p = settings.daita.clone();
        daita_p.enabled = true;
        let spec = TunnelSpec {
            mtu: optimizer::mtu_for(path.hops.len(), path.transport()),
            path,
            keys: self.keys().await,
            daita: daita.then_some(daita_p),
            sanitizer: settings.sanitizer,
            block_stun: settings.firewall.block_webrtc_stun,
            vault: self.ensure_vault().await,
            socket: self.platform.socket_options().await,
            tokens,
            known_psks,
        };
        ActiveTunnel::establish(
            self.platform.as_ref(),
            spec,
            self.counters.clone(),
            self.gate.clone(),
        )
        .await
    }

    /// VWCP tokens: a session token for friends' nodes, empty (owner) otherwise.
    async fn tokens_for(&self, path: &RankedPath) -> Result<Vec<Vec<u8>>> {
        let mut s = self.store.lock().await;
        let mut out = Vec::new();
        let mut dirty = false;
        for h in &path.hops {
            let tok = match h.node.identity_key {
                Some(id) if h.node.kind == NodeKind::Voidwire && s.token_count(&id) > 0 => {
                    dirty = true;
                    s.take_token(&id)
                        .map(|t| t.expose().to_vec())
                        .unwrap_or_default()
                }
                _ => Vec::new(),
            };
            out.push(tok);
        }
        if dirty {
            s.save()?;
        }
        Ok(out)
    }

    /// Run the optimizer (or reuse the cached decision) for `p`.
    async fn choose_path(
        self: &Arc<Self>,
        p: UpParams,
        keep_tunnel: Option<&TunnelIface>,
    ) -> Result<(RankedPath, OptimizerDecision)> {
        let (nodes, warp, salt, settings, f2f_ids) = {
            let s = self.store.lock().await;
            let f2f: Vec<_> = s
                .data
                .client
                .f2f_tokens
                .iter()
                .filter(|(_, t)| !t.is_empty())
                .map(|(k, _)| *k)
                .collect();
            (
                s.data.client.nodes.clone(),
                s.data.client.warp.clone(),
                s.salt(),
                s.data.client.settings.clone(),
                f2f,
            )
        };
        if p.profile == Profile::Warp && warp.is_none() {
            return Err(VwError::Config(
                "WARP profile requires RegisterWarp first".into(),
            ));
        }
        let transport = p.transport.or(settings.transport_preference);
        let cands = optimizer::build_candidates(&nodes, warp.as_ref(), p.profile, transport);
        if cands.is_empty() {
            return Err(optimizer::no_path(p.profile));
        }
        // Resolve hostnames through the bootstrap resolver (pinned while armed).
        let needs_dns = cands.iter().any(|c| {
            c.endpoint
                .host
                .trim_matches(['[', ']'])
                .parse::<IpAddr>()
                .is_err()
        });
        let tunnel_pin = keep_tunnel
            .and_then(|_| self.current_plan())
            .map(|p| p.pinned)
            .unwrap_or_default();
        if needs_dns && keep_tunnel.is_none() {
            let pins = vw_freecloud::http::BOOTSTRAP_DOH
                .iter()
                .map(|a| PinnedEndpoint::tcp(*a))
                .collect();
            self.update_pins(pins, None).await?;
        }
        let cands =
            optimizer::resolve_candidates(self.platform.as_ref(), cands, keep_tunnel.is_none())
                .await;
        let daita = settings.daita.enabled || p.profile == Profile::MaxAnonymity;
        let is_f2f = |n: &NodeDescriptor| n.identity_key.is_some_and(|id| f2f_ids.contains(&id));
        let country = p.country();

        // Cached decision for this network.
        let id = self
            .platform
            .network_identity(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)))
            .await;
        let fp = id.fingerprint(&salt);
        lock(&self.info).network_fp = Some(fp.clone());
        let cached = if settings.auto_optimize
            && keep_tunnel.is_none()
            && p.country.is_none()
            && p.gateway.is_none()
        {
            self.store
                .lock()
                .await
                .cached_decision(&fp, DECISION_MAX_AGE)
        } else {
            None
        };
        if let Some(d) = cached {
            if let Some(path) = optimizer::path_from_decision(&d, &cands) {
                let profile_ok = p.profile != Profile::F2f || is_f2f(&path.exit().node);
                if profile_ok {
                    tracing::info!("reusing cached optimizer decision for this network");
                    self.events.emit(DaemonEvent::Decision(d.clone()));
                    lock(&self.info).decision = Some(d.clone());
                    return Ok((path, d));
                }
            }
        }

        // Pin exactly the candidates being probed.
        let mut pins: Vec<PinnedEndpoint> = cands.iter().filter_map(Candidate::pin).collect();
        pins.extend(tunnel_pin);
        self.update_pins(pins, keep_tunnel.cloned()).await?;
        let keys = self.keys().await;
        let mut results = optimizer::probe_all(self.platform.clone(), &cands, &keys).await;
        let verdict = optimizer::network_verdict(&results);
        optimizer::apply_scores(&mut results, &verdict);
        let ranked = optimizer::rank_paths(
            p.profile,
            country.as_deref(),
            &is_f2f,
            &cands,
            &results,
            &verdict,
        );
        let ranked = match p.gateway {
            Some(g) => {
                // Exactly the chosen exit. Direct (fastest) unless the user
                // asked to chain through WARP (Multihop) or more.
                let mut r: Vec<_> = ranked
                    .into_iter()
                    .filter(|path| {
                        let exit = &path.exit().node;
                        let name = if exit.kind == NodeKind::Warp {
                            WARP_GATEWAY
                        } else {
                            exit.name.as_str()
                        };
                        gateway_id(name) == g
                    })
                    .collect();
                if p.profile == Profile::Auto {
                    r.retain(|path| path.hops.len() == 1);
                }
                if r.is_empty() {
                    return Err(VwError::Config(
                        "the chosen gateway did not answer (check the config or try another gateway)".into(),
                    ));
                }
                r
            }
            None => ranked,
        };
        let best = optimizer::best(&ranked, p.profile)?.clone();
        let decision = optimizer::decision_for(&best, daita, verdict, results);
        tracing::info!(
            hops = best.hops.len(),
            transport = best.transport().label(),
            "optimizer decision"
        );
        self.events.emit(DaemonEvent::Decision(decision.clone()));
        {
            let mut s = self.store.lock().await;
            s.cache_decision(fp, decision.clone());
            if let Err(e) = s.save() {
                tracing::warn!(error = %e, "cannot persist optimizer cache");
            }
        }
        let mut info = lock(&self.info);
        info.decision = Some(decision.clone());
        info.ranked = ranked;
        info.last_optimize = Some(Instant::now());
        Ok((best, decision))
    }

    /// CanaryAuditing: OS TUN, firewall with tunnel, vault, routes, system DNS.
    async fn prepare_host(self: &Arc<Self>, t: &mut ActiveTunnel) -> Result<()> {
        let iface = t.attach_os_tun(self.platform.as_ref())?;
        let pin = optimizer::pin_for(t.path.transport(), t.entry_addr);
        self.update_pins(vec![pin], Some(iface.clone())).await?;
        if let Some(v) = self.ensure_vault().await {
            t.vault_servers = self.platform.start_vault(v, &iface).await?;
        }
        self.platform
            .install_routes(&iface, &[t.entry_addr.ip()], t.tun_v6.is_some())
            .await?;
        self.platform.apply_dns(&iface).await?;
        Ok(())
    }

    async fn canary(self: &Arc<Self>, t: &ActiveTunnel) -> AuditReport {
        let exit = &t.path.exit().node;
        let identity = match (exit.kind, exit.identity_key) {
            (NodeKind::Voidwire, Some(id)) => ExitIdentity::Voidwire {
                name: exit.name.clone(),
                identity: id,
            },
            (NodeKind::Warp, _) => ExitIdentity::Warp,
            _ => ExitIdentity::Generic {
                name: exit.name.clone(),
            },
        };
        let inspector = self.settings().await.live_inspector;
        let hooks = DaemonHooks {
            platform: self.platform.as_ref(),
            firewall: self.firewall.clone(),
            tunnel: t,
            gate: &self.gate,
            counters: &self.counters,
            vault: lock(&self.vault).clone(),
            inspector_setting: inspector,
        };
        let baseline = lock(&self.info).baseline_ip;
        let ctx = CanaryContext {
            hooks: &hooks,
            exit: identity,
            exit_has_ipv6: t.tun_v6.is_some(),
            baseline_ip_hash: baseline,
            ip_salt: self.ip_salt,
            probe_timeout: self.canary_timeout,
        };
        run_canary(&ctx).await
    }

    /// Stop the active tunnel (firewall untouched; routes restored).
    async fn teardown(&self) {
        if let Some(mut t) = self.tunnel.lock().await.take() {
            t.shutdown().await;
        }
        self.generation.fetch_add(1, Ordering::SeqCst);
        if let Err(e) = self.platform.restore_routes().await {
            tracing::warn!(error = %e, "route restore failed");
        }
    }

    // ───────────────────────── monitor ─────────────────────────

    fn spawn_monitor(self: &Arc<Self>, gen: u64) {
        let me = Arc::downgrade(self);
        tokio::spawn(async move {
            let mut iv = tokio::time::interval(MONITOR_EVERY);
            iv.tick().await;
            loop {
                iv.tick().await;
                let Some(c) = me.upgrade() else { return };
                if c.generation.load(Ordering::SeqCst) != gen {
                    return;
                }
                if c.state() != DomeState::TunnelActive {
                    continue;
                }
                match c.check_tunnel().await {
                    Check::Fine => {}
                    Check::RotationDue => {
                        if let Err(e) = c.rotate(gen).await {
                            tracing::warn!(error = %e, "PQ rotation failed; failsafe lockdown");
                        }
                    }
                    Check::LinkLost(why) => {
                        tracing::warn!(reason = why, "link lost; reconnecting");
                        c.clone().link_lost(gen).await;
                        return;
                    }
                    Check::Reoptimize => {
                        let _ = c.optimize_inner(true).await;
                    }
                }
            }
        });
    }

    async fn check_tunnel(&self) -> Check {
        let rotate_cfg = self.settings().await.pq_rotate_secs;
        let (finished, last_rx, rot_due, entry) = {
            let g = self.tunnel.lock().await;
            let Some(t) = g.as_ref() else {
                return Check::Fine;
            };
            let since = t.last_rotation.unwrap_or(t.started);
            let has_pq = t.hops.iter().any(|h| h.pq.is_some());
            (
                t.driver_finished(),
                t.last_rx(),
                has_pq && since.elapsed() >= Duration::from_secs(t.rotate_secs(rotate_cfg)),
                t.entry_addr.ip(),
            )
        };
        if finished {
            return Check::LinkLost("transport closed");
        }
        if last_rx.is_none_or(|t| t.elapsed() >= LINK_TIMEOUT) {
            return Check::LinkLost("no packets for 3 keepalive intervals");
        }
        let salt = self.store.lock().await.salt();
        let fp = self
            .platform
            .network_identity(entry)
            .await
            .fingerprint(&salt);
        let (old, last_opt) = {
            let i = lock(&self.info);
            (i.network_fp.clone(), i.last_optimize)
        };
        if old.as_ref().is_some_and(|o| *o != fp) {
            lock(&self.info).network_fp = Some(fp);
            return Check::LinkLost("default route changed");
        }
        if rot_due {
            return Check::RotationDue;
        }
        if self.settings().await.auto_optimize
            && last_opt.is_some_and(|t| t.elapsed() >= optimizer::REEVALUATE_EVERY)
        {
            return Check::Reoptimize;
        }
        Check::Fine
    }

    /// Rotate the PQ PSKs now (normally driven by the rotation timer).
    pub async fn rotate_now(self: &Arc<Self>) -> Result<()> {
        let gen = self.generation.load(Ordering::SeqCst);
        self.rotate(gen).await
    }

    async fn rotate(self: &Arc<Self>, gen: u64) -> Result<()> {
        let _ops = self.ops.lock().await;
        if self.generation.load(Ordering::SeqCst) != gen || self.state() != DomeState::TunnelActive
        {
            return Ok(());
        }
        self.fire(DomeEvent::RotationDue)?;
        let r = {
            let mut g = self.tunnel.lock().await;
            match g.as_mut() {
                Some(t) => {
                    let path = t.path.clone();
                    let tokens = self.tokens_for(&path).await?;
                    t.rotate(&tokens).await
                }
                None => Err(VwError::Transport("no tunnel".into())),
            }
        };
        match r {
            Ok(()) => {
                Counters::add(&self.counters.pq_rotations, 1);
                self.fire(DomeEvent::RotationComplete)?;
                Ok(())
            }
            Err(e) => {
                self.teardown().await;
                self.fire(DomeEvent::RotationFailed)?;
                Err(e)
            }
        }
    }

    async fn link_lost(self: Arc<Self>, gen: u64) {
        {
            let _ops = self.ops.lock().await;
            if self.generation.load(Ordering::SeqCst) != gen {
                return;
            }
            self.teardown().await;
            let _ = self.fire(DomeEvent::LinkLost);
        }
        let mut backoff = Duration::from_secs(1);
        loop {
            let desired = lock(&self.info).desired;
            let Some(p) = desired else { return };
            if self.state() != DomeState::FailsafeLockdown {
                return;
            }
            let token = lock(&self.cancel).clone();
            let r = {
                let _ops = self.ops.lock().await;
                if self.state() != DomeState::FailsafeLockdown {
                    return;
                }
                tokio::select! {
                    r = self.connect_flow(p) => r,
                    _ = token.cancelled() => return,
                }
            };
            match r {
                Ok(()) => return,
                Err(e) => tracing::warn!(error = %e, "reconnect failed; retrying"),
            }
            tokio::select! {
                _ = tokio::time::sleep(backoff) => {}
                _ = token.cancelled() => return,
            }
            backoff = (backoff * 2).min(Duration::from_secs(60));
        }
    }

    // ───────────────────────── Down / Disarm ─────────────────────────

    pub async fn down(self: &Arc<Self>, keep_lockdown: bool) -> Result<()> {
        if !keep_lockdown {
            return self.disarm().await;
        }
        self.cancel_inflight();
        let _ops = self.ops.lock().await;
        lock(&self.info).desired = None;
        self.teardown().await;
        match self.state() {
            DomeState::TunnelActive | DomeState::KeyRotating => {
                self.fire(DomeEvent::DownKeepLockdown)?;
            }
            DomeState::Handshaking | DomeState::CanaryAuditing | DomeState::ArmingBootLock => {
                self.fire(DomeEvent::Fault)?;
            }
            _ => {}
        }
        // Keep only the lockdown (no pins, no tunnel).
        if self.state().firewall_locked() {
            self.update_pins(Vec::new(), None).await?;
        }
        Ok(())
    }

    /// The only way out of the lockdown.
    pub async fn disarm(self: &Arc<Self>) -> Result<()> {
        self.cancel_inflight();
        let _ops = self.ops.lock().await;
        lock(&self.info).desired = None;
        self.teardown().await;
        match self.state() {
            DomeState::Disarmed => return Ok(()),
            DomeState::Disarming => {}
            _ => {
                self.fire(DomeEvent::Disarm)?;
            }
        }
        let fw = self.firewall.clone();
        tokio::task::spawn_blocking(move || lock(&fw).disarm())
            .await
            .map_err(|e| VwError::Firewall(format!("firewall worker: {e}")))??;
        *lock(&self.plan) = None;
        if let Err(e) = self.platform.restore_dns().await {
            tracing::warn!(error = %e, "system DNS restore failed");
        }
        match std::fs::remove_file(self.marker()) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
        self.fire(DomeEvent::LockReleased)?;
        Ok(())
    }

    // ───────────────────────── Panic ─────────────────────────

    /// Rotate identities, flush caches and switch exit; firewall stays locked.
    pub async fn panic(self: &Arc<Self>) -> Result<()> {
        let token = self.new_cancel();
        let _ops = self.ops.lock().await;
        let t0 = Instant::now();
        let state = self.state();
        match state {
            DomeState::TunnelActive => {}
            DomeState::FailsafeLockdown => {
                self.flush_everything().await;
                self.fresh_identities(None).await?;
                self.fire(DomeEvent::Panic)?;
                let p = lock(&self.info).desired.unwrap_or(UpParams {
                    profile: Profile::Auto,
                    country: None,
                    transport: None,
                    gateway: None,
                });
                return tokio::select! {
                    r = self.after_handshaking(p) => r,
                    _ = token.cancelled() => Err(VwError::Config("cancelled".into())),
                };
            }
            s => {
                return Err(VwError::Config(format!(
                    "panic is not available while {s:?}"
                )))
            }
        }
        self.fire(DomeEvent::Panic)?;
        self.flush_everything().await;
        let current = self.tunnel.lock().await.as_ref().map(|t| t.path.clone());
        self.fresh_identities(current.as_ref()).await?;
        // Next-best exit from the last optimizer run.
        let next = {
            let info = lock(&self.info);
            let cur_exit = current.as_ref().map(|p| p.exit().name.clone());
            info.ranked
                .iter()
                .find(|p| Some(p.exit().name.clone()) != cur_exit)
                .cloned()
                .or_else(|| current.clone())
        };
        let Some(path) = next else {
            self.fire(DomeEvent::RotationFailed)?;
            return Err(VwError::Config("no path to switch to".into()));
        };
        let r = tokio::select! {
            r = self.switch_path(path) => r,
            _ = token.cancelled() => Err(VwError::Config("cancelled".into())),
        };
        match r {
            Ok(switch_ms) => {
                tracing::info!(
                    switch_ms,
                    total_ms = t0.elapsed().as_millis() as u64,
                    "panic: identities rotated, exit switched"
                );
                Counters::add(&self.counters.pq_rotations, 1);
                self.fire(DomeEvent::RotationComplete)?;
                Ok(())
            }
            Err(e) => {
                self.teardown().await;
                self.fire(DomeEvent::RotationFailed)?;
                Err(e)
            }
        }
    }

    async fn after_handshaking(self: &Arc<Self>, p: UpParams) -> Result<()> {
        // State is Handshaking: run the remainder of the connect flow.
        let tunnel = match self.handshake_phase(p).await {
            Ok(t) => t,
            Err(e) => {
                self.fire(DomeEvent::HandshakeFailed)?;
                return Err(e);
            }
        };
        self.fire(DomeEvent::HandshakeComplete)?;
        let mut tunnel = tunnel;
        let report = match self.prepare_host(&mut tunnel).await {
            Ok(()) => self.canary(&tunnel).await,
            Err(e) => failed_report("host-config", &e.to_string()),
        };
        self.events.emit(DaemonEvent::Audit(report.clone()));
        if !report.passed {
            tunnel.shutdown().await;
            self.fire(DomeEvent::CanaryFailed)?;
            return Err(VwError::Config("canary audit failed; lockdown kept".into()));
        }
        self.fire(DomeEvent::CanaryPassed)?;
        let gen = self.generation.fetch_add(1, Ordering::SeqCst) + 1;
        *self.tunnel.lock().await = Some(tunnel);
        self.spawn_monitor(gen);
        Ok(())
    }

    async fn flush_everything(&self) {
        if let Some(v) = lock(&self.vault).clone() {
            v.flush();
        }
        if let Err(e) = self.platform.flush_caches().await {
            tracing::debug!(error = %e, "OS cache flush incomplete");
        }
    }

    /// New WireGuard static key unless a hop admits us by that key; a
    /// re-registered WARP device when WARP is on the path.
    async fn fresh_identities(&self, path: Option<&RankedPath>) -> Result<()> {
        let mut s = self.store.lock().await;
        let key_bound = path.is_some_and(|p| {
            p.hops.iter().any(|h| match h.node.kind {
                NodeKind::Voidwire => !s.is_f2f(&h.node.identity_key),
                NodeKind::Generic => true,
                NodeKind::Warp => false,
            })
        }) || (path.is_none() && !s.data.client.nodes.is_empty());
        if !key_bound {
            s.data.client.wg_private = Some(vw_wg::generate_private_key());
        }
        let warp_used = path.is_some_and(|p| p.hops.iter().any(|h| h.node.kind == NodeKind::Warp));
        let old = s.data.client.warp.clone();
        drop(s);
        if let (true, Some(old)) = (warp_used, old) {
            // Traffic is allowed in KeyRotating: register through the old tunnel.
            match self.platform.warp_register(Vec::new(), false).await {
                Ok(new) => {
                    if let Err(e) = self.platform.warp_delete(&old, Vec::new(), false).await {
                        tracing::debug!(error = %e, "old WARP device not deleted");
                    }
                    let mut s = self.store.lock().await;
                    s.data.client.warp = Some(new);
                    lock(&self.info).ranked.clear();
                    s.save()?;
                }
                Err(e) => tracing::warn!(error = %e, "WARP re-registration failed; keeping device"),
            }
        } else {
            self.store.lock().await.save()?;
        }
        Ok(())
    }

    /// Build a new tunnel on `path`, move host config to it, drop the old one
    /// and verify with the canary. State must be `KeyRotating`.
    async fn switch_path(self: &Arc<Self>, path: RankedPath) -> Result<u64> {
        let mut path = path;
        if path.hops.iter().any(|h| h.node.kind == NodeKind::Warp) {
            // WARP may have been re-registered: rebuild its hop from the store.
            if let Some(acct) = self.store.lock().await.data.client.warp.clone() {
                for h in path
                    .hops
                    .iter_mut()
                    .filter(|h| h.node.kind == NodeKind::Warp)
                {
                    let idx = h
                        .name
                        .rsplit('#')
                        .next()
                        .and_then(|i| i.parse().ok())
                        .unwrap_or(0);
                    let (name, node) = optimizer::warp_node(&acct, idx);
                    h.name = name;
                    h.endpoint = node.endpoints[0].clone();
                    h.node = node;
                }
            }
        }
        let old_pins = self
            .current_plan()
            .map(|p| (p.pinned, p.tunnel))
            .unwrap_or_default();
        let new_pin = path.hops[0]
            .pin()
            .ok_or_else(|| VwError::Config("entry unresolved".into()))?;
        let mut pins = old_pins.0.clone();
        pins.push(new_pin);
        self.update_pins(pins, old_pins.1.clone()).await?;
        let daita = lock(&self.info).decision.as_ref().is_some_and(|d| d.daita);
        let psks = self
            .tunnel
            .lock()
            .await
            .as_ref()
            .map(|t| t.psks())
            .unwrap_or_default();
        let mut new = self.build_tunnel(path, daita, psks).await?;
        let t_switch = Instant::now();
        let iface = new.attach_os_tun(self.platform.as_ref())?;
        self.update_pins(vec![new_pin], Some(iface.clone())).await?;
        if let Some(v) = self.ensure_vault().await {
            if let Some(old) = self.tunnel.lock().await.as_mut() {
                old.vault_servers.clear();
            }
            new.vault_servers = self.platform.start_vault(v, &iface).await?;
        }
        self.platform
            .install_routes(&iface, &[new.entry_addr.ip()], new.tun_v6.is_some())
            .await?;
        self.platform.apply_dns(&iface).await?;
        if let Some(mut old) = self.tunnel.lock().await.take() {
            old.shutdown().await;
        }
        let switch_ms = t_switch.elapsed().as_millis() as u64;
        let report = self.canary(&new).await;
        self.events.emit(DaemonEvent::Audit(report.clone()));
        if !report.passed {
            new.shutdown().await;
            return Err(VwError::Config("canary failed on the new path".into()));
        }
        let gen = self.generation.fetch_add(1, Ordering::SeqCst) + 1;
        *self.tunnel.lock().await = Some(new);
        self.spawn_monitor(gen);
        Ok(switch_ms)
    }

    // ───────────────────────── Audit / Optimize ─────────────────────────

    pub async fn audit(self: &Arc<Self>) -> Result<AuditReport> {
        let _ops = self.ops.lock().await;
        let report = {
            let g = self.tunnel.lock().await;
            match g.as_ref() {
                Some(t) if self.state().traffic_allowed() => self.canary(t).await,
                _ => {
                    let fw = self.firewall_matrix();
                    let mut r = failed_report("tunnel", "no active tunnel");
                    r.checks.insert(
                        0,
                        AuditCheck {
                            name: "firewall-kernel".into(),
                            passed: fw.ipv4_locked && fw.ipv6_locked,
                            detail: format!(
                                "{} lockdown {}",
                                fw.backend,
                                if fw.ipv4_locked { "armed" } else { "not armed" }
                            ),
                            proof: blake3::hash(format!("{fw:?}").as_bytes())
                                .to_hex()
                                .to_string(),
                        },
                    );
                    r
                }
            }
        };
        self.events.emit(DaemonEvent::Audit(report.clone()));
        if !report.passed && self.state().traffic_allowed() {
            tracing::warn!("live audit failed; failsafe lockdown");
            self.teardown().await;
            self.fire(DomeEvent::Fault)?;
        }
        Ok(report)
    }

    pub async fn optimize(self: &Arc<Self>) -> Result<OptimizerDecision> {
        self.optimize_inner(false).await
    }

    async fn optimize_inner(self: &Arc<Self>, background: bool) -> Result<OptimizerDecision> {
        let _ops = self.ops.lock().await;
        let desired = lock(&self.info).desired;
        let p = match desired {
            Some(p) => p,
            None => UpParams {
                profile: self.settings().await.default_profile,
                country: None,
                transport: None,
                gateway: None,
            },
        };
        let active = self.state() == DomeState::TunnelActive;
        let iface = if active {
            self.tunnel
                .lock()
                .await
                .as_ref()
                .and_then(|t| t.iface.clone())
        } else {
            None
        };
        if !self.state().firewall_locked() {
            // Probing before the lockdown exists would leak; arm first.
            return Err(VwError::Config(
                "optimize requires an armed lockdown (run up first)".into(),
            ));
        }
        let restore = self.current_plan();
        let r = self.choose_path(p, iface.as_ref()).await;
        if let Some(plan) = restore {
            self.apply_plan(plan).await?;
        }
        let (best, decision) = r?;
        if active {
            let current = self.tunnel.lock().await.as_ref().map(|t| t.path.names());
            let ranked = lock(&self.info).ranked.clone();
            let cur_score = ranked
                .iter()
                .find(|p| Some(p.names()) == current)
                .map(|p| p.score)
                .unwrap_or(0.0);
            if Some(best.names()) != current && optimizer::should_switch(cur_score, best.score) {
                tracing::info!(background, "switching to a path at least 20% better");
                self.fire(DomeEvent::RotationDue)?;
                match self.switch_path(best).await {
                    Ok(_) => {
                        self.fire(DomeEvent::RotationComplete)?;
                    }
                    Err(e) => {
                        self.teardown().await;
                        self.fire(DomeEvent::RotationFailed)?;
                        return Err(e);
                    }
                }
            }
        }
        Ok(decision)
    }

    // ───────────────────────── status / settings / nodes ─────────────────────────

    fn firewall_matrix(&self) -> FirewallMatrix {
        let fw = lock(&self.firewall);
        match fw.status() {
            Ok(s) => s.into(),
            Err(_) => FirewallMatrix {
                backend: fw.name().into(),
                ..Default::default()
            },
        }
    }

    pub async fn status(&self) -> StatusReport {
        let state = self.state();
        let (hops, transport, mtu, daita, uptime, last_rot, pq) = {
            let g = self.tunnel.lock().await;
            match g.as_ref() {
                Some(t) => (
                    t.hops
                        .iter()
                        .enumerate()
                        .map(|(i, h)| HopInfo {
                            name: h.cand.name.clone(),
                            kind: h.cand.node.kind,
                            role: h.cand.node.role,
                            country: h.cand.node.country.clone(),
                            transport: if i == 0 {
                                h.cand.transport()
                            } else {
                                TransportKind::NativeUdp
                            },
                            post_quantum: h.pq.is_some(),
                            rtt_ms: h.rtt_ms,
                            coords: None,
                        })
                        .collect(),
                    Some(t.path.transport()),
                    Some(t.mtu),
                    t.daita,
                    t.started.elapsed().as_secs(),
                    t.last_rotation.map(|r| r.elapsed().as_secs()),
                    t.hops.last().is_some_and(|h| h.pq.is_some()),
                ),
                None => (Vec::new(), None, None, false, 0, None, false),
            }
        };
        let info = lock(&self.info);
        StatusReport {
            state,
            profile: info.profile.filter(|_| !hops.is_empty()),
            hops,
            transport,
            crypto_suite: if transport.is_none() {
                "none".into()
            } else if pq {
                "WireGuard Noise_IKpsk2 + hybrid X25519/ML-KEM-1024 PSK (rotating)".into()
            } else {
                "WireGuard Noise_IKpsk2 (classical, no post-quantum PSK)".into()
            },
            uptime_secs: uptime,
            mtu,
            daita,
            firewall: if state.firewall_locked() {
                self.firewall_matrix()
            } else {
                FirewallMatrix {
                    backend: lock(&self.firewall).name().into(),
                    ..Default::default()
                }
            },
            last_rotation_secs_ago: last_rot,
            telemetry: self.counters.snapshot(),
            decision: info.decision.clone(),
            platform: self.platform.label(),
            daemon_version: format!(
                "{} (up {}s)",
                crate::DAEMON_VERSION,
                self.started.elapsed().as_secs()
            ),
        }
    }

    pub async fn get_settings(&self) -> Settings {
        self.settings().await
    }

    pub async fn set_settings(self: &Arc<Self>, new: Settings) -> Result<()> {
        if new.pq_rotate_secs < 10 {
            return Err(VwError::Config("pq_rotate_secs must be at least 10".into()));
        }
        let old = {
            let mut s = self.store.lock().await;
            let old = std::mem::replace(&mut s.data.client.settings, new.clone());
            s.save()?;
            old
        };
        if old.dns != new.dns {
            *lock(&self.vault) = None;
            self.ensure_vault().await;
        } else if let Some(v) = lock(&self.vault).clone() {
            v.set_inspector(new.live_inspector);
        }
        if old.firewall != new.firewall {
            if let Some(mut plan) = self.current_plan() {
                plan.settings = new.firewall.clone();
                self.apply_plan(plan).await?;
            }
        }
        Ok(())
    }

    pub async fn list_nodes(&self) -> Vec<NodeSummary> {
        self.store.lock().await.summaries()
    }

    pub async fn import_node(self: &Arc<Self>, uri: &str) -> Result<()> {
        let uri = uri.trim();
        if uri.starts_with(F2F_PREFIX) {
            return self.redeem_invite(uri).await;
        }
        if !uri.starts_with(NODE_PREFIX) {
            return Err(VwError::Uri(
                "expected voidwire://node/ or voidwire://f2f/".into(),
            ));
        }
        let n = decode_node(uri)?;
        let mut s = self.store.lock().await;
        s.upsert_node(n)?;
        s.save()
    }

    /// Import a WireGuard / AmneziaWG `.conf` from any provider as a gateway.
    pub async fn import_wireguard(
        &self,
        name: &str,
        config: &str,
        country: Option<&str>,
    ) -> Result<()> {
        if name.trim() == WARP_GATEWAY {
            return Err(VwError::Config(
                "that name is reserved for Cloudflare WARP".into(),
            ));
        }
        let n = vw_core::wgconf::parse(config, name, country)?;
        let mut s = self.store.lock().await;
        s.upsert_node(n)?;
        s.save()
    }

    pub async fn remove_node(&self, name: &str) -> Result<()> {
        let mut s = self.store.lock().await;
        s.remove_node(name)?;
        s.save()
    }

    /// Validate an F2F invite, connect to the friend's node, redeem tokens.
    pub async fn redeem_invite(self: &Arc<Self>, uri: &str) -> Result<()> {
        let invite = vw_crypto::Invite::from_uri(uri, unix_now())
            .map_err(|e| VwError::Uri(format!("invalid invite: {e}")))?;
        let node = decode_node(&invite.node_uri)?;
        let identity = node
            .identity_key
            .ok_or_else(|| VwError::Config("invite node has no identity".into()))?;
        let info = node
            .token_keys
            .iter()
            .find(|k| k.bandwidth_bps == invite.bandwidth_bps)
            .or_else(|| (node.token_keys.len() == 1).then(|| &node.token_keys[0]))
            .ok_or_else(|| {
                VwError::Config("node publishes no token key for this invite tier".into())
            })?;
        let spki = base64_decode(&info.spki)?;
        let pk = vw_crypto::TokenPublicKey::from_der(info.tier, &spki)
            .map_err(|_| VwError::Config("invalid token key".into()))?;
        {
            let mut s = self.store.lock().await;
            s.upsert_node(node.clone())?;
            s.save()?;
        }
        let _ops = self.ops.lock().await;
        let cands =
            optimizer::build_candidates(std::slice::from_ref(&node), None, Profile::Auto, None);
        let armed = self.state().firewall_locked();
        let cands = optimizer::resolve_candidates(self.platform.as_ref(), cands, armed).await;
        let mut last_err = VwError::Config("node unreachable".into());
        let restore = self.current_plan();
        for c in cands {
            if armed {
                let mut plan = restore
                    .clone()
                    .unwrap_or_else(|| LockdownPlan::new(Default::default()));
                if let Some(pin) = c.pin() {
                    plan.pinned.push(pin);
                }
                self.apply_plan(plan).await?;
            }
            let r = self.redeem_via(&c, identity, &invite, &pk).await;
            if let Some(p) = restore.clone() {
                self.apply_plan(p).await?;
            }
            match r {
                Ok(tokens) => {
                    let n = tokens.len();
                    let mut s = self.store.lock().await;
                    s.add_tokens(identity, tokens);
                    s.save()?;
                    tracing::info!(tokens = n, "friend invite redeemed");
                    return Ok(());
                }
                Err(e) => last_err = e,
            }
        }
        Err(last_err)
    }

    async fn redeem_via(
        &self,
        c: &Candidate,
        identity: vw_core::config::Bytes32,
        invite: &vw_crypto::Invite,
        pk: &vw_crypto::TokenPublicKey,
    ) -> Result<Vec<vw_core::secret::SecretVec>> {
        let keys = self.keys().await;
        let opts = vw_stealth::ConnectOptions {
            amnezia: c.node.amnezia,
            socket: self.platform.socket_options().await,
            resolved: c.addr,
            masque_target: None,
            connect_timeout: Duration::from_secs(10),
        };
        let t = self.platform.connect(&c.endpoint, &opts).await?;
        let mut s = DirectSession::new(optimizer::peer_for(&c.node, &keys), t);
        s.handshake(3, Duration::from_secs(3)).await?;
        let mut token = zeroize::Zeroizing::new(vec![0x02]);
        token.extend_from_slice(invite.invite_secret.expose());
        let port = ephemeral_port();
        let src = std::net::SocketAddr::new(IpAddr::V4(vw_core::consts::PROVISIONAL_V4), port);
        let session = vwcp_handshake(
            &mut s,
            src,
            identity,
            initial_epoch(),
            token.to_vec(),
            Duration::from_secs(10),
        )
        .await?;
        s.peer.set_psk(session.psk.clone());
        s.handshake(3, Duration::from_secs(3)).await?;
        let src = std::net::SocketAddr::new(IpAddr::V4(session.v4), port);
        let tokens = vwcp_redeem(&mut s, src, pk, REDEEM_TOKENS, Duration::from_secs(10)).await;
        s.close().await;
        tokens
    }

    /// Register an anonymous WARP device (user accepted the ToS in the client).
    pub async fn register_warp(self: &Arc<Self>) -> Result<()> {
        let _ops = self.ops.lock().await;
        let state = self.state();
        let acct = if state.traffic_allowed() {
            // Through the tunnel: unmarked sockets follow the tunnel routes.
            self.platform.warp_register(Vec::new(), false).await?
        } else if state.firewall_locked() {
            let restore = self.current_plan();
            let mut plan = restore
                .clone()
                .unwrap_or_else(|| LockdownPlan::new(Default::default()));
            plan.pinned.extend(
                vw_freecloud::http::BOOTSTRAP_DOH
                    .iter()
                    .map(|a| PinnedEndpoint::tcp(*a)),
            );
            self.apply_plan(plan.clone()).await?;
            let host = vw_core::consts::WARP_API_BASE
                .trim_start_matches("https://")
                .split('/')
                .next()
                .unwrap_or_default()
                .to_string();
            let r = async {
                let ips = self.platform.resolve(&host, true).await?;
                let api: Vec<std::net::SocketAddr> = ips
                    .into_iter()
                    .map(|ip| std::net::SocketAddr::new(ip, 443))
                    .collect();
                let mut p2 = plan.clone();
                p2.pinned
                    .extend(api.iter().map(|a| PinnedEndpoint::tcp(*a)));
                self.apply_plan(p2).await?;
                self.platform.warp_register(api, true).await
            }
            .await;
            if let Some(p) = restore {
                self.apply_plan(p).await?;
            }
            r?
        } else {
            self.platform.warp_register(Vec::new(), false).await?
        };
        let mut s = self.store.lock().await;
        s.data.client.warp = Some(acct);
        s.save()
    }

    /// `voidwire exec` preparation.
    pub async fn exec_prepare(&self) -> Result<ExecTicket> {
        if self.state() != DomeState::TunnelActive {
            return Err(VwError::Config(
                "exec requires an active, audited tunnel".into(),
            ));
        }
        let mut g = self.tunnel.lock().await;
        let t = g
            .as_mut()
            .ok_or_else(|| VwError::Config("no tunnel".into()))?;
        crate::exec::prepare(self.platform.as_ref(), t).await
    }
}

enum Check {
    Fine,
    RotationDue,
    LinkLost(&'static str),
    Reoptimize,
}

fn failed_report(name: &str, detail: &str) -> AuditReport {
    AuditReport {
        passed: false,
        checks: vec![AuditCheck {
            name: name.into(),
            passed: false,
            detail: vw_firewall::scrub_addresses(detail),
            proof: blake3::hash(detail.as_bytes()).to_hex().to_string(),
        }],
        unix_time: unix_now(),
    }
}

fn base64_decode(s: &str) -> Result<Vec<u8>> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(s.trim())
        .map_err(|_| VwError::Config("bad base64 token key".into()))
}

#[cfg(test)]
mod tests {
    #[test]
    fn b64() {
        assert_eq!(super::base64_decode("aGVsbG8=").unwrap(), b"hello");
        assert!(super::base64_decode("*").is_err());
    }
}
