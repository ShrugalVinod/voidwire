//! Live canary self-verifier (ARCHITECTURE.md §2, `CanaryAuditing`).
//!
//! [`run_canary`] executes every leak check through a [`CanaryHooks`]
//! implementation and returns an [`AuditReport`]. Each check carries a proof:
//! the BLAKE3 digest of its probe transcript (what was sent, what was
//! observed, counter values), domain-separated by check name, so a report can
//! be compared against a re-run or a log without revealing addresses.
//!
//! Checks:
//! 1. `firewall-kernel` — the kernel enforces default-deny (`is_armed_in_kernel`)
//!    and the status matrix shows IPv4, IPv6 and DNS locked.
//! 2. `egress-udp-observer`, `egress-udp-dns`, `egress-tcp-https` — unmarked
//!    probes bound to the physical interface must fail or get no reply.
//! 3. `dns-vault` — a random canary name resolved through the *system*
//!    resolver must be seen by the DNS vault.
//! 4. `stun-filter` — a STUN Binding Request injected into the TUN path must
//!    increment `stun_blocked`.
//! 5. `ipv6-policy` — on IPv4-only exits an IPv6 packet must be dropped and
//!    counted.
//! 6. `exit-identity` — VoidWire exits: a fresh AttestRequest answered with an
//!    attestation signed by the expected node identity; WARP: the in-tunnel
//!    Cloudflare trace reports `warp=on`.
//! 7. `real-ip` — when a pre-arm public-IP hash was captured, the in-tunnel
//!    public IP must differ from it.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use async_trait::async_trait;
use rand::RngCore;
use vw_core::config::Bytes32;
use vw_core::consts::LEAK_OBSERVER_V4;
use vw_core::ipc::{AuditCheck, AuditReport, FirewallMatrix};
use vw_core::Result;
use vw_crypto::attest::SignedAttestation;

/// Domain separator of every proof digest.
const PROOF_DOMAIN: &[u8] = b"vw-canary-v1";
/// Parent zone of canary names. `internal` is reserved for private use, is not
/// special-cased by OS resolvers, and the vault answers it locally (never
/// forwarded), so the probe cannot leak the name upstream.
pub const CANARY_ZONE: &str = "voidwire-canary.internal";

/// Who the exit should be.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExitIdentity {
    /// A `voidwire-node` with this Ed25519 identity.
    Voidwire { name: String, identity: Bytes32 },
    /// Cloudflare WARP (classical WireGuard).
    Warp,
    /// A plain WireGuard server without an identity mechanism.
    Generic { name: String },
}

/// Transport protocol of a physical-egress probe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EgressProto {
    Udp,
    Tcp,
}

/// One unmarked probe that must not leave the host outside the tunnel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EgressProbe {
    pub name: &'static str,
    pub proto: EgressProto,
    pub target: SocketAddr,
    /// UDP payload (ignored for TCP connects).
    pub payload: Vec<u8>,
}

/// What a physical-egress probe observed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EgressOutcome {
    /// The kernel refused (send/connect error): the lockdown works.
    Blocked(String),
    /// Sent but nothing came back before the deadline.
    NoReply,
    /// A reply / completed connection: a leak.
    Reached(usize),
}

/// Kernel firewall observation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FirewallObservation {
    pub armed_in_kernel: bool,
    pub status: FirewallMatrix,
}

/// A counter before/after an injected probe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CounterObservation {
    pub before: u64,
    pub after: u64,
    /// Raw bytes of the injected probe (part of the transcript).
    pub probe: Vec<u8>,
}

impl CounterObservation {
    pub fn incremented(&self) -> bool {
        self.after > self.before
    }
}

/// DNS canary observation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsObservation {
    /// The system resolver returned (any rcode, including NXDOMAIN).
    pub resolver_answered: bool,
    /// The vault's inspector saw the canary name.
    pub vault_saw_name: bool,
    pub intercepted_before: u64,
    pub intercepted_after: u64,
}

/// OS / daemon hooks used by the canary. The daemon implements this over the
/// live tunnel; tests implement it in memory.
#[async_trait]
pub trait CanaryHooks: Send + Sync {
    async fn firewall(&self) -> Result<FirewallObservation>;
    async fn physical_egress(&self, probe: &EgressProbe) -> EgressOutcome;
    async fn dns_probe(&self, name: &str) -> Result<DnsObservation>;
    async fn stun_probe(&self) -> Result<CounterObservation>;
    async fn ipv6_probe(&self) -> Result<CounterObservation>;
    /// Send an AttestRequest with `nonce` to the exit; returns the encoded
    /// `SignedAttestation`.
    async fn attest(&self, nonce: [u8; 32]) -> Result<Vec<u8>>;
    /// Body of the in-tunnel `cdn-cgi/trace` response.
    async fn trace(&self) -> Result<String>;
}

/// Inputs to [`run_canary`].
pub struct CanaryContext<'a> {
    pub hooks: &'a dyn CanaryHooks,
    pub exit: ExitIdentity,
    pub exit_has_ipv6: bool,
    /// `BLAKE3-keyed(ip_salt, public_ip)` captured before arming, if any.
    pub baseline_ip_hash: Option<[u8; 32]>,
    pub ip_salt: [u8; 32],
    /// Upper bound for each hook call.
    pub probe_timeout: Duration,
}

/// The physical-egress probes every audit runs.
pub fn egress_probes() -> Vec<EgressProbe> {
    vec![
        EgressProbe {
            name: "egress-udp-observer",
            proto: EgressProto::Udp,
            target: SocketAddr::new(IpAddr::V4(LEAK_OBSERVER_V4), 9),
            payload: b"voidwire-canary".to_vec(),
        },
        EgressProbe {
            name: "egress-udp-dns",
            proto: EgressProto::Udp,
            target: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9)), 53),
            payload: dns_query("example.com", rand::random()),
        },
        EgressProbe {
            name: "egress-tcp-https",
            proto: EgressProto::Tcp,
            target: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 443),
            payload: Vec::new(),
        },
    ]
}

/// Minimal DNS A query wire message.
pub fn dns_query(name: &str, id: u16) -> Vec<u8> {
    let mut q = Vec::with_capacity(32 + name.len());
    q.extend_from_slice(&id.to_be_bytes());
    q.extend_from_slice(&[0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]);
    for label in name.split('.').filter(|l| !l.is_empty()) {
        q.push(label.len().min(63) as u8);
        q.extend_from_slice(&label.as_bytes()[..label.len().min(63)]);
    }
    q.extend_from_slice(&[0, 0, 1, 0, 1]);
    q
}

/// Fresh random canary name under [`CANARY_ZONE`].
pub fn canary_name() -> String {
    let mut b = [0u8; 8];
    rand::rngs::OsRng.fill_bytes(&mut b);
    format!("vwc-{}.{CANARY_ZONE}", hex::encode(b))
}

/// Hash a public IP for the real-IP comparison.
pub fn ip_hash(salt: &[u8; 32], ip: &str) -> [u8; 32] {
    *blake3::keyed_hash(salt, ip.trim().as_bytes()).as_bytes()
}

/// Parse `key=value` lines of a Cloudflare trace body.
pub fn trace_field<'a>(body: &'a str, key: &str) -> Option<&'a str> {
    body.lines()
        .filter_map(|l| l.split_once('='))
        .find(|(k, _)| k.trim() == key)
        .map(|(_, v)| v.trim())
}

struct Transcript {
    name: &'static str,
    h: blake3::Hasher,
}

impl Transcript {
    fn new(name: &'static str) -> Self {
        let mut h = blake3::Hasher::new();
        h.update(PROOF_DOMAIN);
        h.update(&(name.len() as u16).to_be_bytes());
        h.update(name.as_bytes());
        Self { name, h }
    }

    fn add(&mut self, label: &str, data: &[u8]) -> &mut Self {
        self.h.update(&(label.len() as u16).to_be_bytes());
        self.h.update(label.as_bytes());
        self.h.update(&(data.len() as u64).to_be_bytes());
        self.h.update(data);
        self
    }

    fn finish(&self, passed: bool, detail: impl Into<String>) -> AuditCheck {
        let mut h = self.h.clone();
        h.update(&[passed as u8]);
        AuditCheck {
            name: self.name.to_string(),
            passed,
            detail: detail.into(),
            proof: h.finalize().to_hex().to_string(),
        }
    }
}

async fn bounded<T>(d: Duration, f: impl std::future::Future<Output = Result<T>>) -> Result<T> {
    tokio::time::timeout(d, f)
        .await
        .map_err(|_| vw_core::VwError::Timeout)?
}

async fn check_firewall(ctx: &CanaryContext<'_>) -> AuditCheck {
    let mut t = Transcript::new("firewall-kernel");
    match bounded(ctx.probe_timeout, ctx.hooks.firewall()).await {
        Ok(o) => {
            let s = &o.status;
            t.add("armed", &[o.armed_in_kernel as u8]).add(
                "matrix",
                &[s.ipv4_locked as u8, s.ipv6_locked as u8, s.dns_vault as u8],
            );
            t.add("backend", s.backend.as_bytes());
            let ok = o.armed_in_kernel && s.ipv4_locked && s.ipv6_locked && s.dns_vault;
            let detail = if ok {
                format!("{} default-deny verified in kernel", s.backend)
            } else if !o.armed_in_kernel {
                format!("{} lockdown is not present in the kernel", s.backend)
            } else {
                "lockdown matrix incomplete (IPv4/IPv6/DNS)".to_string()
            };
            t.finish(ok, detail)
        }
        Err(e) => {
            t.add("error", e.to_string().as_bytes());
            t.finish(false, format!("cannot query firewall: {e}"))
        }
    }
}

async fn check_egress(ctx: &CanaryContext<'_>, probe: EgressProbe) -> AuditCheck {
    let mut t = Transcript::new(probe.name);
    t.add("target", probe.target.to_string().as_bytes())
        .add("proto", &[probe.proto as u8])
        .add("payload", &probe.payload);
    let outcome = tokio::time::timeout(ctx.probe_timeout, ctx.hooks.physical_egress(&probe))
        .await
        .unwrap_or(EgressOutcome::NoReply);
    match &outcome {
        EgressOutcome::Blocked(e) => {
            t.add("blocked", e.as_bytes());
            t.finish(true, "refused by the kernel outside the tunnel")
        }
        EgressOutcome::NoReply => {
            t.add("no-reply", &[]);
            t.finish(true, "no reply outside the tunnel")
        }
        EgressOutcome::Reached(n) => {
            t.add("reached", &(*n as u64).to_be_bytes());
            t.finish(false, "LEAK: probe reached the network outside the tunnel")
        }
    }
}

async fn check_dns(ctx: &CanaryContext<'_>) -> AuditCheck {
    let mut t = Transcript::new("dns-vault");
    let name = canary_name();
    t.add("name", name.as_bytes());
    match bounded(ctx.probe_timeout, ctx.hooks.dns_probe(&name)).await {
        Ok(o) => {
            t.add("answered", &[o.resolver_answered as u8])
                .add("vault_saw", &[o.vault_saw_name as u8])
                .add("before", &o.intercepted_before.to_be_bytes())
                .add("after", &o.intercepted_after.to_be_bytes());
            let ok = o.vault_saw_name || o.intercepted_after > o.intercepted_before;
            t.finish(
                ok,
                if ok {
                    "system resolver queries reach the DNS vault"
                } else {
                    "system resolver bypassed the DNS vault"
                },
            )
        }
        Err(e) => {
            t.add("error", e.to_string().as_bytes());
            t.finish(false, format!("dns probe failed: {e}"))
        }
    }
}

async fn check_counter(
    ctx: &CanaryContext<'_>,
    name: &'static str,
    ok_detail: &str,
    fail_detail: &str,
    obs: impl std::future::Future<Output = Result<CounterObservation>>,
) -> AuditCheck {
    let mut t = Transcript::new(name);
    match bounded(ctx.probe_timeout, obs).await {
        Ok(o) => {
            t.add("probe", &o.probe)
                .add("before", &o.before.to_be_bytes())
                .add("after", &o.after.to_be_bytes());
            let ok = o.incremented();
            t.finish(ok, if ok { ok_detail } else { fail_detail })
        }
        Err(e) => {
            t.add("error", e.to_string().as_bytes());
            t.finish(false, format!("probe failed: {e}"))
        }
    }
}

async fn check_identity(ctx: &CanaryContext<'_>, trace: &Result<String>) -> AuditCheck {
    let mut t = Transcript::new("exit-identity");
    match &ctx.exit {
        ExitIdentity::Voidwire { name, identity } => {
            let mut nonce = [0u8; 32];
            rand::rngs::OsRng.fill_bytes(&mut nonce);
            t.add("node", name.as_bytes())
                .add("identity", &identity.0)
                .add("nonce", &nonce);
            match bounded(ctx.probe_timeout, ctx.hooks.attest(nonce)).await {
                Ok(raw) => {
                    t.add("attestation", &raw);
                    let verified = SignedAttestation::decode(&raw)
                        .map_err(|e| e.to_string())
                        .and_then(|s| {
                            s.verify(identity, &nonce)
                                .map(|r| (r.ram_only, r.swap_disabled, r.logging_off))
                                .map_err(|e| e.to_string())
                        });
                    match verified {
                        Ok((ram, swap, log)) => t.finish(
                            true,
                            format!(
                                "attestation signed by the expected node (ram_only={ram}, swap_off={swap}, logging_off={log})"
                            ),
                        ),
                        Err(e) => t.finish(false, format!("attestation rejected: {e}")),
                    }
                }
                Err(e) => {
                    t.add("error", e.to_string().as_bytes());
                    t.finish(false, format!("exit did not attest: {e}"))
                }
            }
        }
        ExitIdentity::Warp => match trace {
            Ok(body) => {
                let warp = trace_field(body, "warp").unwrap_or("absent");
                t.add("warp", warp.as_bytes());
                if warp == "absent" && ctx.baseline_ip_hash.is_some() {
                    // A non-Cloudflare IP checker answered: WARP status is not
                    // reported, but `real-ip` still proves the exit changed.
                    t.finish(
                        true,
                        "WARP status not reported by the fallback checker; exit IP change is verified by real-ip",
                    )
                } else {
                    let ok = matches!(warp, "on" | "plus");
                    t.finish(
                        ok,
                        if ok {
                            "Cloudflare reports traffic arriving via WARP".to_string()
                        } else {
                            format!("Cloudflare trace says warp={warp}")
                        },
                    )
                }
            }
            Err(e) => {
                t.add("error", e.to_string().as_bytes());
                t.finish(false, format!("in-tunnel trace failed: {e}"))
            }
        },
        ExitIdentity::Generic { name } => {
            t.add("node", name.as_bytes());
            t.finish(
                true,
                "generic WireGuard exit: no identity mechanism, endpoint key pinned only",
            )
        }
    }
}

fn check_real_ip(
    ctx: &CanaryContext<'_>,
    baseline: &[u8; 32],
    trace: &Result<String>,
) -> AuditCheck {
    let mut t = Transcript::new("real-ip");
    t.add("baseline", baseline);
    match trace {
        Ok(body) => match trace_field(body, "ip") {
            Some(ip) => {
                let h = ip_hash(&ctx.ip_salt, ip);
                t.add("tunnel_ip_hash", &h);
                let ok = h != *baseline;
                t.finish(
                    ok,
                    if ok {
                        "public IP differs from the pre-arm address"
                    } else {
                        "LEAK: public IP equals the pre-arm address"
                    },
                )
            }
            None => t.finish(false, "trace response has no ip field"),
        },
        Err(e) => {
            t.add("error", e.to_string().as_bytes());
            t.finish(false, format!("in-tunnel trace failed: {e}"))
        }
    }
}

/// Run every check. `passed` is true only if all checks pass.
pub async fn run_canary(ctx: &CanaryContext<'_>) -> AuditReport {
    let mut checks = vec![check_firewall(ctx).await];
    let probes = egress_probes();
    let mut egress = Vec::new();
    {
        let futs = probes.into_iter().map(|p| check_egress(ctx, p));
        for c in join_all(futs).await {
            egress.push(c);
        }
    }
    checks.extend(egress);
    checks.push(check_dns(ctx).await);
    checks.push(
        check_counter(
            ctx,
            "stun-filter",
            "STUN Binding Request dropped and counted",
            "STUN Binding Request was not dropped",
            ctx.hooks.stun_probe(),
        )
        .await,
    );
    if !ctx.exit_has_ipv6 {
        checks.push(
            check_counter(
                ctx,
                "ipv6-policy",
                "IPv6 dropped on an IPv4-only exit",
                "IPv6 packet was not dropped on an IPv4-only exit",
                ctx.hooks.ipv6_probe(),
            )
            .await,
        );
    }
    let needs_trace = ctx.exit == ExitIdentity::Warp || ctx.baseline_ip_hash.is_some();
    let trace = if needs_trace {
        bounded(ctx.probe_timeout * 3, ctx.hooks.trace()).await
    } else {
        Err(vw_core::VwError::Unsupported("trace not needed"))
    };
    checks.push(check_identity(ctx, &trace).await);
    if let Some(b) = &ctx.baseline_ip_hash {
        checks.push(check_real_ip(ctx, b, &trace));
    }
    let passed = checks.iter().all(|c| c.passed);
    if !passed {
        let failed: Vec<&str> = checks
            .iter()
            .filter(|c| !c.passed)
            .map(|c| c.name.as_str())
            .collect();
        tracing::warn!(failed = ?failed, "canary audit failed");
    }
    AuditReport {
        passed,
        checks,
        unix_time: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
    }
}

/// Await futures concurrently (small local helper; avoids a futures dep).
async fn join_all<F: std::future::Future>(futs: impl IntoIterator<Item = F>) -> Vec<F::Output> {
    let futs: Vec<F> = futs.into_iter().collect();
    let mut out = Vec::with_capacity(futs.len());
    let mut pinned: Vec<std::pin::Pin<Box<F>>> = futs.into_iter().map(Box::pin).collect();
    let mut results: Vec<Option<F::Output>> = (0..pinned.len()).map(|_| None).collect();
    std::future::poll_fn(|cx| {
        let mut pending = false;
        for (i, f) in pinned.iter_mut().enumerate() {
            if results[i].is_none() {
                match f.as_mut().poll(cx) {
                    std::task::Poll::Ready(v) => results[i] = Some(v),
                    std::task::Poll::Pending => pending = true,
                }
            }
        }
        if pending {
            std::task::Poll::Pending
        } else {
            std::task::Poll::Ready(())
        }
    })
    .await;
    for r in results.into_iter().flatten() {
        out.push(r);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use vw_crypto::attest::AttestationReport;
    use vw_crypto::identity::NodeIdentity;

    #[derive(Default)]
    struct Faults {
        disarmed: bool,
        leak: bool,
        dns_bypass: bool,
        stun_pass: bool,
        v6_pass: bool,
        wrong_identity: bool,
        warp_off: bool,
        same_ip: bool,
    }

    struct MemHooks {
        node: NodeIdentity,
        other: NodeIdentity,
        f: Faults,
        calls: Mutex<Vec<&'static str>>,
    }

    impl MemHooks {
        fn new(f: Faults) -> Self {
            Self {
                node: NodeIdentity::generate(),
                other: NodeIdentity::generate(),
                f,
                calls: Mutex::new(Vec::new()),
            }
        }
    }

    #[async_trait]
    impl CanaryHooks for MemHooks {
        async fn firewall(&self) -> Result<FirewallObservation> {
            let armed = !self.f.disarmed;
            Ok(FirewallObservation {
                armed_in_kernel: armed,
                status: FirewallMatrix {
                    ipv4_locked: armed,
                    ipv6_locked: armed,
                    dns_vault: armed,
                    stun_filter: true,
                    tunnelvision_guard: true,
                    boot_lock: true,
                    backend: "test".into(),
                },
            })
        }
        async fn physical_egress(&self, probe: &EgressProbe) -> EgressOutcome {
            self.calls.lock().unwrap().push(probe.name);
            if self.f.leak && probe.proto == EgressProto::Tcp {
                EgressOutcome::Reached(1)
            } else if probe.proto == EgressProto::Tcp {
                EgressOutcome::Blocked("EPERM".into())
            } else {
                EgressOutcome::NoReply
            }
        }
        async fn dns_probe(&self, name: &str) -> Result<DnsObservation> {
            assert!(name.ends_with(CANARY_ZONE));
            Ok(DnsObservation {
                resolver_answered: true,
                vault_saw_name: !self.f.dns_bypass,
                intercepted_before: 3,
                intercepted_after: 3,
            })
        }
        async fn stun_probe(&self) -> Result<CounterObservation> {
            Ok(CounterObservation {
                before: 0,
                after: if self.f.stun_pass { 0 } else { 1 },
                probe: vec![1, 2, 3],
            })
        }
        async fn ipv6_probe(&self) -> Result<CounterObservation> {
            Ok(CounterObservation {
                before: 5,
                after: if self.f.v6_pass { 5 } else { 6 },
                probe: vec![6],
            })
        }
        async fn attest(&self, nonce: [u8; 32]) -> Result<Vec<u8>> {
            let signer = if self.f.wrong_identity {
                &self.other
            } else {
                &self.node
            };
            let r = AttestationReport {
                binary_blake3: "0".repeat(64),
                swap_disabled: true,
                logging_off: true,
                ram_only: true,
                uptime_secs: 10,
                unix_time: 1,
                nonce,
                node_identity: signer.public(),
            };
            Ok(r.sign(signer).unwrap().encode().unwrap())
        }
        async fn trace(&self) -> Result<String> {
            let warp = if self.f.warp_off { "off" } else { "on" };
            let ip = if self.f.same_ip {
                "198.51.100.7"
            } else {
                "104.28.0.1"
            };
            Ok(format!("fl=1\nip={ip}\nwarp={warp}\n"))
        }
    }

    async fn run(h: &MemHooks, exit: ExitIdentity, baseline: bool) -> AuditReport {
        let salt = [7u8; 32];
        run_canary(&CanaryContext {
            hooks: h,
            exit,
            exit_has_ipv6: false,
            baseline_ip_hash: baseline.then(|| ip_hash(&salt, "198.51.100.7")),
            ip_salt: salt,
            probe_timeout: Duration::from_secs(2),
        })
        .await
    }

    fn vw_exit(h: &MemHooks) -> ExitIdentity {
        ExitIdentity::Voidwire {
            name: "n".into(),
            identity: h.node.public(),
        }
    }

    fn failed(r: &AuditReport) -> Vec<String> {
        r.checks
            .iter()
            .filter(|c| !c.passed)
            .map(|c| c.name.clone())
            .collect()
    }

    #[tokio::test]
    async fn all_pass_voidwire_and_warp() {
        let h = MemHooks::new(Faults::default());
        let r = run(&h, vw_exit(&h), false).await;
        assert!(r.passed, "{:?}", failed(&r));
        assert_eq!(r.checks.len(), 8);
        assert!(r.checks.iter().all(|c| c.proof.len() == 64));
        assert_eq!(h.calls.lock().unwrap().len(), 3);
        let r = run(&h, ExitIdentity::Warp, true).await;
        assert!(r.passed, "{:?}", failed(&r));
        assert!(r.checks.iter().any(|c| c.name == "real-ip"));
    }

    #[tokio::test]
    async fn each_failure_is_detected() {
        let cases: Vec<(Faults, &str, bool)> = vec![
            (
                Faults {
                    disarmed: true,
                    ..Default::default()
                },
                "firewall-kernel",
                false,
            ),
            (
                Faults {
                    leak: true,
                    ..Default::default()
                },
                "egress-tcp-https",
                false,
            ),
            (
                Faults {
                    dns_bypass: true,
                    ..Default::default()
                },
                "dns-vault",
                false,
            ),
            (
                Faults {
                    stun_pass: true,
                    ..Default::default()
                },
                "stun-filter",
                false,
            ),
            (
                Faults {
                    v6_pass: true,
                    ..Default::default()
                },
                "ipv6-policy",
                false,
            ),
            (
                Faults {
                    wrong_identity: true,
                    ..Default::default()
                },
                "exit-identity",
                false,
            ),
            (
                Faults {
                    warp_off: true,
                    ..Default::default()
                },
                "exit-identity",
                true,
            ),
            (
                Faults {
                    same_ip: true,
                    ..Default::default()
                },
                "real-ip",
                true,
            ),
        ];
        for (f, name, warp) in cases {
            let h = MemHooks::new(f);
            let exit = if warp {
                ExitIdentity::Warp
            } else {
                vw_exit(&h)
            };
            let r = run(&h, exit, warp).await;
            assert!(!r.passed, "{name} should fail");
            assert_eq!(failed(&r), vec![name.to_string()]);
        }
    }

    #[test]
    fn helpers() {
        let q = dns_query("a.bc", 0x1234);
        assert_eq!(&q[..2], &[0x12, 0x34]);
        assert_eq!(&q[12..], &[1, b'a', 2, b'b', b'c', 0, 0, 1, 0, 1]);
        assert!(canary_name().ends_with(CANARY_ZONE));
        assert_eq!(trace_field("ip=1.2.3.4\nwarp=on", "warp"), Some("on"));
        assert_eq!(trace_field("x", "warp"), None);
    }
}
