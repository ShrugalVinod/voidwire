//! The daemon's [`CanaryHooks`]: OS probes through the [`Platform`], in-tunnel
//! probes through the live pipeline.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use vw_core::consts::{STUN_MAGIC, TTL_NORMAL};
use vw_core::packet::{build_udp, PROTO_TCP, PROTO_UDP};
use vw_core::telemetry::Counters;
use vw_core::{Result, VwError};
use vw_dns::DnsVault;
use vw_firewall::FirewallBackend;
use vw_leakaudit::canary::{
    CanaryHooks, CounterObservation, DnsObservation, EgressOutcome, EgressProbe,
    FirewallObservation,
};

use crate::link::{vwcp_attest, TunnelLink};
use crate::pipeline::Permit;
use crate::platform::Platform;
use crate::tunnel::ActiveTunnel;
use crate::util::ephemeral_port;

/// Hooks over one live tunnel.
pub struct DaemonHooks<'a> {
    pub platform: &'a dyn Platform,
    pub firewall: Arc<Mutex<Box<dyn FirewallBackend>>>,
    pub tunnel: &'a ActiveTunnel,
    pub gate: &'a crate::pipeline::Gate,
    pub counters: &'a Counters,
    pub vault: Option<Arc<DnsVault>>,
    /// Inspector state to restore after the DNS probe.
    pub inspector_setting: bool,
}

const PROBE_TTL: Duration = Duration::from_secs(10);

/// RFC 5389 Binding Request.
pub fn stun_binding_request() -> Vec<u8> {
    let mut p = vec![0x00, 0x01, 0x00, 0x00];
    p.extend_from_slice(&STUN_MAGIC.to_be_bytes());
    p.extend_from_slice(&rand::random::<[u8; 12]>());
    p
}

async fn wait_counter(c: &AtomicU64, before: u64, timeout: Duration) -> u64 {
    let deadline = tokio::time::Instant::now() + timeout;
    let mut iv = tokio::time::interval(Duration::from_millis(10));
    loop {
        let v = c.load(Relaxed);
        if v > before || tokio::time::Instant::now() >= deadline {
            return v;
        }
        iv.tick().await;
    }
}

impl DaemonHooks<'_> {
    async fn inject_counted(
        &self,
        pkt: Vec<u8>,
        port: u16,
        c: &AtomicU64,
    ) -> Result<CounterObservation> {
        let permit = Permit::Local {
            proto: PROTO_UDP,
            port,
        };
        self.gate.permit(permit, PROBE_TTL);
        let before = c.load(Relaxed);
        let r = self.tunnel.mux.inject(pkt.clone()).await;
        let after = match r {
            Ok(()) => wait_counter(c, before, Duration::from_secs(2)).await,
            Err(_) => before,
        };
        self.gate.revoke(permit);
        r?;
        Ok(CounterObservation {
            before,
            after,
            probe: pkt,
        })
    }
}

#[async_trait]
impl CanaryHooks for DaemonHooks<'_> {
    async fn firewall(&self) -> Result<FirewallObservation> {
        let fw = self.firewall.lock().unwrap_or_else(|p| p.into_inner());
        Ok(FirewallObservation {
            armed_in_kernel: fw.is_armed_in_kernel()?,
            status: fw.status()?.into(),
        })
    }

    async fn physical_egress(&self, probe: &EgressProbe) -> EgressOutcome {
        self.platform.egress_probe(probe).await
    }

    async fn dns_probe(&self, name: &str) -> Result<DnsObservation> {
        let vault = self
            .vault
            .as_ref()
            .ok_or_else(|| VwError::Dns("DNS vault not running".into()))?;
        let mut rx = vault.subscribe();
        vault.set_inspector(true);
        let before = self.counters.dns_intercepted.load(Relaxed);
        let answered = self.platform.system_resolve(name).await;
        let mut saw = false;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(1);
        while let Ok(Ok(ev)) = tokio::time::timeout_at(deadline, rx.recv()).await {
            if ev.name.trim_end_matches('.').eq_ignore_ascii_case(name) {
                saw = true;
                break;
            }
        }
        vault.set_inspector(self.inspector_setting);
        Ok(DnsObservation {
            resolver_answered: answered,
            vault_saw_name: saw,
            intercepted_before: before,
            intercepted_after: self.counters.dns_intercepted.load(Relaxed),
        })
    }

    async fn stun_probe(&self) -> Result<CounterObservation> {
        let port = ephemeral_port();
        let src = SocketAddr::new(IpAddr::V4(self.tunnel.tun_v4.0), port);
        let dst = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1)), 3478);
        let pkt = build_udp(src, dst, &stun_binding_request(), TTL_NORMAL)?;
        self.inject_counted(pkt, port, &self.counters.stun_blocked)
            .await
    }

    async fn ipv6_probe(&self) -> Result<CounterObservation> {
        let port = ephemeral_port();
        let src = SocketAddr::new(IpAddr::V6(vw_core::consts::CLIENT_POOL_V6.0), port);
        let dst = SocketAddr::new(
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
            443,
        );
        let pkt = build_udp(src, dst, b"voidwire-canary-v6", TTL_NORMAL)?;
        self.inject_counted(pkt, port, &self.counters.ipv6_dropped)
            .await
    }

    async fn attest(&self, nonce: [u8; 32]) -> Result<Vec<u8>> {
        let last = self.tunnel.hops.len() - 1;
        let src = SocketAddr::new(
            IpAddr::V4(self.tunnel.hop_addr(last)),
            self.tunnel.hops[last].src_port,
        );
        let mut link = TunnelLink::new(
            self.tunnel.engine.clone(),
            self.tunnel.transport.clone(),
            last,
            &self.tunnel.bus,
        );
        vwcp_attest(&mut link, src, nonce, Duration::from_secs(5)).await
    }

    async fn trace(&self) -> Result<String> {
        let permits: Vec<Permit> = crate::platform::IP_CHECKERS
            .iter()
            .flat_map(|(_, ips)| ips.iter())
            .map(|o| Permit::Remote {
                proto: PROTO_TCP,
                addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::from(*o)), 443),
            })
            .collect();
        for p in &permits {
            self.gate.permit(*p, PROBE_TTL * 3);
        }
        // Every checker in turn; one retry round for busy free servers.
        let mut r = self.platform.https_trace(false).await;
        if r.is_err() {
            tokio::time::sleep(Duration::from_millis(700)).await;
            r = self.platform.https_trace(false).await;
        }
        for p in &permits {
            self.gate.revoke(*p);
        }
        r
    }
}
