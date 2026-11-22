//! Iron Dome driver against in-memory nodes and a test firewall backend.

mod common;

use std::sync::atomic::Ordering;
use std::time::Duration;

use common::*;
use vw_core::config::Profile;
use vw_core::packet::{build_udp, IpView};
use vw_core::state::{DomeEvent as E, DomeState as S};
use vw_core::transport::TunDevice;

fn events(c: &vw_daemon::controller::Controller) -> Vec<E> {
    c.history().into_iter().map(|(_, e, _)| e).collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn full_up_single_hop_pq_canary_and_traffic() {
    let net = Net::new();
    let node = net.add_node("alpha", 10);
    let p = TestPlatform::new(net.clone());
    let c = controller(&p, std::slice::from_ref(&node)).await;
    assert_eq!(c.state(), S::Disarmed);

    c.up(Profile::Auto, None, None).await.expect("up");
    assert_eq!(c.state(), S::TunnelActive);
    assert_eq!(
        events(&c),
        vec![
            E::Arm,
            E::LockEngaged,
            E::HandshakeComplete,
            E::CanaryPassed
        ]
    );
    // The firewall was armed before any connection or TUN existed.
    let log = p.log();
    let arm = log.iter().position(|l| l == "fw-arm").unwrap();
    let first_connect = log.iter().position(|l| l == "connect").unwrap();
    let tun = log.iter().position(|l| l == "tun").unwrap();
    assert!(arm < first_connect && first_connect < tun, "{log:?}");
    assert!(
        p.dir.join("lockdown.armed").exists(),
        "boot-lock marker written"
    );
    // Final plan: only the entry pinned, tunnel interface allowed.
    let plan = p.last_plan().unwrap();
    assert_eq!(plan.pinned.len(), 1);
    assert_eq!(plan.pinned[0].addr, node.addr);
    assert_eq!(plan.tunnel.as_ref().unwrap().name, "vwtest0");
    // PQ handshake, attestation and canary evidence.
    assert!(node.vwcp_sessions.load(Ordering::SeqCst) >= 1);
    assert!(node.attestations.load(Ordering::SeqCst) >= 1);
    let snap = c.counters.snapshot();
    assert!(snap.stun_blocked >= 1 && snap.ipv6_dropped >= 1);

    // User traffic flows only now.
    let st = c.status().await;
    assert_eq!(st.hops.len(), 1);
    assert!(st.hops[0].post_quantum);
    assert!(st.crypto_suite.contains("ML-KEM"));
    let src = format!("{}:40000", plan.tunnel.as_ref().unwrap().v4.unwrap().0);
    let pkt = build_udp(
        src.parse().unwrap(),
        "198.51.100.20:443".parse().unwrap(),
        b"hello",
        64,
    )
    .unwrap();
    p.app().write_packet(&pkt).await.unwrap();
    let mut seen = false;
    for _ in 0..100 {
        if lock(&node.seen_user)
            .iter()
            .any(|s| IpView::parse(s).is_ok_and(|v| v.udp_payload(s) == Some(&b"hello"[..])))
        {
            seen = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(seen, "user packet reached the exit after the canary");

    // PQ rotation: KeyRotating ↔ TunnelActive with a fresh VWCP session.
    let before = node.vwcp_sessions.load(Ordering::SeqCst);
    c.rotate_now().await.expect("rotation");
    assert_eq!(c.state(), S::TunnelActive);
    assert!(node.vwcp_sessions.load(Ordering::SeqCst) > before);
    assert_eq!(c.counters.snapshot().pq_rotations, 1);

    // Down keeping the lockdown: still armed, no automatic disarm.
    c.down(true).await.unwrap();
    assert_eq!(c.state(), S::FailsafeLockdown);
    assert!(p.armed());
    c.disarm().await.unwrap();
    assert_eq!(c.state(), S::Disarmed);
    assert!(!p.armed());
    assert!(!p.dir.join("lockdown.armed").exists());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_hop_cascade_with_pq_on_both_hops() {
    let net = Net::new();
    let a = net.add_node("alpha", 10);
    let b = net.add_node("beta", 11);
    let p = TestPlatform::new(net.clone());
    let c = controller(&p, &[a.clone(), b.clone()]).await;
    if let Err(e) = c.up(Profile::Multihop, None, None).await {
        panic!("up failed: {e}; history {:?}", c.history());
    }
    assert_eq!(c.state(), S::TunnelActive);
    let st = c.status().await;
    assert_eq!(st.hops.len(), 2);
    assert!(st.hops.iter().all(|h| h.post_quantum));
    assert_eq!(st.mtu, Some(1280));
    assert!(a.vwcp_sessions.load(Ordering::SeqCst) >= 1);
    assert!(b.vwcp_sessions.load(Ordering::SeqCst) >= 1);
    // Only the entry is pinned.
    let plan = p.last_plan().unwrap();
    assert_eq!(plan.pinned.len(), 1);
    let entry = st.hops[0].name.clone();
    let entry_addr = if entry == "alpha" { a.addr } else { b.addr };
    assert_eq!(plan.pinned[0].addr, entry_addr);
    // Panic: next-best exit, firewall never disarmed.
    c.panic().await.expect("panic");
    assert_eq!(c.state(), S::TunnelActive);
    assert!(events(&c).contains(&E::Panic));
    assert!(!lock(&p.fw_ops).iter().any(|o| matches!(o, FwOp::Disarm)));
    assert!(p.log().contains(&"flush".to_string()));
    c.disarm().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn canary_failure_keeps_lockdown_and_never_allows_traffic() {
    let net = Net::new();
    let node = net.add_node("alpha", 10);
    let p = TestPlatform::new(net.clone());
    p.leak.store(true, Ordering::SeqCst);
    let c = controller(&p, &[node]).await;
    let mut rx = c.events.subscribe();
    assert!(c.up(Profile::Auto, None, None).await.is_err());
    assert_eq!(c.state(), S::FailsafeLockdown);
    assert!(p.armed());
    let h = c.history();
    assert!(h.iter().all(|(_, _, to)| *to != S::TunnelActive));
    assert!(events(&c).contains(&E::CanaryFailed));
    assert!(!c.gate().is_open());
    // An Audit event with the failing egress check was broadcast.
    let mut saw = false;
    while let Ok(ev) = rx.try_recv() {
        if let vw_core::ipc::DaemonEvent::Audit(r) = ev {
            saw |= !r.passed
                && r.checks
                    .iter()
                    .any(|c| c.name.starts_with("egress") && !c.passed);
        }
    }
    assert!(saw);
    // Down (keep) does not disarm; only Disarm does.
    c.down(true).await.unwrap();
    assert!(p.armed());
    c.disarm().await.unwrap();
    assert!(!p.armed());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn unreachable_gateway_is_a_handshake_failure_under_lockdown() {
    let net = Net::new();
    let node = net.add_node("alpha", 10);
    node.kill();
    let p = TestPlatform::new(net.clone());
    let c = controller(&p, &[node]).await;
    assert!(c.up(Profile::Auto, None, None).await.is_err());
    assert_eq!(c.state(), S::FailsafeLockdown);
    assert_eq!(events(&c), vec![E::Arm, E::LockEngaged, E::HandshakeFailed]);
    assert!(p.armed());
    assert!(matches!(lock(&p.fw_ops).first(), Some(FwOp::Arm(plan)) if plan.pinned.is_empty()));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn transport_loss_is_link_lost_and_stays_locked() {
    let net = Net::new();
    let node = net.add_node("alpha", 10);
    let p = TestPlatform::new(net.clone());
    let c = controller(&p, std::slice::from_ref(&node)).await;
    c.up(Profile::Auto, None, None).await.unwrap();
    node.kill();
    let mut ok = false;
    for _ in 0..100 {
        if events(&c).contains(&E::LinkLost) {
            ok = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(ok, "link loss detected");
    assert_ne!(c.state(), S::TunnelActive);
    assert_ne!(c.state(), S::Disarmed);
    assert!(p.armed());
    c.disarm().await.unwrap();
    assert_eq!(c.state(), S::Disarmed);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn boot_lock_arms_before_anything_else() {
    let net = Net::new();
    let p = TestPlatform::new(net.clone());
    std::fs::write(p.dir.join("lockdown.armed"), b"armed\n").unwrap();
    let c = controller(&p, &[]).await;
    assert_eq!(events(&c).first(), Some(&E::Arm));
    assert_eq!(p.log().first().map(String::as_str), Some("fw-arm"));
    // No nodes: the automatic reconnect fails into lockdown, never disarmed.
    for _ in 0..50 {
        if c.state() == S::FailsafeLockdown {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(c.state(), S::FailsafeLockdown);
    assert!(p.armed());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn exec_requires_active_tunnel_and_is_system_wide_off_linux() {
    let net = Net::new();
    let node = net.add_node("alpha", 10);
    let p = TestPlatform::new(net.clone());
    let c = controller(&p, &[node]).await;
    assert!(c.exec_prepare().await.is_err());
    c.up(Profile::Auto, None, None).await.unwrap();
    let t = c.exec_prepare().await.unwrap();
    assert!(t.netns.is_none());
    assert!(t.isolation.contains("system-wide"));
    let r = c.audit().await.unwrap();
    assert!(r.passed, "{:?}", r.checks);
    c.disarm().await.unwrap();
}
