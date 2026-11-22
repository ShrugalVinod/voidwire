//! VWIPC request handling over `tokio::io::duplex`.

mod common;

use common::*;
use vw_core::config::Profile;
use vw_core::ipc::{DaemonEvent, IpcClient, Request, Response};

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn requests_and_event_stream() {
    let net = Net::new();
    let node = net.add_node("alpha", 10);
    let p = TestPlatform::new(net.clone());
    let c = controller(&p, &[]).await;
    let token = key32();

    let (a, b) = tokio::io::duplex(1 << 20);
    let (c2, t2) = (c.clone(), token.clone());
    tokio::spawn(async move { vw_daemon::ipc_server::serve_connection(c2, b, &t2).await });
    let mut cl = IpcClient::handshake(Box::new(a), &token).await.unwrap();

    let Response::Status(s) = cl.request(&Request::Status).await.unwrap() else {
        panic!()
    };
    assert_eq!(s.state, vw_core::state::DomeState::Disarmed);
    assert_eq!(s.firewall.backend, "test");

    let uri = vw_core::uri::encode_node(&node.descriptor()).unwrap();
    assert_eq!(
        cl.request(&Request::ImportNode { uri }).await.unwrap(),
        Response::Ok
    );
    let Response::Nodes(n) = cl.request(&Request::ListNodes).await.unwrap() else {
        panic!()
    };
    assert_eq!(n.len(), 1);
    assert!(n[0].post_quantum);
    assert!(cl
        .request(&Request::ImportNode {
            uri: "https://x".into()
        })
        .await
        .is_err());

    let Response::Settings(mut st) = cl.request(&Request::GetSettings).await.unwrap() else {
        panic!()
    };
    st.live_inspector = true;
    assert_eq!(
        cl.request(&Request::SetSettings(st.clone())).await.unwrap(),
        Response::Ok
    );
    let Response::Settings(back) = cl.request(&Request::GetSettings).await.unwrap() else {
        panic!()
    };
    assert!(back.live_inspector);
    st.pq_rotate_secs = 1;
    assert!(cl.request(&Request::SetSettings(st)).await.is_err());

    assert!(matches!(
        cl.request(&Request::Telemetry).await.unwrap(),
        Response::Telemetry(_)
    ));
    assert!(cl.request(&Request::ExecPrepare).await.is_err());
    assert!(
        cl.request(&Request::Panic).await.is_err(),
        "nothing to panic while disarmed"
    );
    assert!(
        cl.request(&Request::Optimize).await.is_err(),
        "never probe outside the lockdown"
    );

    // A second, subscribed connection sees state changes from the first.
    let (a2, b2) = tokio::io::duplex(1 << 20);
    let (c3, t3) = (c.clone(), token.clone());
    tokio::spawn(async move { vw_daemon::ipc_server::serve_connection(c3, b2, &t3).await });
    let sub = IpcClient::handshake(Box::new(a2), &token).await.unwrap();
    let mut events = sub.subscribe().await.unwrap();
    assert!(matches!(
        events.next().await.unwrap(),
        DaemonEvent::Telemetry(_)
    ));

    let up = Request::Up {
        profile: Profile::Auto,
        country: None,
        transport: None,
        gateway: None,
    };
    assert_eq!(cl.request(&up).await.unwrap(), Response::Ok);
    let mut states = Vec::new();
    let mut decision = false;
    while states.last() != Some(&vw_core::state::DomeState::TunnelActive) {
        match tokio::time::timeout(std::time::Duration::from_secs(5), events.next())
            .await
            .unwrap()
            .unwrap()
        {
            DaemonEvent::StateChanged { to, .. } => states.push(to),
            DaemonEvent::Decision(_) => decision = true,
            _ => {}
        }
    }
    assert!(decision);
    assert_eq!(
        states.first(),
        Some(&vw_core::state::DomeState::ArmingBootLock)
    );

    let Response::Audit(r) = cl.request(&Request::Audit).await.unwrap() else {
        panic!()
    };
    assert!(r.passed);
    let Response::Status(s) = cl.request(&Request::Status).await.unwrap() else {
        panic!()
    };
    assert_eq!(s.hops.len(), 1);
    assert!(s.decision.is_some());
    assert_eq!(cl.request(&Request::Disarm).await.unwrap(), Response::Ok);
    assert!(!p.armed());
}

#[tokio::test]
async fn wrong_token_is_rejected() {
    let p = TestPlatform::new(Net::new());
    let c = controller(&p, &[]).await;
    let (a, b) = tokio::io::duplex(4096);
    let good = key32();
    let srv =
        tokio::spawn(async move { vw_daemon::ipc_server::serve_connection(c, b, &good).await });
    assert!(IpcClient::handshake(Box::new(a), &key32()).await.is_err());
    assert!(srv.await.unwrap().is_err());
}
