//! A daemon panic fires `Fault`: traffic stops, the firewall stays armed.

mod common;

use common::*;
use vw_core::config::Profile;
use vw_core::state::DomeState as S;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn panic_fires_fault_and_keeps_lockdown() {
    let net = Net::new();
    let node = net.add_node("alpha", 10);
    let p = TestPlatform::new(net.clone());
    let c = controller(&p, &[node]).await;
    vw_daemon::controller::install_panic_hook(&c);
    c.up(Profile::Auto, None, None, None).await.unwrap();
    assert!(c.gate().is_open());
    let r = std::thread::spawn(|| panic!("simulated daemon bug")).join();
    assert!(r.is_err());
    assert_eq!(c.state(), S::FailsafeLockdown);
    assert!(!c.gate().is_open());
    assert!(p.armed());
}
