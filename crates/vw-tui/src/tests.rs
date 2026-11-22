//! Unit, rendering and runtime tests. All daemon data here is test-only.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crossterm::event::{Event, KeyCode, KeyEvent, KeyEventKind, KeyEventState, KeyModifiers};
use ratatui::backend::TestBackend;
use ratatui::Terminal;
use vw_core::config::{NodeKind, NodeRole, Profile, TransportKind};
use vw_core::ipc::{
    read_frame, server_handshake, write_frame, AuditCheck, AuditReport, DaemonEvent,
    FirewallMatrix, HopInfo, IpcClient, Request, Response, StatusReport,
};
use vw_core::probe::{NetworkVerdict, OptimizerDecision, ProbeResult};
use vw_core::secret::Key32;
use vw_core::state::DomeState;
use vw_core::telemetry::{ShieldCounts, TelemetrySnapshot};

use crate::app::{rate_between, Link, Tone, BANNER_TTL, RATE_HISTORY};
use crate::{map_key, Action, App, Command, Focus};

// ───────────────────────────── fixtures ────────────────────────────────

fn pq_hop(name: &str, role: NodeRole, coords: Option<(f64, f64)>) -> HopInfo {
    HopInfo {
        name: name.into(),
        kind: NodeKind::Voidwire,
        role,
        country: Some("DE".into()),
        transport: TransportKind::AmneziaWg,
        post_quantum: true,
        rtt_ms: Some(23.4),
        coords,
    }
}

fn warp_hop() -> HopInfo {
    HopInfo {
        name: "warp-anycast".into(),
        kind: NodeKind::Warp,
        role: NodeRole::Entry,
        country: None,
        transport: TransportKind::NativeUdp,
        post_quantum: false,
        rtt_ms: Some(9.0),
        coords: Some((37.77, -122.42)),
    }
}

fn decision() -> OptimizerDecision {
    let cand = |name: &str, score: f64| ProbeResult {
        node_name: name.into(),
        transport: TransportKind::AmneziaWg,
        reachable: true,
        handshake_ms: Some(30.0),
        rtt_ms: Some(20.0),
        jitter_ms: Some(1.0),
        loss: 0.0,
        throughput_mbps: Some(200.0),
        post_quantum: true,
        score,
    };
    OptimizerDecision {
        hops: vec!["fra-entry".into(), "ams-exit".into()],
        transport: TransportKind::AmneziaWg,
        mtu: 1280,
        mss_v4: 1240,
        daita: true,
        verdict: NetworkVerdict::default(),
        candidates: vec![cand("slow-node", 12.5), cand("best-node", 98.7)],
        reason: "lowest latency PQ pair".into(),
    }
}

fn sample_status(state: DomeState) -> StatusReport {
    StatusReport {
        state,
        profile: Some(Profile::Multihop),
        hops: vec![
            pq_hop("fra-entry", NodeRole::Entry, Some((50.11, 8.68))),
            pq_hop("ams-exit", NodeRole::Exit, Some((52.37, 4.90))),
        ],
        transport: Some(TransportKind::AmneziaWg),
        crypto_suite: "X25519+ML-KEM-1024 hybrid · ChaCha20-Poly1305 · BLAKE3".into(),
        uptime_secs: 3_723,
        mtu: Some(1280),
        daita: true,
        firewall: FirewallMatrix {
            ipv4_locked: true,
            ipv6_locked: true,
            dns_vault: true,
            stun_filter: true,
            tunnelvision_guard: true,
            boot_lock: false,
            backend: "pf".into(),
        },
        last_rotation_secs_ago: Some(42),
        telemetry: TelemetrySnapshot {
            rx_bytes: 10_000,
            tx_bytes: 5_000,
            stun_blocked: 3,
            shield: ShieldCounts {
                ads: 120,
                trackers: 45,
                telemetry: 12,
                malware: 1,
                custom: 0,
                cname_uncloaked: 7,
            },
            ..TelemetrySnapshot::default()
        },
        decision: Some(decision()),
        platform: "macos-aarch64".into(),
        daemon_version: "0.1.0".into(),
    }
}

fn telemetry(rx: u64, tx: u64) -> TelemetrySnapshot {
    TelemetrySnapshot {
        rx_bytes: rx,
        tx_bytes: tx,
        ..TelemetrySnapshot::default()
    }
}

fn audit(passed: bool) -> AuditReport {
    AuditReport {
        passed,
        checks: vec![
            AuditCheck {
                name: "dns-canary".into(),
                passed: true,
                detail: "resolved via vault".into(),
                proof: "a1b2c3d4e5f60718293a4b5c".into(),
            },
            AuditCheck {
                name: "ipv6-egress".into(),
                passed,
                detail: "no v6 egress".into(),
                proof: "ffeeddccbbaa99887766".into(),
            },
        ],
        unix_time: 1_700_000_000,
    }
}

fn online_app(state: DomeState) -> App {
    let mut app = App::new();
    app.link_up("0.1.0".into());
    app.events_up();
    app.apply_status(sample_status(state));
    app
}

fn key(code: KeyCode) -> KeyEvent {
    KeyEvent::new(code, KeyModifiers::NONE)
}

fn render(app: &App, w: u16, h: u16) -> String {
    let mut term = Terminal::new(TestBackend::new(w, h)).unwrap();
    term.draw(|f| crate::ui::draw(f, app)).unwrap();
    let buf = term.backend().buffer().clone();
    let mut out = String::new();
    for y in 0..h {
        for x in 0..w {
            out.push_str(buf[(x, y)].symbol());
        }
        out.push('\n');
    }
    out
}

// ───────────────────────────── key mapping ─────────────────────────────

#[test]
fn keys_map_to_actions() {
    let cases = [
        (KeyCode::Char('P'), Action::Panic),
        (KeyCode::Char('p'), Action::Panic),
        (KeyCode::Char('c'), Action::Connect),
        (KeyCode::Char('d'), Action::Disconnect),
        (KeyCode::Char('D'), Action::RequestDisarm),
        (KeyCode::Char('a'), Action::Audit),
        (KeyCode::Char('o'), Action::Optimize),
        (KeyCode::Char('q'), Action::Quit),
        (KeyCode::Esc, Action::Quit),
        (KeyCode::Tab, Action::FocusNext),
        (KeyCode::BackTab, Action::FocusPrev),
        (KeyCode::Char('x'), Action::None),
        (KeyCode::Char('y'), Action::None),
    ];
    for (code, want) in cases {
        assert_eq!(map_key(key(code), false), want, "{code:?}");
    }
    let ctrl_c = KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL);
    assert_eq!(map_key(ctrl_c, false), Action::Quit);
    assert_eq!(map_key(ctrl_c, true), Action::Quit);
}

#[test]
fn confirm_mode_keys() {
    assert_eq!(
        map_key(key(KeyCode::Char('y')), true),
        Action::ConfirmDisarm
    );
    assert_eq!(
        map_key(key(KeyCode::Char('Y')), true),
        Action::ConfirmDisarm
    );
    assert_eq!(
        map_key(key(KeyCode::Char('n')), true),
        Action::CancelConfirm
    );
    assert_eq!(map_key(key(KeyCode::Esc), true), Action::CancelConfirm);
    // A stray `P` while confirming must not trigger a panic rotation.
    assert_eq!(
        map_key(key(KeyCode::Char('P')), true),
        Action::CancelConfirm
    );
}

#[test]
fn key_release_is_ignored() {
    let release = KeyEvent {
        code: KeyCode::Char('P'),
        modifiers: KeyModifiers::SHIFT,
        kind: KeyEventKind::Release,
        state: KeyEventState::NONE,
    };
    assert_eq!(map_key(release, false), Action::None);
}

#[test]
fn commands_send_the_right_requests() {
    assert_eq!(Command::Panic.request(), Request::Panic);
    assert_eq!(
        Command::Connect.request(),
        Request::Up {
            profile: Profile::Auto,
            country: None,
            transport: None,
            gateway: None
        }
    );
    assert_eq!(
        Command::Disconnect.request(),
        Request::Down {
            keep_lockdown: true
        }
    );
    assert_eq!(Command::Disarm.request(), Request::Disarm);
    assert_eq!(Command::Audit.request(), Request::Audit);
    assert_eq!(Command::Optimize.request(), Request::Optimize);
}

// ───────────────────────────── app state ───────────────────────────────

#[test]
fn status_brings_link_online_and_link_loss_clears_data() {
    let mut app = App::new();
    assert_eq!(app.link, Link::Connecting);
    app.apply_status(sample_status(DomeState::TunnelActive));
    assert!(app.is_online());
    assert_eq!(app.state(), Some(DomeState::TunnelActive));
    assert!(app.decision.is_some());

    app.link_down("cannot reach voidwired".into());
    assert!(app.status.is_none());
    assert!(app.decision.is_none());
    assert!(app.rx.is_empty());
    assert_eq!(
        app.link,
        Link::Offline {
            error: "cannot reach voidwired".into(),
            attempts: 1
        }
    );
    app.link_down("again".into());
    assert!(matches!(app.link, Link::Offline { attempts: 2, .. }));
    app.link_up("0.1.0".into());
    assert!(app.is_online());
}

#[test]
fn events_update_state() {
    let mut app = online_app(DomeState::TunnelActive);
    app.apply_event(DaemonEvent::StateChanged {
        from: DomeState::TunnelActive,
        to: DomeState::FailsafeLockdown,
    });
    assert_eq!(app.state(), Some(DomeState::FailsafeLockdown));
    assert_eq!(app.logs.back().unwrap().level, "state");

    app.apply_event(DaemonEvent::Audit(audit(false)));
    assert!(!app.last_audit.as_ref().unwrap().passed);

    let mut d = decision();
    d.reason = "network changed".into();
    app.apply_event(DaemonEvent::Decision(d));
    assert_eq!(app.decision.as_ref().unwrap().reason, "network changed");

    app.apply_event(DaemonEvent::Log {
        level: "warn".into(),
        message: "rotation slow".into(),
    });
    assert_eq!(app.logs.back().unwrap().message, "rotation slow");

    app.apply_event(DaemonEvent::DnsInspect {
        name: "example.com".into(),
        category: None,
        blocked: false,
    });
    assert!(app.logs.iter().all(|l| !l.message.contains("example.com")));

    app.apply_audit(audit(true));
    assert!(app.last_audit.as_ref().unwrap().passed);
}

#[test]
fn rate_between_handles_edge_cases() {
    assert_eq!(rate_between(0, 2048, Duration::from_secs(2)), Some(1024));
    assert_eq!(rate_between(1000, 1000, Duration::from_secs(1)), Some(0));
    assert_eq!(rate_between(5000, 100, Duration::from_secs(1)), None);
    assert_eq!(rate_between(0, 100, Duration::ZERO), None);
    assert_eq!(
        rate_between(0, 1500, Duration::from_millis(500)),
        Some(3000)
    );
}

#[test]
fn rates_from_successive_snapshots() {
    let t0 = Instant::now();
    let mut app = App::new();
    let mut st = sample_status(DomeState::TunnelActive);
    st.telemetry = telemetry(0, 0);
    app.apply_status_at(st.clone(), t0);
    assert!(app.rx.is_empty(), "first snapshot is only a baseline");

    st.telemetry = telemetry(1024 * 1024, 2048);
    app.apply_status_at(st.clone(), t0 + Duration::from_secs(1));
    assert_eq!(app.rx.current(), Some(1024 * 1024));
    assert_eq!(app.tx.current(), Some(2048));

    // An event arriving right after the poll is too close to sample from.
    app.apply_event_at(
        DaemonEvent::Telemetry(telemetry(1024 * 1024 + 10, 2048)),
        t0 + Duration::from_millis(1100),
    );
    assert_eq!(app.rx.len(), 1);
    assert_eq!(
        app.status.as_ref().unwrap().telemetry.rx_bytes,
        1024 * 1024 + 10
    );

    app.apply_event_at(
        DaemonEvent::Telemetry(telemetry(3 * 1024 * 1024, 4096)),
        t0 + Duration::from_secs(3),
    );
    assert_eq!(app.rx.current(), Some(1024 * 1024));
    assert_eq!(app.tx.current(), Some(1024));
    assert_eq!(app.rx.peak(), 1024 * 1024);

    // Counter reset (daemon restart) clears history rather than spiking.
    app.apply_event_at(
        DaemonEvent::Telemetry(telemetry(10, 10)),
        t0 + Duration::from_secs(4),
    );
    assert!(app.rx.is_empty());
}

#[test]
fn rate_history_is_bounded() {
    let t0 = Instant::now();
    let mut app = App::new();
    for i in 0..(RATE_HISTORY as u64 + 30) {
        app.apply_event_at(
            DaemonEvent::Telemetry(telemetry(i * 100, i * 10)),
            t0 + Duration::from_secs(i),
        );
    }
    assert_eq!(app.rx.len(), RATE_HISTORY);
    assert_eq!(app.rx.tail(5), vec![100; 5]);
    assert_eq!(app.tx.tail(1000).len(), RATE_HISTORY);
}

#[test]
fn actions_respect_link_and_confirmation() {
    let now = Instant::now();
    let mut offline = App::new();
    offline.link_down("down".into());
    assert_eq!(offline.perform(Action::Panic, now), None);
    assert_eq!(offline.banner.as_ref().unwrap().tone, Tone::Warning);

    let mut app = online_app(DomeState::TunnelActive);
    assert_eq!(app.perform(Action::Panic, now), Some(Command::Panic));
    assert_eq!(
        app.perform(Action::Panic, now),
        None,
        "no duplicate in flight"
    );
    assert_eq!(app.in_flight, vec![Command::Panic]);

    assert_eq!(app.perform(Action::RequestDisarm, now), None);
    assert!(app.confirm_disarm);
    assert_eq!(app.perform(Action::CancelConfirm, now), None);
    assert!(!app.confirm_disarm);
    app.perform(Action::RequestDisarm, now);
    assert_eq!(
        app.perform(Action::ConfirmDisarm, now),
        Some(Command::Disarm)
    );
    assert!(!app.confirm_disarm);

    assert_eq!(app.perform(Action::FocusNext, now), None);
    assert_eq!(app.focus, Focus::Map);
    app.perform(Action::FocusPrev, now);
    app.perform(Action::FocusPrev, now);
    assert_eq!(app.focus, Focus::Log);

    app.perform(Action::Quit, now);
    assert!(app.should_quit);
}

#[test]
fn focus_cycle_visits_every_panel() {
    let mut f = Focus::Overview;
    for _ in 0..Focus::ORDER.len() {
        f = f.next();
    }
    assert_eq!(f, Focus::Overview);
    assert_eq!(Focus::Overview.prev(), Focus::Log);
}

#[test]
fn command_results_flash_banners() {
    let now = Instant::now();
    let mut app = online_app(DomeState::TunnelActive);
    app.perform(Action::Panic, now);
    app.apply_command_result(Command::Panic, Ok(Response::Ok), now);
    assert!(app.in_flight.is_empty());
    let b = app.banner.clone().unwrap();
    assert_eq!(b.tone, Tone::Success);
    assert!(b.text.contains("IDENTITY ROTATED"));

    app.apply_command_result(Command::Panic, Err("rotation timed out".into()), now);
    let b = app.banner.clone().unwrap();
    assert_eq!(b.tone, Tone::Danger);
    assert!(b.text.contains("rotation timed out"));

    app.apply_command_result(Command::Audit, Ok(Response::Audit(audit(false))), now);
    assert!(app.banner.as_ref().unwrap().text.contains("AUDIT FAILED"));
    assert!(!app.last_audit.as_ref().unwrap().passed);

    let mut d = decision();
    d.hops = vec!["x".into()];
    app.apply_command_result(Command::Optimize, Ok(Response::Optimized(Box::new(d))), now);
    assert_eq!(app.decision.as_ref().unwrap().hops, vec!["x".to_string()]);

    app.tick(now + BANNER_TTL - Duration::from_millis(1));
    assert!(app.banner.is_some());
    app.tick(now + BANNER_TTL);
    assert!(app.banner.is_none());
}

// ───────────────────────────── rendering ───────────────────────────────

#[test]
fn renders_protected_dashboard() {
    let mut app = online_app(DomeState::TunnelActive);
    app.apply_audit(audit(true));
    let s = render(&app, 140, 44);
    for needle in [
        "VOIDWIRE",
        "PROTECTED",
        "CVE-2024-3661",
        "ML-KEM-1024",
        "World Route Map",
        "YOU",
        "not geolocated",
        "fra-entry",
        "Ghost Multi-Hop",
        "AmneziaWG",
        "01:02:03",
        "macos-aarch64",
        "PASSED",
        "a1b2c3d4e5f6",
        "best-node",
        "lowest latency PQ pair",
        "CNAME-uncloaked",
        "pre-canary",
        "panic",
    ] {
        assert!(s.contains(needle), "missing {needle:?} in\n{s}");
    }
    assert!(!s.contains("LOCKDOWN"));
    assert!(!s.contains("no post-quantum protection"));
    // Highest-scoring candidate is listed first.
    assert!(s.find("best-node").unwrap() < s.find("slow-node").unwrap());
}

#[test]
fn renders_lockdown_badge() {
    let app = online_app(DomeState::FailsafeLockdown);
    let s = render(&app, 120, 40);
    assert!(s.contains("LOCKDOWN"));
    assert!(!s.contains("PROTECTED"));
}

#[test]
fn transitional_states_are_not_protected() {
    for st in [
        DomeState::Handshaking,
        DomeState::CanaryAuditing,
        DomeState::ArmingBootLock,
        DomeState::Disarming,
        DomeState::Disarmed,
    ] {
        let s = render(&online_app(st), 120, 40);
        assert!(!s.contains("PROTECTED"), "{st:?}");
        assert!(!s.contains("LOCKDOWN"), "{st:?}");
    }
    assert!(render(&online_app(DomeState::KeyRotating), 120, 40).contains("PROTECTED"));
}

#[test]
fn warns_about_non_pq_hops() {
    let mut app = online_app(DomeState::TunnelActive);
    let mut st = sample_status(DomeState::TunnelActive);
    st.hops[0] = warp_hop();
    st.crypto_suite = "Noise_IKpsk2 X25519 · ChaCha20-Poly1305 (classical)".into();
    app.apply_status(st);
    app.focus = Focus::Crypto;
    let s = render(&app, 160, 30);
    assert!(s.contains("CLASSICAL"));
    assert!(
        s.contains(
            "Hop 1 (warp-anycast) is classical WireGuard (WARP): no post-quantum protection"
        ),
        "{s}"
    );
    assert!(!s.contains("ML-KEM-1024"));
}

#[test]
fn small_terminal_collapses_map() {
    let app = online_app(DomeState::TunnelActive);
    let s = render(&app, 80, 24);
    assert!(!s.contains("World Route Map"));
    assert!(s.contains("YOU ─▶ 1 fra-entry"), "{s}");
    assert!(s.contains("PROTECTED"));
    assert!(s.contains("CVE-2024-3661"));
    // Focusing the map shows it even on a small terminal.
    let mut app = app;
    app.focus = Focus::Map;
    assert!(render(&app, 80, 24).contains("World Route Map"));
}

#[test]
fn every_view_renders_at_every_size() {
    let mut app = online_app(DomeState::TunnelActive);
    app.apply_audit(audit(false));
    app.set_banner("hello", Tone::Info, Instant::now());
    for focus in Focus::ORDER {
        app.focus = focus;
        for (w, h) in [(20, 5), (80, 24), (100, 30), (200, 60)] {
            let s = render(&app, w, h);
            if w >= 80 {
                assert!(s.contains("VOIDWIRE"), "{focus:?} {w}x{h}");
            }
        }
    }
    app.confirm_disarm = true;
    assert!(render(&app, 80, 24).contains("DISARM IRON DOME"));
    render(&app, 10, 3);
}

#[test]
fn unreachable_daemon_is_full_screen() {
    let mut app = App::new();
    assert!(render(&app, 80, 24).contains("CONNECTING"));
    app.link_down("cannot reach voidwired at /var/run/voidwire/voidwired.sock".into());
    let s = render(&app, 100, 30);
    assert!(s.contains("DAEMON UNREACHABLE"));
    assert!(s.contains("cannot reach voidwired"));
    assert!(s.contains("Retrying every 2 s"));
    assert!(!s.contains("PROTECTED"));
}

// ───────────────────────────── runtime ─────────────────────────────────

/// A minimal in-process daemon speaking real VWIPC over a duplex pipe.
async fn fake_daemon(
    mut io: tokio::io::DuplexStream,
    token: Key32,
    panicked: Arc<AtomicBool>,
    notify: tokio::sync::mpsc::UnboundedSender<&'static str>,
) {
    if server_handshake(&mut io, &token, "0.1.0-test")
        .await
        .is_err()
    {
        return;
    }
    loop {
        let Ok(req) = read_frame::<_, Request>(&mut io).await else {
            return;
        };
        let resp = match req {
            Request::Status => {
                let _ = notify.send("status");
                Response::Status(Box::new(sample_status(DomeState::TunnelActive)))
            }
            Request::Subscribe => {
                let ev = DaemonEvent::Log {
                    level: "info".into(),
                    message: "subscribed-ok".into(),
                };
                if write_frame(&mut io, &Response::Event(Box::new(ev)))
                    .await
                    .is_err()
                {
                    return;
                }
                let _ = notify.send("subscribed");
                // Keep the stream open until the client goes away.
                let _ = read_frame::<_, Request>(&mut io).await;
                return;
            }
            Request::Panic => {
                panicked.store(true, Ordering::SeqCst);
                let _ = notify.send("panic");
                Response::Ok
            }
            _ => Response::Error {
                message: "unsupported in test".into(),
            },
        };
        if write_frame(&mut io, &resp).await.is_err() {
            return;
        }
    }
}

#[tokio::test]
async fn drive_end_to_end_with_fake_daemon() {
    let token = Key32::random();
    let panicked = Arc::new(AtomicBool::new(false));
    let (notify_tx, mut notify_rx) = tokio::sync::mpsc::unbounded_channel();

    let connect = {
        let token = token.clone();
        let panicked = panicked.clone();
        move || {
            let (client, server) = tokio::io::duplex(1 << 16);
            tokio::spawn(fake_daemon(
                server,
                token.clone(),
                panicked.clone(),
                notify_tx.clone(),
            ));
            let token = token.clone();
            async move { IpcClient::handshake(Box::new(client), &token).await }
        }
    };

    let (key_tx, key_rx) = tokio::sync::mpsc::unbounded_channel::<std::io::Result<Event>>();
    let input = futures_util::stream::unfold(key_rx, |mut rx| async move {
        rx.recv().await.map(|ev| (ev, rx))
    });
    let input = Box::pin(input);

    let ui = tokio::spawn(async move {
        let mut term = Terminal::new(TestBackend::new(120, 40)).unwrap();
        let app = crate::runtime::drive(&mut term, input, connect).await;
        (app, term)
    });

    // Waits until every named notification has been seen at least once
    // (in any order) after the call starts.
    async fn wait_all(
        rx: &mut tokio::sync::mpsc::UnboundedReceiver<&'static str>,
        want: &[&'static str],
    ) {
        let mut pending: Vec<&str> = want.to_vec();
        tokio::time::timeout(Duration::from_secs(10), async {
            while !pending.is_empty() {
                let got = rx.recv().await.expect("fake daemon alive");
                pending.retain(|w| *w != got);
            }
        })
        .await
        .expect("fake daemon notification");
    }
    wait_all(&mut notify_rx, &["status", "subscribed"]).await;
    // The next poll guarantees the first status has been applied by the UI.
    wait_all(&mut notify_rx, &["status"]).await;

    key_tx
        .send(Ok(Event::Key(key(KeyCode::Char('P')))))
        .unwrap();
    wait_all(&mut notify_rx, &["panic"]).await;
    // Let the command result travel back to the UI before quitting.
    wait_all(&mut notify_rx, &["status"]).await;
    key_tx
        .send(Ok(Event::Key(key(KeyCode::Char('q')))))
        .unwrap();

    let (app, term) = tokio::time::timeout(Duration::from_secs(10), ui)
        .await
        .expect("ui exits")
        .unwrap();
    let app = app.unwrap();
    assert!(panicked.load(Ordering::SeqCst));
    assert!(app.should_quit);
    assert_eq!(app.state(), Some(DomeState::TunnelActive));
    assert!(app.events_online);
    assert!(app.logs.iter().any(|l| l.message == "subscribed-ok"));
    assert!(app
        .banner
        .as_ref()
        .is_some_and(|b| b.text.contains("IDENTITY ROTATED")));

    let buf = term.backend().buffer();
    let screen: String = (0..buf.area.height)
        .flat_map(|y| (0..buf.area.width).map(move |x| (x, y)))
        .map(|p| buf[p].symbol().to_string())
        .collect();
    assert!(screen.contains("PROTECTED"));
    assert!(screen.contains("IDENTITY ROTATED"));
}

#[tokio::test]
async fn drive_shows_unreachable_and_keeps_retrying() {
    let attempts = Arc::new(std::sync::atomic::AtomicU32::new(0));
    let connect = {
        let attempts = attempts.clone();
        move || {
            attempts.fetch_add(1, Ordering::SeqCst);
            async { Err::<IpcClient, _>("cannot reach voidwired (test)".to_string()) }
        }
    };
    let (key_tx, key_rx) = tokio::sync::mpsc::unbounded_channel::<std::io::Result<Event>>();
    let input = Box::pin(futures_util::stream::unfold(key_rx, |mut rx| async move {
        rx.recv().await.map(|ev| (ev, rx))
    }));
    let ui = tokio::spawn(async move {
        let mut term = Terminal::new(TestBackend::new(100, 30)).unwrap();
        let app = crate::runtime::drive(&mut term, input, connect).await;
        (app, term)
    });
    // Two status + two event attempts, spaced by the 2 s retry interval.
    tokio::time::timeout(Duration::from_secs(10), async {
        while attempts.load(Ordering::SeqCst) < 4 {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("retries");
    key_tx
        .send(Ok(Event::Key(key(KeyCode::Char('P')))))
        .unwrap();
    key_tx.send(Ok(Event::Key(key(KeyCode::Esc)))).unwrap();
    let (app, term) = ui.await.unwrap();
    let app = app.unwrap();
    assert!(matches!(app.link, Link::Offline { .. }));
    assert!(app.in_flight.is_empty(), "panic is not sent while offline");
    let buf = term.backend().buffer();
    let screen: String = (0..buf.area.height)
        .flat_map(|y| (0..buf.area.width).map(move |x| (x, y)))
        .map(|p| buf[p].symbol().to_string())
        .collect();
    assert!(screen.contains("DAEMON UNREACHABLE"));
    assert!(screen.contains("cannot reach voidwired (test)"));
}
