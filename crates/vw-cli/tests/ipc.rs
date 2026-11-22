//! End-to-end tests against an in-process fake `voidwired` speaking real
//! VWIPC (framing + `server_handshake`) over a temporary Unix socket.
//! They mutate process environment, so they run serially under one lock.
#![cfg(unix)]

mod common;

use std::sync::{Arc, Mutex};

use clap::Parser;
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::broadcast;
use vw_cli::{execute, Cli, ExitCode};
use vw_core::config::{NodeDescriptor, NodeKind, NodeRole, Profile, Settings, TransportKind};
use vw_core::ipc::{
    read_frame, server_handshake, write_frame, DaemonEvent, ExecTicket, Request, Response,
};
use vw_core::secret::Key32;
use vw_core::state::DomeState;

static ENV_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

struct Fake {
    state: DomeState,
    settings: Settings,
    fail_up: bool,
    audit_pass: bool,
    log: Vec<String>,
}

type Shared = Arc<Mutex<Fake>>;

struct Daemon {
    shared: Shared,
    _dir: tempfile::TempDir,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for Daemon {
    fn drop(&mut self) {
        self.task.abort();
    }
}

fn emit(tx: &broadcast::Sender<DaemonEvent>, shared: &Shared, path: &[DomeState]) {
    for w in path.windows(2) {
        shared.lock().unwrap().state = w[1];
        let _ = tx.send(DaemonEvent::StateChanged {
            from: w[0],
            to: w[1],
        });
    }
}

async fn handle(
    mut s: UnixStream,
    token: Key32,
    shared: Shared,
    tx: broadcast::Sender<DaemonEvent>,
) {
    if server_handshake(&mut s, &token, "0.1.0-fake")
        .await
        .is_err()
    {
        return;
    }
    while let Ok(req) = read_frame::<_, Request>(&mut s).await {
        shared.lock().unwrap().log.push(format!("{req:?}"));
        let resp = match req {
            Request::Status => {
                let st = shared.lock().unwrap().state;
                Response::Status(Box::new(common::status(st)))
            }
            Request::Subscribe => {
                let mut rx = tx.subscribe();
                let _ = write_frame(&mut s, &Response::Ok).await;
                while let Ok(ev) = rx.recv().await {
                    if write_frame(&mut s, &Response::Event(Box::new(ev)))
                        .await
                        .is_err()
                    {
                        return;
                    }
                }
                return;
            }
            Request::Up { .. } => {
                let (from, fail) = {
                    let f = shared.lock().unwrap();
                    (f.state, f.fail_up)
                };
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                if fail {
                    emit(
                        &tx,
                        &shared,
                        &[from, DomeState::ArmingBootLock, DomeState::Handshaking],
                    );
                    let _ = tx.send(DaemonEvent::Log {
                        level: "error".into(),
                        message: "no gateway answered the handshake".into(),
                    });
                    emit(
                        &tx,
                        &shared,
                        &[DomeState::Handshaking, DomeState::FailsafeLockdown],
                    );
                    Response::Error {
                        message: "handshake failed on every candidate".into(),
                    }
                } else {
                    emit(
                        &tx,
                        &shared,
                        &[
                            from,
                            DomeState::ArmingBootLock,
                            DomeState::Handshaking,
                            DomeState::CanaryAuditing,
                            DomeState::TunnelActive,
                        ],
                    );
                    let _ = tx.send(DaemonEvent::Decision(common::decision()));
                    Response::Ok
                }
            }
            Request::Down { keep_lockdown } => {
                shared.lock().unwrap().state = if keep_lockdown {
                    DomeState::FailsafeLockdown
                } else {
                    DomeState::Disarmed
                };
                Response::Ok
            }
            Request::Disarm => {
                shared.lock().unwrap().state = DomeState::Disarmed;
                Response::Ok
            }
            Request::Panic => Response::Ok,
            Request::Audit => Response::Audit(common::audit(shared.lock().unwrap().audit_pass)),
            Request::Optimize => Response::Optimized(Box::new(common::decision())),
            Request::GetSettings => {
                Response::Settings(Box::new(shared.lock().unwrap().settings.clone()))
            }
            Request::SetSettings(s) => {
                shared.lock().unwrap().settings = *s;
                Response::Ok
            }
            Request::ListNodes => Response::Nodes(common::nodes()),
            Request::RemoveNode { name } if name != "oracle-fra" => Response::Error {
                message: format!("no node named {name}"),
            },
            Request::ImportNode { .. }
            | Request::RemoveNode { .. }
            | Request::RedeemInvite { .. }
            | Request::RegisterWarp => Response::Ok,
            Request::Telemetry => Response::Telemetry(Default::default()),
            Request::ExecPrepare => Response::Exec(ExecTicket {
                netns: None,
                isolation: "system-wide Iron Dome lockdown".into(),
            }),
        };
        if write_frame(&mut s, &resp).await.is_err() {
            return;
        }
    }
}

/// Start a fake daemon and point `connect_default` at it.
fn start(initial: DomeState) -> Daemon {
    let dir = tempfile::tempdir().unwrap();
    let token = Key32::random();
    std::fs::write(dir.path().join("ipc.token"), hex(token.expose())).unwrap();
    let sock = dir.path().join("d.sock");
    let listener = UnixListener::bind(&sock).unwrap();
    std::env::set_var("VOIDWIRE_STATE_DIR", dir.path());
    std::env::set_var("VOIDWIRE_IPC", &sock);
    let shared: Shared = Arc::new(Mutex::new(Fake {
        state: initial,
        settings: Settings::default(),
        fail_up: false,
        audit_pass: true,
        log: Vec::new(),
    }));
    let (tx, _) = broadcast::channel(64);
    let sh = shared.clone();
    let task = tokio::spawn(async move {
        while let Ok((s, _)) = listener.accept().await {
            tokio::spawn(handle(s, token.clone(), sh.clone(), tx.clone()));
        }
    });
    Daemon {
        shared,
        _dir: dir,
        task,
    }
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

async fn run(args: &[&str]) -> (Result<i32, vw_cli::CliError>, String, String) {
    let mut v = vec!["voidwire"];
    v.extend_from_slice(args);
    let cli = Cli::try_parse_from(v).unwrap();
    let (mut out, o, e) = common::sink(cli.json);
    let r = execute(cli, &mut out).await;
    (r, o.text(), e.text())
}

fn code(r: &Result<i32, vw_cli::CliError>) -> i32 {
    match r {
        Ok(c) => *c,
        Err(e) => e.code.code(),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn unreachable_daemon_explains_install() {
    let _g = ENV_LOCK.lock().await;
    let dir = tempfile::tempdir().unwrap();
    std::env::set_var("VOIDWIRE_STATE_DIR", dir.path().join("missing"));
    std::env::set_var("VOIDWIRE_IPC", dir.path().join("none.sock"));
    let (r, _, _) = run(&["status"]).await;
    let e = r.unwrap_err();
    assert_eq!(e.code, ExitCode::DaemonUnavailable);
    assert!(e.hint.unwrap().contains("voidwired install"));

    // Token present, socket absent: installed but not running.
    std::env::set_var("VOIDWIRE_STATE_DIR", dir.path());
    std::fs::write(dir.path().join("ipc.token"), "00".repeat(32)).unwrap();
    let (r, _, _) = run(&["nodes", "list"]).await;
    let e = r.unwrap_err();
    assert_eq!(e.code, ExitCode::DaemonUnavailable);
    assert!(e.hint.is_some());
}

#[tokio::test(flavor = "multi_thread")]
async fn wrong_token_is_permission_denied() {
    let _g = ENV_LOCK.lock().await;
    let d = start(DomeState::Disarmed);
    let dir = std::env::var("VOIDWIRE_STATE_DIR").unwrap();
    std::fs::write(format!("{dir}/ipc.token"), "11".repeat(32)).unwrap();
    let (r, _, _) = run(&["status"]).await;
    assert_eq!(r.unwrap_err().code, ExitCode::PermissionDenied);
    drop(d);
}

#[tokio::test(flavor = "multi_thread")]
async fn status_human_json_and_audit() {
    let _g = ENV_LOCK.lock().await;
    let d = start(DomeState::TunnelActive);
    let (r, o, _) = run(&["status"]).await;
    assert_eq!(code(&r), 0);
    assert!(o.contains("TunnelActive"));
    assert!(o.contains("oracle-fra"));

    let (r, o, _) = run(&["status", "--json"]).await;
    assert_eq!(code(&r), 0);
    let j: serde_json::Value = serde_json::from_str(&o).unwrap();
    assert_eq!(j["state"], "TunnelActive");

    let (r, o, _) = run(&["status", "--audit"]).await;
    assert_eq!(code(&r), 0);
    assert!(o.contains("all 2 checks passed"));

    d.shared.lock().unwrap().audit_pass = false;
    let (r, o, _) = run(&["status", "--audit", "--json"]).await;
    assert_eq!(code(&r), ExitCode::AuditFailed.code());
    let j: serde_json::Value = serde_json::from_str(&o).unwrap();
    assert_eq!(j["passed"], false);
    assert_eq!(j["audit"]["checks"][1]["passed"], false);
}

#[tokio::test(flavor = "multi_thread")]
async fn up_follows_events_to_active() {
    let _g = ENV_LOCK.lock().await;
    let d = start(DomeState::Disarmed);
    let (r, o, _) = run(&[
        "up",
        "--profile",
        "stealth",
        "--country",
        "de",
        "--transport",
        "amnezia-wg",
    ])
    .await;
    assert_eq!(code(&r), 0, "{r:?}\n{o}");
    assert!(o.contains("Chameleon Stealth"));
    assert!(o.contains("TunnelActive"));
    assert!(o.contains("protected in"));
    assert!(o.contains("Optimizer decision"));
    assert!(o.contains("AmneziaWG"));
    let log = d.shared.lock().unwrap().log.join("\n");
    assert!(log.contains("profile: Stealth"));
    assert!(log.contains("country: Some(\"DE\")"));
    assert!(log.contains("transport: Some(AmneziaWg)"));

    // Default profile comes from the daemon settings.
    {
        let mut f = d.shared.lock().unwrap();
        f.state = DomeState::Disarmed;
        f.settings.default_profile = Profile::Warp;
    }
    let (r, o, _) = run(&["up", "--json"]).await;
    assert_eq!(code(&r), 0);
    let j: serde_json::Value = serde_json::from_str(&o).unwrap();
    assert_eq!(j["state"], "TunnelActive");
    assert_eq!(j["decision"]["mtu"], 1280);
    assert!(d
        .shared
        .lock()
        .unwrap()
        .log
        .iter()
        .any(|l| l.contains("profile: Warp")));
}

#[tokio::test(flavor = "multi_thread")]
async fn up_failure_reports_lockdown() {
    let _g = ENV_LOCK.lock().await;
    let d = start(DomeState::Disarmed);
    d.shared.lock().unwrap().fail_up = true;
    let (r, _, _) = run(&["up", "--profile", "multihop"]).await;
    let e = r.unwrap_err();
    assert_eq!(e.code, ExitCode::Lockdown);
    assert!(
        e.message.contains("handshake"),
        "reason should be reported: {}",
        e.message
    );
    assert!(e.hint.unwrap().contains("voidwire disarm"));
}

#[tokio::test(flavor = "multi_thread")]
async fn control_commands_round_trip() {
    let _g = ENV_LOCK.lock().await;
    let d = start(DomeState::TunnelActive);

    let (r, o, _) = run(&["panic"]).await;
    assert_eq!(code(&r), 0);
    assert!(o.contains("panic rotation complete"));
    assert!(o.contains("new exit   oracle-fra (DE)"));

    let (r, o, _) = run(&["down", "--keep-lockdown"]).await;
    assert_eq!(code(&r), 0);
    assert!(o.contains("FailsafeLockdown"));
    assert_eq!(d.shared.lock().unwrap().state, DomeState::FailsafeLockdown);

    let (r, _, _) = run(&["disarm", "--yes"]).await;
    assert_eq!(code(&r), 0);
    assert_eq!(d.shared.lock().unwrap().state, DomeState::Disarmed);

    let (r, o, _) = run(&["optimize"]).await;
    assert_eq!(code(&r), 0);
    assert!(o.contains("Cloudflare WARP → oracle-fra"));

    let (r, o, _) = run(&["nodes", "list"]).await;
    assert_eq!(code(&r), 0);
    assert!(o.contains("oracle-fra"));

    let node = NodeDescriptor {
        version: 1,
        name: "home".into(),
        kind: NodeKind::Voidwire,
        role: NodeRole::Exit,
        wg_public_key: vw_core::config::Bytes32([7; 32]),
        identity_key: Some(vw_core::config::Bytes32([8; 32])),
        endpoints: vec![vw_core::config::Endpoint {
            transport: TransportKind::NativeUdp,
            host: "192.0.2.1".into(),
            port: 51820,
            sni: None,
            path: None,
            cert_sha256: None,
        }],
        amnezia: None,
        country: None,
        ipv6_exit: false,
        static_v4: None,
        static_v6: None,
        reserved: None,
        static_psk: None,
        token_keys: Vec::new(),
    };
    let uri = vw_core::uri::encode_node(&node).unwrap();
    let (r, o, _) = run(&["nodes", "import", &uri]).await;
    assert_eq!(code(&r), 0);
    assert!(o.contains("imported node 'home'"));

    let (r, _, _) = run(&["nodes", "remove", "nope"]).await;
    let e = r.unwrap_err();
    assert_eq!(e.code, ExitCode::Rejected);
    assert!(e.message.contains("no node named nope"));
    let (r, _, _) = run(&["nodes", "remove", "oracle-fra"]).await;
    assert_eq!(code(&r), 0);

    let invite = vw_core::uri::encode_blob(vw_core::uri::F2F_PREFIX, &[1; 40]);
    let (r, o, _) = run(&["invite", "redeem", &invite, "--json"]).await;
    assert_eq!(code(&r), 0);
    assert!(o.contains("\"ok\": true"));
    let (r, _, _) = run(&["invite", "redeem", &uri]).await;
    assert_eq!(code(&r), ExitCode::Usage.code());

    let (r, o, _) = run(&["warp", "register", "--accept-tos"]).await;
    assert_eq!(code(&r), 0);
    assert!(o.contains("WARP device registered"));

    let log = d.shared.lock().unwrap().log.join("\n");
    for needle in [
        "Panic",
        "Down { keep_lockdown: true }",
        "Disarm",
        "Optimize",
        "ImportNode",
        "RedeemInvite",
        "RegisterWarp",
    ] {
        assert!(log.contains(needle), "daemon never saw {needle}");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn settings_get_and_set() {
    let _g = ENV_LOCK.lock().await;
    let d = start(DomeState::Disarmed);
    let (r, o, _) = run(&["settings", "get"]).await;
    assert_eq!(code(&r), 0);
    let mut s: Settings = serde_json::from_str(&o).unwrap();
    assert_eq!(s, Settings::default());
    s.firewall.allow_lan = true;
    s.pq_rotate_secs = 60;
    let (r, _, _) = run(&["settings", "set", &serde_json::to_string(&s).unwrap()]).await;
    assert_eq!(code(&r), 0);
    assert_eq!(d.shared.lock().unwrap().settings, s);
    let (r, _, _) = run(&["settings", "set", "{\"bad\":1}"]).await;
    assert_eq!(code(&r), ExitCode::Usage.code());
}

#[tokio::test(flavor = "multi_thread")]
async fn exec_runs_only_when_tunnel_active() {
    let _g = ENV_LOCK.lock().await;
    let d = start(DomeState::TunnelActive);
    let (r, _, e) = run(&["exec", "--", "sh", "-c", "exit 7"]).await;
    assert_eq!(code(&r), 7);
    assert!(e.contains("system-wide Iron Dome lockdown"));
    let (r, _, _) = run(&["exec", "true"]).await;
    assert_eq!(code(&r), 0);

    d.shared.lock().unwrap().state = DomeState::FailsafeLockdown;
    let (r, _, _) = run(&["exec", "true"]).await;
    let e = r.unwrap_err();
    assert_eq!(e.code, ExitCode::Rejected);
    assert!(e.message.contains("not active"));
}
