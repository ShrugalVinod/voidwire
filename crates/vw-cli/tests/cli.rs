//! Pure tests: argument parsing, formatters, exit codes, settings parsing,
//! exec argv construction and `cloud generate`.

mod common;

use std::ffi::OsString;

use clap::Parser;
use vw_cli::cli::{
    parse_country, CloudCommand, Command, InviteCommand, NodesCommand, ProfileArg, ProviderArg,
    SettingsCommand, TransportArg, WarpCommand, DEFAULT_UP_TIMEOUT_SECS,
};
use vw_cli::commands::exec::{invoking_identity, netns_argv, valid_netns_name, Identity};
use vw_cli::commands::up::{terminal, Tracker, UpOutcome};
use vw_cli::commands::{cloud, describe_import_uri, is_yes, parse_settings, parse_settings_arg};
use vw_cli::daemon::{classify_connect_error, TokenState};
use vw_cli::output::{Cell, Style, Table};
use vw_cli::{render, Cli, CliError, ExitCode, Theme};
use vw_core::config::{Profile, Settings, TransportKind};
use vw_core::state::DomeState;
use vw_core::VwError;

fn parse(args: &[&str]) -> Cli {
    let mut v = vec!["voidwire"];
    v.extend_from_slice(args);
    Cli::try_parse_from(v).unwrap_or_else(|e| panic!("{args:?}: {e}"))
}

fn parse_err(args: &[&str]) -> clap::Error {
    let mut v = vec!["voidwire"];
    v.extend_from_slice(args);
    Cli::try_parse_from(v).expect_err("should fail")
}

// ───────────────────────────── parsing ─────────────────────────────

#[test]
fn parses_up() {
    let c = parse(&[
        "up",
        "--profile",
        "max-anonymity",
        "--country",
        "de",
        "--transport",
        "masque-quic",
    ]);
    let Command::Up(a) = c.command else { panic!() };
    assert_eq!(a.profile, Some(ProfileArg::MaxAnonymity));
    assert_eq!(a.country.as_deref(), Some("DE"));
    assert_eq!(a.transport, Some(TransportArg::MasqueQuic));
    assert_eq!(a.timeout, DEFAULT_UP_TIMEOUT_SECS);
    assert!(!c.json);

    let Command::Up(a) = parse(&["up"]).command else {
        panic!()
    };
    assert_eq!(a.profile, None);
    for p in [
        "auto",
        "warp",
        "multihop",
        "stealth",
        "f2f",
        "max-anonymity",
    ] {
        parse(&["up", "--profile", p]);
    }
    for t in ["native-udp", "amnezia-wg", "masque-quic", "tls-websocket"] {
        parse(&["up", "--transport", t]);
    }
    parse_err(&["up", "--profile", "tor"]);
    parse_err(&["up", "--country", "DEU"]);
    parse_err(&["up", "--timeout", "0"]);
    assert_eq!(Profile::from(ProfileArg::F2f), Profile::F2f);
    assert_eq!(
        TransportKind::from(TransportArg::TlsWebsocket),
        TransportKind::TlsWebsocket
    );
}

#[test]
fn parses_simple_commands() {
    assert!(matches!(
        parse(&["down"]).command,
        Command::Down {
            keep_lockdown: false
        }
    ));
    assert!(matches!(
        parse(&["down", "--keep-lockdown"]).command,
        Command::Down {
            keep_lockdown: true
        }
    ));
    assert!(matches!(
        parse(&["disarm"]).command,
        Command::Disarm { yes: false }
    ));
    assert!(matches!(
        parse(&["disarm", "-y"]).command,
        Command::Disarm { yes: true }
    ));
    assert!(matches!(
        parse(&["status"]).command,
        Command::Status { audit: false }
    ));
    let c = parse(&["status", "--audit", "--json"]);
    assert!(c.json);
    assert!(matches!(c.command, Command::Status { audit: true }));
    assert!(parse(&["--json", "status"]).json);
    assert!(matches!(parse(&["panic"]).command, Command::Panic));
    assert!(matches!(parse(&["optimize"]).command, Command::Optimize));
    assert!(matches!(parse(&["tui"]).command, Command::Tui));
    assert!(matches!(
        parse(&["completions", "zsh"]).command,
        Command::Completions { .. }
    ));
    parse_err(&["completions", "tcsh"]);
    parse_err(&["frobnicate"]);
}

#[test]
fn parses_exec_without_shell() {
    let Command::Exec { cmd } = parse(&["exec", "--", "curl", "-v", "https://x"]).command else {
        panic!()
    };
    let want: Vec<OsString> = ["curl", "-v", "https://x"].iter().map(Into::into).collect();
    assert_eq!(cmd, want);
    let Command::Exec { cmd } = parse(&["exec", "ls", "-la"]).command else {
        panic!()
    };
    assert_eq!(cmd.len(), 2);
    parse_err(&["exec"]);
}

#[test]
fn parses_nodes_invite_warp_settings() {
    let Command::Nodes(NodesCommand::Import { uri }) =
        parse(&["nodes", "import", "voidwire://node/abc"]).command
    else {
        panic!()
    };
    assert_eq!(uri, "voidwire://node/abc");
    assert!(matches!(
        parse(&["nodes", "list"]).command,
        Command::Nodes(NodesCommand::List)
    ));
    assert!(matches!(
        parse(&["nodes", "remove", "x"]).command,
        Command::Nodes(NodesCommand::Remove { .. })
    ));
    assert!(matches!(
        parse(&["invite", "redeem", "voidwire://f2f/x"]).command,
        Command::Invite(InviteCommand::Redeem { .. })
    ));
    assert!(matches!(
        parse(&["warp", "register"]).command,
        Command::Warp(WarpCommand::Register { accept_tos: false })
    ));
    assert!(matches!(
        parse(&["warp", "register", "--accept-tos"]).command,
        Command::Warp(WarpCommand::Register { accept_tos: true })
    ));
    assert!(matches!(
        parse(&["settings", "get"]).command,
        Command::Settings(SettingsCommand::Get)
    ));
    assert!(matches!(
        parse(&["settings", "set", "@s.json"]).command,
        Command::Settings(SettingsCommand::Set { .. })
    ));
    parse_err(&["settings", "set"]);
}

#[test]
fn parses_cloud_generate() {
    let c = parse(&[
        "cloud",
        "generate",
        "--provider",
        "oracle-free",
        "--out",
        "dir",
        "--version",
        "0.2.0",
        "--name",
        "n1",
        "--region",
        "eu-frankfurt-1",
        "--ssh-key",
        "k.pub",
        "--owner-key",
        "AAAA",
        "--authorize-me",
    ]);
    let Command::Cloud(CloudCommand::Generate(a)) = c.command else {
        panic!()
    };
    assert_eq!(a.provider, ProviderArg::OracleFree);
    assert_eq!(a.release_version.as_deref(), Some("0.2.0"));
    assert!(a.authorize_me);
    for p in ["oracle-free", "gcp-free", "fly", "docker", "ssh"] {
        parse(&["cloud", "generate", "--provider", p]);
    }
    parse_err(&["cloud", "generate"]);
    parse_err(&["cloud", "generate", "--provider", "aws"]);
}

#[test]
fn help_and_version_are_not_errors() {
    assert_eq!(vw_cli::main_entry(["voidwire", "--version"]), 0);
    assert_eq!(
        vw_cli::main_entry(["voidwire", "bogus"]),
        ExitCode::Usage.code()
    );
}

#[test]
fn country_parser() {
    assert_eq!(parse_country(" us ").unwrap(), "US");
    assert!(parse_country("U1").is_err());
    assert!(parse_country("").is_err());
}

// ───────────────────────────── formatting ─────────────────────────────

#[test]
fn status_block_active() {
    let t = Theme::PLAIN;
    let s = render::status_block(&t, &common::status(DomeState::TunnelActive));
    for needle in [
        "TunnelActive",
        "Ghost Multi-Hop",
        "you → Cloudflare WARP [classical] → oracle-fra DE [PQ] → internet",
        "PQ hybrid",
        "AmneziaWG (stealth)",
        "X25519+ML-KEM-1024",
        "1280",
        "DAITA on",
        "01:02:05",
        "last key rotation 42s ago",
        "1.50 MiB (1,234 pkts)",
        "[pf]",
        "✓ IPv4",
        "✗ boot lock",
        "voidwired 0.1.0 on macos",
    ] {
        assert!(s.contains(needle), "missing {needle:?} in\n{s}");
    }
    assert!(!s.contains('\x1b'));
    let colored = render::status_block(&Theme::COLOR, &common::status(DomeState::TunnelActive));
    assert!(colored.contains("\x1b[1;32mTunnelActive\x1b[0m"));
}

#[test]
fn status_block_lockdown() {
    let s = render::status_block(&Theme::PLAIN, &common::status(DomeState::FailsafeLockdown));
    assert!(s.contains("FailsafeLockdown"));
    assert!(s.contains("LOCKDOWN"));
    assert!(s.contains("no route"));
}

#[test]
fn audit_table_pass_and_fail() {
    let t = Theme::PLAIN;
    let ok = common::audit(true);
    assert!(render::audit_passed(&ok));
    let s = render::audit_table(&t, &ok);
    assert!(s.contains("CHECK"));
    assert!(s.contains("PROOF (BLAKE3)"));
    assert!(s.contains("dns-leak"));
    assert!(s.contains("aaaaaaaaaaaa"));
    assert!(!s.contains(&"a".repeat(13)));
    assert!(s.contains("13:01:01 UTC"));
    assert!(s.contains("all 2 checks passed"));

    let bad = common::audit(false);
    assert!(!render::audit_passed(&bad));
    let s = render::audit_table(&t, &bad);
    assert!(s.contains("FAIL"));
    assert!(s.contains("1 of 2 checks FAILED"));

    let mut empty = common::audit(true);
    empty.checks.clear();
    assert!(
        !render::audit_passed(&empty),
        "an empty audit proves nothing"
    );
    let mut lying = common::audit(true);
    lying.passed = false;
    assert!(!render::audit_passed(&lying));
}

#[test]
fn decision_block_contents() {
    let s = render::decision_block(&Theme::PLAIN, &common::decision());
    for needle in [
        "Cloudflare WARP → oracle-fra",
        "AmneziaWG (stealth)",
        "1280   MSS 1240   DAITA on",
        "QUIC blocked, WireGuard signature filtered",
        "plain WireGuard is filtered",
        "85.40",
        "unreachable",
    ] {
        assert!(s.contains(needle), "missing {needle:?} in\n{s}");
    }
    // Best candidate first.
    assert!(s.find("oracle-fra  ").unwrap() < s.find("gcp-usw").unwrap());
}

#[test]
fn nodes_and_transitions() {
    let t = Theme::PLAIN;
    let s = render::nodes_table(&t, &common::nodes());
    assert!(s.contains("oracle-fra"));
    assert!(s.contains("entry+exit"));
    assert!(s.contains("WireGuard UDP, TLS-WebSocket"));
    assert!(render::nodes_table(&t, &[]).contains("no nodes imported"));
    let l = render::transition_line(&t, 1500, DomeState::Handshaking, DomeState::CanaryAuditing);
    assert!(l.contains("[   1.5s] Handshaking → CanaryAuditing"));
    let hops = common::hops();
    assert_eq!(render::exit_hop(&hops).unwrap().name, "oracle-fra");
    assert!(render::exit_hop(&[]).is_none());
}

#[test]
fn table_alignment_ignores_color() {
    let mut t = Table::new(["A", "B"]);
    t.row(vec![Cell::new("long-cell", Style::Ok), Cell::plain("x")]);
    t.row(vec![Cell::plain("s"), Cell::plain("y")]);
    let plain = t.render(&Theme::PLAIN);
    assert_eq!(plain, "A          B\nlong-cell  x\ns          y\n");
    let colored = t.render(&Theme::COLOR);
    let stripped: String = {
        let mut out = String::new();
        let mut esc = false;
        for c in colored.chars() {
            match (esc, c) {
                (_, '\x1b') => esc = true,
                (true, 'm') => esc = false,
                (true, _) => {}
                (false, c) => out.push(c),
            }
        }
        out
    };
    assert_eq!(stripped, plain);
}

// ───────────────────────────── exit codes ─────────────────────────────

#[test]
fn exit_codes_are_stable() {
    let all = [
        (ExitCode::Success, 0),
        (ExitCode::Failure, 1),
        (ExitCode::Usage, 2),
        (ExitCode::DaemonUnavailable, 3),
        (ExitCode::PermissionDenied, 4),
        (ExitCode::Lockdown, 5),
        (ExitCode::AuditFailed, 6),
        (ExitCode::Timeout, 7),
        (ExitCode::Rejected, 8),
        (ExitCode::Cancelled, 9),
    ];
    for (c, n) in all {
        assert_eq!(c.code(), n, "{}", c.name());
    }
}

#[test]
fn request_errors_map_to_codes() {
    let m = |e| CliError::from_request(e).code;
    assert_eq!(m(VwError::Ipc("nope".into())), ExitCode::Rejected);
    assert_eq!(m(VwError::Timeout), ExitCode::Timeout);
    assert_eq!(m(VwError::Auth), ExitCode::PermissionDenied);
    assert_eq!(
        m(VwError::Io(std::io::Error::from(
            std::io::ErrorKind::UnexpectedEof
        ))),
        ExitCode::DaemonUnavailable
    );
    assert_eq!(m(VwError::Config("x".into())), ExitCode::Failure);
    let j = CliError::new(ExitCode::Lockdown, "m").with_hint("h").json();
    assert_eq!(j["error"]["code"], 5);
    assert_eq!(j["error"]["kind"], "lockdown");
    assert_eq!(j["error"]["hint"], "h");
}

#[test]
fn connect_errors_are_actionable() {
    let ep = "/nonexistent.sock";
    let e = classify_connect_error(VwError::Permission("x".into()), TokenState::Missing, ep);
    assert_eq!(e.code, ExitCode::DaemonUnavailable);
    assert!(e.message.contains("not appear to be installed"));
    assert!(e.hint.unwrap().contains("voidwired"));
    let e = classify_connect_error(
        VwError::Permission("denied".into()),
        TokenState::Present,
        ep,
    );
    assert_eq!(e.code, ExitCode::PermissionDenied);
    let e = classify_connect_error(VwError::Ipc("cannot reach".into()), TokenState::Present, ep);
    assert_eq!(e.code, ExitCode::DaemonUnavailable);
    assert!(e.hint.is_some());
    let e = classify_connect_error(VwError::Auth, TokenState::Present, ep);
    assert_eq!(e.code, ExitCode::PermissionDenied);
    let e = classify_connect_error(VwError::Timeout, TokenState::Present, ep);
    assert_eq!(e.code, ExitCode::DaemonUnavailable);
}

// ───────────────────────────── settings / uris / prompts ─────────────────────────────

#[test]
fn settings_parsing() {
    let mut s = Settings::default();
    s.firewall.allow_lan = true;
    s.default_profile = Profile::Stealth;
    let text = serde_json::to_string(&s).unwrap();
    assert_eq!(parse_settings(&text).unwrap(), s);
    assert_eq!(parse_settings_arg(&text).unwrap(), s);

    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("s.json");
    std::fs::write(&p, serde_json::to_string_pretty(&s).unwrap()).unwrap();
    assert_eq!(parse_settings_arg(&format!("@{}", p.display())).unwrap(), s);

    let e = parse_settings(r#"{"firewall":{"allow_lan":true}}"#).unwrap_err();
    assert_eq!(e.code, ExitCode::Usage);
    assert!(e.hint.unwrap().contains("settings get"));
    assert_eq!(
        parse_settings("not json").unwrap_err().code,
        ExitCode::Usage
    );
    assert_eq!(
        parse_settings_arg("@/definitely/missing.json")
            .unwrap_err()
            .code,
        ExitCode::Usage
    );
}

#[test]
fn import_uri_validation() {
    assert_eq!(
        describe_import_uri("https://x").unwrap_err().code,
        ExitCode::Usage
    );
    assert!(describe_import_uri("voidwire://node/!!!").is_err());
    let f2f = vw_core::uri::encode_blob(vw_core::uri::F2F_PREFIX, &[1, 2, 3]);
    assert_eq!(describe_import_uri(&f2f).unwrap(), "friend invite");
    assert!(is_yes("Y\n"));
    assert!(is_yes(" yes "));
    assert!(!is_yes(""));
    assert!(!is_yes("no"));
}

// ───────────────────────────── up / exec helpers ─────────────────────────────

#[test]
fn up_tracker_and_terminal_states() {
    let mut t = Tracker {
        current: Some(DomeState::Disarmed),
        ..Default::default()
    };
    assert_eq!(
        t.observe(10, Some(DomeState::Disarmed), DomeState::ArmingBootLock),
        Some((DomeState::Disarmed, DomeState::ArmingBootLock))
    );
    // Same state seen again via polling is not re-printed.
    assert_eq!(t.observe(20, None, DomeState::ArmingBootLock), None);
    // A polled jump fills in `from` from the tracker.
    assert_eq!(
        t.observe(30, None, DomeState::TunnelActive),
        Some((DomeState::ArmingBootLock, DomeState::TunnelActive))
    );
    assert_eq!(t.transitions.len(), 2);

    assert_eq!(
        terminal(DomeState::TunnelActive, true),
        Some(UpOutcome::Active)
    );
    assert_eq!(
        terminal(DomeState::FailsafeLockdown, true),
        Some(UpOutcome::Lockdown { reason: None })
    );
    assert_eq!(terminal(DomeState::FailsafeLockdown, false), None);
    assert_eq!(terminal(DomeState::Handshaking, true), None);
}

#[test]
fn exec_argv_and_identity() {
    let cmd: Vec<OsString> = ["curl", "-s", "https://example.com; rm -rf /"]
        .iter()
        .map(Into::into)
        .collect();
    let who = Identity {
        uid: 1000,
        gid: 1000,
    };
    let root = netns_argv("vw-exec", who, true, &cmd);
    let want: Vec<OsString> = [
        "ip",
        "netns",
        "exec",
        "vw-exec",
        "setpriv",
        "--reuid",
        "1000",
        "--regid",
        "1000",
        "--init-groups",
        "--",
        "curl",
        "-s",
        "https://example.com; rm -rf /",
    ]
    .iter()
    .map(Into::into)
    .collect();
    assert_eq!(root, want);
    let user = netns_argv("vw-exec", who, false, &cmd);
    assert_eq!(&user[..2], &[OsString::from("sudo"), OsString::from("--")]);
    assert_eq!(&user[2..], &want[..]);

    assert_eq!(
        invoking_identity(0, 0, Some("501"), Some("20")),
        Identity { uid: 501, gid: 20 }
    );
    assert_eq!(
        invoking_identity(0, 0, None, None),
        Identity { uid: 0, gid: 0 }
    );
    assert_eq!(
        invoking_identity(1000, 100, Some("501"), Some("20")),
        Identity {
            uid: 1000,
            gid: 100
        },
        "SUDO_* is only trusted when running as root"
    );
    assert!(valid_netns_name("vw-exec_1"));
    assert!(!valid_netns_name("-x"));
    assert!(!valid_netns_name("../x"));
    assert!(!valid_netns_name(""));
}

// ───────────────────────────── cloud generate ─────────────────────────────

fn cloud_cli(args: &[&str]) -> vw_cli::cli::CloudArgs {
    let mut v = vec!["cloud", "generate"];
    v.extend_from_slice(args);
    match parse(&v).command {
        Command::Cloud(CloudCommand::Generate(a)) => a,
        _ => unreachable!(),
    }
}

#[test]
fn cloud_generate_writes_bundle() {
    let dir = tempfile::tempdir().unwrap();
    let out_dir = dir.path().join("oracle");
    let key = dir.path().join("id.pub");
    std::fs::write(
        &key,
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExample me@host\n",
    )
    .unwrap();
    let owner = "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=";
    let args = cloud_cli(&[
        "--provider",
        "oracle-free",
        "--out",
        out_dir.to_str().unwrap(),
        "--name",
        "fra-1",
        "--ssh-key",
        key.to_str().unwrap(),
        "--owner-key",
        owner,
    ]);
    let (mut out, o, _e) = common::sink(false);
    assert_eq!(cloud::run(&mut out, &args).unwrap(), 0);
    for f in ["cloud-init.yaml", "main.tf", "bootstrap.sh", "README.md"] {
        assert!(out_dir.join(f).is_file(), "{f} missing");
    }
    let ci = std::fs::read_to_string(out_dir.join("cloud-init.yaml")).unwrap();
    assert!(ci.contains("--authorize bmXOC"));
    assert!(ci.contains("--name fra-1"));
    assert!(ci.contains(env!("CARGO_PKG_VERSION")));
    let text = o.text();
    assert!(text.contains("wrote 4 files"));
    assert!(text.contains("Oracle Cloud Always Free"));
    assert!(text.contains("Next steps"));
    assert!(text.contains("tofu init"));

    // Refuses to overwrite without --force.
    let (mut out, _, _) = common::sink(false);
    assert_eq!(
        cloud::run(&mut out, &args).unwrap_err().code,
        ExitCode::Usage
    );
    let mut forced = args;
    forced.force = true;
    let (mut out, o, _) = common::sink(true);
    assert_eq!(cloud::run(&mut out, &forced).unwrap(), 0);
    let j: serde_json::Value = serde_json::from_str(&o.text()).unwrap();
    assert_eq!(j["provider"], "oracle-free");
    assert_eq!(j["owner_preauthorized"], true);
    assert_eq!(j["files"].as_array().unwrap().len(), 4);
}

#[test]
fn cloud_generate_option_errors() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("x");
    let o = out.to_str().unwrap();
    let e = cloud::bundle_options(
        &cloud_cli(&["--provider", "fly", "--authorize-me"]),
        "0.1.0",
    )
    .unwrap_err();
    assert_eq!(e.code, ExitCode::Usage);
    assert!(e.message.contains("--owner-key"));
    assert!(e.hint.unwrap().contains("invite redeem"));
    let e = cloud::bundle_options(
        &cloud_cli(&["--provider", "fly", "--owner-key", "short"]),
        "0.1.0",
    )
    .unwrap_err();
    assert_eq!(e.code, ExitCode::Usage);
    let priv_key = dir.path().join("id");
    std::fs::write(&priv_key, "-----BEGIN OPENSSH PRIVATE KEY-----\n").unwrap();
    let e = cloud::bundle_options(
        &cloud_cli(&["--provider", "ssh", "--ssh-key", priv_key.to_str().unwrap()]),
        "0.1.0",
    )
    .unwrap_err();
    assert!(e.message.contains("private key"));
    let (mut sink, _, _) = common::sink(false);
    let e = cloud::run(
        &mut sink,
        &cloud_cli(&["--provider", "docker", "--out", o, "--name", "bad name"]),
    )
    .unwrap_err();
    assert_eq!(e.code, ExitCode::Usage);
    let opts = cloud::bundle_options(&cloud_cli(&["--provider", "gcp-free"]), "v9.9.9").unwrap();
    assert_eq!(opts.version, "9.9.9");
    assert_eq!(
        cloud::deploy_steps("# x\n\n## Deploy\n\n1. a\n2. b\n\n## Other\n\nz"),
        Some("1. a\n2. b")
    );
}
