//! Command handlers. Each talks to the real daemon over VWIPC (except
//! `cloud generate` and `completions`, which are local).

pub mod cloud;
pub mod exec;
pub mod up;

use std::io::IsTerminal;
use std::time::Instant;

use clap::CommandFactory;
use serde_json::json;
use vw_core::config::Settings;
use vw_core::ipc::{Request, Response};
use vw_core::uri::{decode_blob, decode_node, F2F_PREFIX, NODE_PREFIX};

use crate::cli::{
    Cli, CloudCommand, Command, InviteCommand, NodesCommand, SettingsCommand, WarpCommand,
};
use crate::daemon;
use crate::exit::{CliError, CliResult, ExitCode};
use crate::output::Out;
use crate::render;

/// Run a parsed command line; returns the process exit code on success.
pub async fn execute(cli: Cli, out: &mut Out) -> CliResult<i32> {
    match cli.command {
        Command::Up(a) => {
            up::run(
                out,
                a.profile.map(Into::into),
                a.country,
                a.transport.map(Into::into),
                a.timeout,
            )
            .await
        }
        Command::Down { keep_lockdown } => down(out, keep_lockdown).await,
        Command::Disarm { yes } => disarm(out, yes).await,
        Command::Status { audit } => status(out, audit).await,
        Command::Panic => panic(out).await,
        Command::Exec { cmd } => exec::run(out, cmd).await,
        Command::Optimize => optimize(out).await,
        Command::Nodes(NodesCommand::List) => nodes_list(out).await,
        Command::Nodes(NodesCommand::Import { uri }) => import(out, &uri).await,
        Command::Nodes(NodesCommand::Remove { name }) => remove(out, &name).await,
        Command::Invite(InviteCommand::Redeem { uri }) => redeem(out, &uri).await,
        Command::Warp(WarpCommand::Register { accept_tos }) => warp_register(out, accept_tos).await,
        Command::Settings(SettingsCommand::Get) => settings_get(out).await,
        Command::Settings(SettingsCommand::Set { value }) => settings_set(out, &value).await,
        Command::Cloud(CloudCommand::Generate(a)) => cloud::run(out, &a),
        Command::Tui => tui().await,
        Command::Completions { shell } => {
            let mut buf = Vec::new();
            clap_complete::generate(shell, &mut Cli::command(), "voidwire", &mut buf);
            out.print(&String::from_utf8_lossy(&buf));
            Ok(0)
        }
    }
}

fn ok_message(out: &mut Out, message: &str, extra: serde_json::Value) {
    if out.json {
        let mut v = json!({ "ok": true, "message": message });
        if let (Some(m), serde_json::Value::Object(e)) = (v.as_object_mut(), extra) {
            m.extend(e);
        }
        out.emit_json(&v);
    } else {
        let t = out.theme;
        out.line(&t.ok(&format!("✓ {message}")));
    }
}

/// Ask a yes/no question on the terminal; refuses when stdin is not a TTY.
async fn confirm(out: &mut Out, question: &str, refuse_hint: &str) -> CliResult<bool> {
    if !std::io::stdin().is_terminal() {
        return Err(CliError::new(
            ExitCode::Cancelled,
            "confirmation required but stdin is not a terminal",
        )
        .with_hint(refuse_hint.to_string()));
    }
    out.note(&format!("{question} [y/N] "));
    let answer = tokio::task::spawn_blocking(|| {
        let mut s = String::new();
        std::io::stdin().read_line(&mut s).map(|_| s)
    })
    .await
    .map_err(|e| CliError::failure(e.to_string()))??;
    Ok(is_yes(&answer))
}

pub fn is_yes(answer: &str) -> bool {
    matches!(answer.trim().to_ascii_lowercase().as_str(), "y" | "yes")
}

async fn down(out: &mut Out, keep_lockdown: bool) -> CliResult<i32> {
    let mut c = daemon::connect().await?;
    let req = Request::Down { keep_lockdown };
    match daemon::call(&mut c, &req).await? {
        Response::Ok => {}
        other => return Err(daemon::unexpected(&req, &other)),
    }
    let s = daemon::status(&mut c).await?;
    if out.json {
        out.emit_json(&json!({ "ok": true, "state": s.state, "firewall": s.firewall }));
        return Ok(0);
    }
    let t = out.theme;
    out.line(&t.ok("✓ tunnel down"));
    out.line(&format!(
        "  state {}  {}",
        t.paint(render::state_style(s.state), render::state_name(s.state)),
        t.dim(render::state_meaning(s.state))
    ));
    if keep_lockdown {
        out.line(&t.dim(
            "  The firewall stays locked; `voidwire up` reconnects, `voidwire disarm` releases it.",
        ));
    }
    Ok(0)
}

async fn disarm(out: &mut Out, yes: bool) -> CliResult<i32> {
    let t = out.theme;
    if !yes {
        out.note(&t.warn(
            "Disarming removes the Iron Dome lockdown: traffic will flow UNPROTECTED outside the tunnel, \
             with your real IP and DNS visible to the network.",
        ));
        if !confirm(
            out,
            "Disarm the lockdown?",
            "Pass --yes to disarm non-interactively.",
        )
        .await?
        {
            return Err(CliError::new(
                ExitCode::Cancelled,
                "not disarmed; the lockdown is still in place",
            ));
        }
    }
    daemon::call_ok(&Request::Disarm).await?;
    ok_message(
        out,
        "lockdown released; traffic is no longer protected by VoidWire",
        json!({}),
    );
    Ok(0)
}

async fn status(out: &mut Out, audit: bool) -> CliResult<i32> {
    let mut c = daemon::connect().await?;
    let s = daemon::status(&mut c).await?;
    if !audit {
        if out.json {
            out.emit(&s);
        } else {
            let t = out.theme;
            out.print(&render::status_block(&t, &s));
        }
        return Ok(0);
    }
    let req = Request::Audit;
    let a = match daemon::call(&mut c, &req).await? {
        Response::Audit(a) => a,
        other => return Err(daemon::unexpected(&req, &other)),
    };
    let passed = render::audit_passed(&a);
    if out.json {
        out.emit_json(&json!({ "status": s, "audit": a, "passed": passed }));
    } else {
        let t = out.theme;
        out.print(&render::status_block(&t, &s));
        out.line("");
        out.print(&render::audit_table(&t, &a));
    }
    if passed {
        Ok(0)
    } else {
        let failed = a.checks.iter().filter(|c| !c.passed).count();
        Err(CliError::new(
            ExitCode::AuditFailed,
            format!("leak audit failed ({failed} of {} checks)", a.checks.len()),
        )
        .with_hint("Do not trust this connection until the failing checks pass; `voidwire panic` rotates everything."))
    }
}

async fn panic(out: &mut Out) -> CliResult<i32> {
    let mut c = daemon::connect().await?;
    let req = Request::Panic;
    let started = Instant::now();
    let resp = daemon::call(&mut c, &req).await?;
    let elapsed = started.elapsed();
    if !matches!(resp, Response::Ok) {
        return Err(daemon::unexpected(&req, &resp));
    }
    let s = daemon::status(&mut c).await?;
    let exit = render::exit_hop(&s.hops);
    if out.json {
        out.emit_json(&json!({
            "ok": true,
            "elapsed_ms": elapsed.as_secs_f64() * 1000.0,
            "state": s.state,
            "exit": exit,
        }));
        return Ok(0);
    }
    let t = out.theme;
    let ms = elapsed.as_secs_f64() * 1000.0;
    let timing = format!("{ms:.1} ms (measured by the CLI, including IPC)");
    out.line(&t.ok("✓ panic rotation complete"));
    out.line(&format!(
        "  elapsed    {}",
        if ms < 100.0 {
            t.ok(&timing)
        } else {
            t.warn(&timing)
        }
    ));
    out.line("  rotated    WireGuard + ML-KEM keys, DNS cache flushed; firewall stayed locked");
    match exit {
        Some(h) => out.line(&format!(
            "  new exit   {}{}",
            t.bold(&h.name),
            h.country
                .as_deref()
                .map(|c| format!(" ({c})"))
                .unwrap_or_default()
        )),
        None => out.line(&format!("  new exit   {}", t.dim("none reported"))),
    }
    out.line(&format!(
        "  state      {}",
        t.paint(render::state_style(s.state), render::state_name(s.state))
    ));
    Ok(0)
}

async fn optimize(out: &mut Out) -> CliResult<i32> {
    let req = Request::Optimize;
    if !out.json {
        out.note(
            &out.theme
                .dim("Measuring gateways and transports (this can take a minute)..."),
        );
    }
    let d = match daemon::call_once(&req).await? {
        Response::Optimized(d) => *d,
        other => return Err(daemon::unexpected(&req, &other)),
    };
    if out.json {
        out.emit(&d);
    } else {
        let t = out.theme;
        out.print(&render::decision_block(&t, &d));
    }
    Ok(0)
}

async fn nodes_list(out: &mut Out) -> CliResult<i32> {
    let req = Request::ListNodes;
    let nodes = match daemon::call_once(&req).await? {
        Response::Nodes(n) => n,
        other => return Err(daemon::unexpected(&req, &other)),
    };
    if out.json {
        out.emit(&nodes);
    } else {
        let t = out.theme;
        out.print(&render::nodes_table(&t, &nodes));
    }
    Ok(0)
}

/// Local sanity check of an import URI; returns a description.
pub fn describe_import_uri(uri: &str) -> CliResult<String> {
    let uri = uri.trim();
    if uri.starts_with(NODE_PREFIX) {
        let n = decode_node(uri).map_err(|e| CliError::usage(format!("invalid node URI: {e}")))?;
        Ok(format!("node '{}'", n.name))
    } else if uri.starts_with(F2F_PREFIX) {
        decode_blob(F2F_PREFIX, uri)
            .map_err(|e| CliError::usage(format!("invalid invite URI: {e}")))?;
        Ok("friend invite".into())
    } else {
        Err(CliError::usage(format!(
            "expected a {NODE_PREFIX}... or {F2F_PREFIX}... URI"
        )))
    }
}

async fn import(out: &mut Out, uri: &str) -> CliResult<i32> {
    let what = describe_import_uri(uri)?;
    daemon::call_ok(&Request::ImportNode {
        uri: uri.trim().to_string(),
    })
    .await?;
    ok_message(out, &format!("imported {what}"), json!({}));
    Ok(0)
}

async fn remove(out: &mut Out, name: &str) -> CliResult<i32> {
    daemon::call_ok(&Request::RemoveNode {
        name: name.to_string(),
    })
    .await?;
    ok_message(out, &format!("removed node '{name}'"), json!({}));
    Ok(0)
}

async fn redeem(out: &mut Out, uri: &str) -> CliResult<i32> {
    let uri = uri.trim();
    if !uri.starts_with(F2F_PREFIX) {
        return Err(CliError::usage(format!(
            "expected a {F2F_PREFIX}... invite URI"
        )));
    }
    describe_import_uri(uri)?;
    if !out.json {
        out.note(
            &out.theme.dim(
                "Redeeming the invite with the friend's node (blind-signed session tokens)...",
            ),
        );
    }
    daemon::call_ok(&Request::RedeemInvite {
        uri: uri.to_string(),
    })
    .await?;
    ok_message(
        out,
        "invite redeemed; connect with `voidwire up --profile f2f`",
        json!({}),
    );
    Ok(0)
}

async fn warp_register(out: &mut Out, accept_tos: bool) -> CliResult<i32> {
    let url = vw_freecloud::warp::WARP_TOS_URL;
    if !accept_tos {
        out.note(&format!(
            "Registering an anonymous Cloudflare WARP device means accepting Cloudflare's terms of service:\n  {url}"
        ));
        let hint = format!("Read {url} and pass --accept-tos to register non-interactively.");
        if !confirm(out, "Do you accept the Cloudflare WARP terms?", &hint).await? {
            return Err(CliError::new(
                ExitCode::Cancelled,
                "terms not accepted; nothing was registered",
            ));
        }
    }
    if !out.json {
        out.note(
            &out.theme
                .dim("Registering with Cloudflare through the daemon..."),
        );
    }
    daemon::call_ok(&Request::RegisterWarp).await?;
    ok_message(
        out,
        "WARP device registered; try `voidwire up --profile warp`",
        json!({ "tos_url": url }),
    );
    Ok(0)
}

async fn settings_get(out: &mut Out) -> CliResult<i32> {
    let req = Request::GetSettings;
    match daemon::call_once(&req).await? {
        Response::Settings(s) => {
            out.emit(&*s);
            Ok(0)
        }
        other => Err(daemon::unexpected(&req, &other)),
    }
}

/// Read `value` (inline JSON, `@FILE` or `@-` for stdin) as full settings.
pub fn parse_settings_arg(value: &str) -> CliResult<Settings> {
    let text = match value.strip_prefix('@') {
        Some("-") => {
            let mut s = String::new();
            std::io::Read::read_to_string(&mut std::io::stdin(), &mut s)
                .map_err(|e| CliError::usage(format!("reading stdin: {e}")))?;
            s
        }
        Some(path) => std::fs::read_to_string(path)
            .map_err(|e| CliError::usage(format!("cannot read {path}: {e}")))?,
        None => value.to_string(),
    };
    parse_settings(&text)
}

pub fn parse_settings(text: &str) -> CliResult<Settings> {
    serde_json::from_str::<Settings>(text).map_err(|e| {
        CliError::usage(format!("invalid settings JSON: {e}")).with_hint(
            "Settings must be a complete document; start from `voidwire settings get > s.json`, edit, then `voidwire settings set @s.json`.",
        )
    })
}

async fn settings_set(out: &mut Out, value: &str) -> CliResult<i32> {
    let s = parse_settings_arg(value)?;
    daemon::call_ok(&Request::SetSettings(Box::new(s))).await?;
    ok_message(out, "settings saved", json!({}));
    Ok(0)
}

async fn tui() -> CliResult<i32> {
    if !std::io::stdout().is_terminal() {
        return Err(CliError::usage(
            "`voidwire tui` needs an interactive terminal",
        ));
    }
    // Fail fast with install/start guidance instead of a full-screen retry loop.
    drop(daemon::connect().await?);
    vw_tui::run()
        .await
        .map_err(|e| CliError::failure(format!("tui: {e:#}")))?;
    Ok(0)
}
