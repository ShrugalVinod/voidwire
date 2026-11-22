//! `voidwire up`: send `Up`, then follow the event stream until the tunnel is
//! active, the daemon fails closed, or the deadline passes.

use std::time::{Duration, Instant};

use serde_json::json;
use tokio::sync::mpsc;
use vw_core::config::{Profile, TransportKind};
use vw_core::ipc::{DaemonEvent, IpcClient, Request, Response, StatusReport};
use vw_core::probe::OptimizerDecision;
use vw_core::state::DomeState;

use crate::daemon;
use crate::exit::{CliError, CliResult, ExitCode};
use crate::output::Out;
use crate::render;

/// Interval of the `Status` safety-net poll (covers events missed because the
/// subscription raced the `Up` request).
pub const STATUS_POLL: Duration = Duration::from_secs(2);

/// What ended the wait.
#[derive(Debug, Clone, PartialEq)]
pub enum UpOutcome {
    Active,
    Lockdown { reason: Option<String> },
    TimedOut { last: Option<DomeState> },
}

/// Tracks observed states so each transition is printed once, whether it
/// arrived as an event or was noticed by polling.
#[derive(Debug, Default)]
pub struct Tracker {
    pub current: Option<DomeState>,
    pub transitions: Vec<(u128, DomeState, DomeState)>,
}

impl Tracker {
    /// Record `to`; returns the transition to print, if it is new.
    pub fn observe(
        &mut self,
        at_ms: u128,
        from: Option<DomeState>,
        to: DomeState,
    ) -> Option<(DomeState, DomeState)> {
        if self.current == Some(to) {
            return None;
        }
        let from = from.or(self.current).unwrap_or(to);
        self.current = Some(to);
        if from == to {
            return None;
        }
        self.transitions.push((at_ms, from, to));
        Some((from, to))
    }
}

/// Classify a state reached while waiting. `trusted` is false for polled
/// states seen before the daemon acknowledged `Up` (they may be stale).
pub fn terminal(state: DomeState, trusted: bool) -> Option<UpOutcome> {
    if !trusted {
        return None;
    }
    match state {
        DomeState::TunnelActive | DomeState::KeyRotating => Some(UpOutcome::Active),
        DomeState::FailsafeLockdown => Some(UpOutcome::Lockdown { reason: None }),
        _ => None,
    }
}

pub fn lockdown_error(reason: Option<&str>) -> CliError {
    let reason = reason.unwrap_or("the daemon entered FailsafeLockdown");
    CliError::new(ExitCode::Lockdown, format!("tunnel failed: {reason}")).with_hint(
        "The firewall is still locked, so nothing leaks, but nothing gets out either. \
         Retry with `voidwire up` (try --profile stealth or another --transport), \
         or release the lockdown with `voidwire disarm`.",
    )
}

pub fn timeout_error(secs: u64, last: Option<DomeState>) -> CliError {
    let last = last.map(render::state_name).unwrap_or("unknown");
    CliError::new(
        ExitCode::Timeout,
        format!("tunnel not active after {secs}s (last state: {last})"),
    )
    .with_hint(
        "The daemon keeps trying and the firewall stays locked meanwhile. \
         Watch it with `voidwire status`, or release the lockdown with `voidwire disarm`.",
    )
}

async fn poll_status(client: &mut Option<IpcClient>) -> CliResult<StatusReport> {
    if client.is_none() {
        *client = Some(daemon::connect().await?);
    }
    let c = client.as_mut().expect("connected above");
    match daemon::status(c).await {
        Ok(s) => Ok(s),
        Err(e) => {
            *client = None;
            Err(e)
        }
    }
}

pub async fn run(
    out: &mut Out,
    profile: Option<Profile>,
    country: Option<String>,
    transport: Option<TransportKind>,
    timeout_secs: u64,
) -> CliResult<i32> {
    let theme = out.theme;
    let profile = match profile {
        Some(p) => p,
        None => match daemon::call_once(&Request::GetSettings).await? {
            Response::Settings(s) => s.default_profile,
            other => return Err(daemon::unexpected(&Request::GetSettings, &other)),
        },
    };

    // Subscribe first so the transitions caused by `Up` are not missed.
    let sub = daemon::connect()
        .await?
        .subscribe()
        .await
        .map_err(CliError::from_request)?;
    let (tx, mut events) = mpsc::unbounded_channel();
    let reader = tokio::spawn(async move {
        let mut sub = sub;
        while let Ok(ev) = sub.next().await {
            if tx.send(ev).is_err() {
                break;
            }
        }
    });

    let mut up_client = daemon::connect().await?;
    let mut status_client = Some(daemon::connect().await?);
    let initial = daemon::status(status_client.as_mut().expect("just connected")).await?;

    if !out.json {
        let mut what = format!("Bringing VoidWire up: {}", profile.label());
        if let Some(c) = &country {
            what.push_str(&format!(", country {c}"));
        }
        if let Some(t) = transport {
            what.push_str(&format!(", transport {}", t.label()));
        }
        out.line(&theme.bold(&what));
    }

    let req = Request::Up {
        profile,
        country: country.clone(),
        transport,
    };
    let mut up_task = tokio::spawn(async move { daemon::call(&mut up_client, &req).await });

    let started = Instant::now();
    let deadline = tokio::time::sleep(Duration::from_secs(timeout_secs));
    tokio::pin!(deadline);
    let mut poll = tokio::time::interval(STATUS_POLL);
    poll.tick().await;

    let mut tracker = Tracker {
        current: Some(initial.state),
        ..Default::default()
    };
    let mut up_done = false;
    let mut stream_open = true;
    let mut last_problem: Option<String> = None;
    let mut decision: Option<OptimizerDecision> = None;

    let outcome = loop {
        tokio::select! {
            ev = events.recv(), if stream_open => match ev {
                Some(DaemonEvent::StateChanged { from, to }) => {
                    let at = started.elapsed().as_millis();
                    if let Some((f, t)) = tracker.observe(at, Some(from), to) {
                        if !out.json {
                            out.line(&render::transition_line(&theme, at, f, t));
                        }
                    }
                    if let Some(o) = terminal(to, true) {
                        break o;
                    }
                }
                Some(DaemonEvent::Log { level, message }) => {
                    let lvl = level.to_ascii_lowercase();
                    if lvl == "warn" || lvl == "warning" || lvl == "error" {
                        if !out.json {
                            out.line(&format!("           {}", theme.warn(&message)));
                        }
                        last_problem = Some(message);
                    }
                }
                Some(DaemonEvent::Decision(d)) => decision = Some(d),
                Some(_) => {}
                None => stream_open = false,
            },
            r = &mut up_task, if !up_done => {
                up_done = true;
                let r = r.map_err(|e| CliError::failure(format!("internal task failed: {e}")))?;
                let s = poll_status(&mut status_client).await?;
                let at = started.elapsed().as_millis();
                if let Some((f, t)) = tracker.observe(at, None, s.state) {
                    if !out.json {
                        out.line(&render::transition_line(&theme, at, f, t));
                    }
                }
                match r {
                    Ok(Response::Ok) => {
                        if let Some(o) = terminal(s.state, true) {
                            break o;
                        }
                    }
                    Ok(other) => {
                        reader.abort();
                        return Err(daemon::unexpected(&Request::Up { profile, country, transport }, &other));
                    }
                    Err(e) if e.code == ExitCode::Rejected && s.state == DomeState::FailsafeLockdown => {
                        break UpOutcome::Lockdown {
                            reason: Some(e.message.trim_start_matches("voidwired: ").to_string()),
                        };
                    }
                    // The Up call itself timed out: keep following until our deadline.
                    Err(e) if e.code == ExitCode::Timeout => {}
                    Err(e) => {
                        reader.abort();
                        return Err(e);
                    }
                }
            },
            _ = poll.tick() => {
                if let Ok(s) = poll_status(&mut status_client).await {
                    let at = started.elapsed().as_millis();
                    let changed = tracker.observe(at, None, s.state);
                    if let Some((f, t)) = changed {
                        if !out.json {
                            out.line(&render::transition_line(&theme, at, f, t));
                        }
                    }
                    // Before Up is acknowledged, only a change we saw happen counts.
                    let trusted = up_done || !tracker.transitions.is_empty();
                    if let Some(o) = terminal(s.state, trusted) {
                        break o;
                    }
                }
            },
            _ = &mut deadline => break UpOutcome::TimedOut { last: tracker.current },
        }
    };
    reader.abort();
    if !up_done {
        up_task.abort();
    }

    let elapsed = started.elapsed();
    let transitions: Vec<_> = tracker
        .transitions
        .iter()
        .map(|(at, f, t)| json!({ "at_ms": at, "from": f, "to": t }))
        .collect();

    match outcome {
        UpOutcome::Active => {
            let status = poll_status(&mut status_client).await.ok();
            let decision = status
                .as_ref()
                .and_then(|s| s.decision.clone())
                .or(decision);
            if out.json {
                out.emit_json(&json!({
                    "state": status.as_ref().map(|s| s.state).unwrap_or(DomeState::TunnelActive),
                    "elapsed_ms": elapsed.as_millis(),
                    "transitions": transitions,
                    "decision": decision,
                    "status": status,
                }));
            } else {
                out.line(&theme.ok(&format!("✓ protected in {:.1}s", elapsed.as_secs_f64())));
                if let Some(s) = &status {
                    out.line(&format!("  route {}", render::route_line(&theme, &s.hops)));
                }
                match &decision {
                    Some(d) => out.print(&render::decision_block(&theme, d)),
                    None => {
                        out.line(&theme.dim("  (the daemon did not report an optimizer decision)"))
                    }
                }
            }
            Ok(ExitCode::Success.code())
        }
        UpOutcome::Lockdown { reason } => {
            let reason = reason.or(last_problem);
            Err(lockdown_error(reason.as_deref()))
        }
        UpOutcome::TimedOut { last } => Err(timeout_error(timeout_secs, last)),
    }
}
