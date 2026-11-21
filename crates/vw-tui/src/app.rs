//! Pure dashboard state. Every value shown on screen is derived from data the
//! daemon sent (`StatusReport`, `DaemonEvent`, `AuditReport`, command
//! responses); nothing here performs I/O.

use std::collections::VecDeque;
use std::time::{Duration, Instant};

use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use vw_core::config::Profile;
use vw_core::ipc::{AuditReport, DaemonEvent, Request, Response, StatusReport};
use vw_core::probe::OptimizerDecision;
use vw_core::state::DomeState;
use vw_core::telemetry::TelemetrySnapshot;

/// Number of per-second rate samples kept for the sparklines.
pub const RATE_HISTORY: usize = 120;
/// Snapshots closer together than this are not used for rate samples (the
/// status poll and the telemetry event stream can deliver almost at once).
pub const MIN_SAMPLE_GAP: Duration = Duration::from_millis(250);
/// How long a result banner stays on screen.
pub const BANNER_TTL: Duration = Duration::from_secs(6);
/// Daemon log lines kept in RAM for the log view.
pub const LOG_CAP: usize = 200;

// ───────────────────────────── key mapping ─────────────────────────────

/// What a key press means, independent of any I/O.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    None,
    Quit,
    /// `P`/`p`: panic identity rotation.
    Panic,
    /// `c`: connect with the Auto profile.
    Connect,
    /// `d`: disconnect, keep the lockdown armed.
    Disconnect,
    /// `D`: open the in-UI disarm confirmation.
    RequestDisarm,
    /// `y` while the confirmation is open.
    ConfirmDisarm,
    /// Any other key while the confirmation is open.
    CancelConfirm,
    /// `a`: run the live canary audit.
    Audit,
    /// `o`: re-run the optimizer.
    Optimize,
    /// Tab: focus the next panel.
    FocusNext,
    /// Shift+Tab: focus the previous panel.
    FocusPrev,
}

/// Map a key event to an [`Action`]. `confirm_pending` is true while the
/// disarm confirmation dialog is open.
pub fn map_key(key: KeyEvent, confirm_pending: bool) -> Action {
    // Windows reports both press and release; act on presses only.
    if key.kind != KeyEventKind::Press {
        return Action::None;
    }
    if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
        return Action::Quit;
    }
    if confirm_pending {
        return match key.code {
            KeyCode::Char('y') | KeyCode::Char('Y') => Action::ConfirmDisarm,
            _ => Action::CancelConfirm,
        };
    }
    match key.code {
        KeyCode::Char('q') | KeyCode::Esc => Action::Quit,
        KeyCode::Char('P') | KeyCode::Char('p') => Action::Panic,
        KeyCode::Char('c') => Action::Connect,
        KeyCode::Char('d') => Action::Disconnect,
        KeyCode::Char('D') => Action::RequestDisarm,
        KeyCode::Char('a') => Action::Audit,
        KeyCode::Char('o') => Action::Optimize,
        KeyCode::Tab => Action::FocusNext,
        KeyCode::BackTab => Action::FocusPrev,
        _ => Action::None,
    }
}

// ───────────────────────────── commands ────────────────────────────────

/// A daemon request triggered from the keyboard.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Command {
    Panic,
    Connect,
    Disconnect,
    Disarm,
    Audit,
    Optimize,
}

impl Command {
    /// The exact IPC request this command sends.
    pub fn request(self) -> Request {
        match self {
            Command::Panic => Request::Panic,
            Command::Connect => Request::Up {
                profile: Profile::Auto,
                country: None,
                transport: None,
            },
            Command::Disconnect => Request::Down {
                keep_lockdown: true,
            },
            // `Disarm` is valid from every locked FSM state (it tears the
            // tunnel down on the way), so it is the one request that always
            // means "disconnect and remove the lockdown".
            Command::Disarm => Request::Disarm,
            Command::Audit => Request::Audit,
            Command::Optimize => Request::Optimize,
        }
    }

    pub const fn label(self) -> &'static str {
        match self {
            Command::Panic => "panic rotate",
            Command::Connect => "connect",
            Command::Disconnect => "disconnect",
            Command::Disarm => "disarm",
            Command::Audit => "audit",
            Command::Optimize => "optimize",
        }
    }
}

// ───────────────────────────── focus ───────────────────────────────────

/// Which panel is enlarged. `Overview` shows the full dashboard.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Focus {
    #[default]
    Overview,
    Map,
    Traffic,
    Crypto,
    Firewall,
    Shield,
    Optimizer,
    Log,
}

impl Focus {
    pub const ORDER: [Focus; 8] = [
        Focus::Overview,
        Focus::Map,
        Focus::Traffic,
        Focus::Crypto,
        Focus::Firewall,
        Focus::Shield,
        Focus::Optimizer,
        Focus::Log,
    ];

    fn index(self) -> usize {
        Self::ORDER.iter().position(|f| *f == self).unwrap_or(0)
    }

    pub fn next(self) -> Focus {
        Self::ORDER[(self.index() + 1) % Self::ORDER.len()]
    }

    pub fn prev(self) -> Focus {
        let n = Self::ORDER.len();
        Self::ORDER[(self.index() + n - 1) % n]
    }

    pub const fn title(self) -> &'static str {
        match self {
            Focus::Overview => "Overview",
            Focus::Map => "World Route Map",
            Focus::Traffic => "Encrypted Traffic",
            Focus::Crypto => "Cryptographic Suite",
            Focus::Firewall => "Iron Dome Firewall Matrix",
            Focus::Shield => "Shield",
            Focus::Optimizer => "Optimizer",
            Focus::Log => "Daemon Log",
        }
    }
}

// ───────────────────────────── rates ───────────────────────────────────

/// A bounded series of bytes-per-second samples.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct RateSeries {
    samples: VecDeque<u64>,
}

impl RateSeries {
    pub fn push(&mut self, bytes_per_sec: u64) {
        if self.samples.len() == RATE_HISTORY {
            self.samples.pop_front();
        }
        self.samples.push_back(bytes_per_sec);
    }

    pub fn current(&self) -> Option<u64> {
        self.samples.back().copied()
    }

    pub fn peak(&self) -> u64 {
        self.samples.iter().copied().max().unwrap_or(0)
    }

    pub fn len(&self) -> usize {
        self.samples.len()
    }

    pub fn is_empty(&self) -> bool {
        self.samples.is_empty()
    }

    /// The newest `n` samples, oldest first.
    pub fn tail(&self, n: usize) -> Vec<u64> {
        let skip = self.samples.len().saturating_sub(n);
        self.samples.iter().skip(skip).copied().collect()
    }

    pub fn clear(&mut self) {
        self.samples.clear();
    }
}

/// Bytes per second between two counter readings. `None` when the counter
/// went backwards (daemon restart) or the interval is unusable.
pub fn rate_between(prev_bytes: u64, now_bytes: u64, elapsed: Duration) -> Option<u64> {
    let secs = elapsed.as_secs_f64();
    if now_bytes < prev_bytes || secs.is_nan() || secs <= 0.0 {
        return None;
    }
    Some(((now_bytes - prev_bytes) as f64 / secs).round() as u64)
}

#[derive(Debug, Clone, Copy, PartialEq)]
struct CounterSample {
    at: Instant,
    rx_bytes: u64,
    tx_bytes: u64,
}

// ───────────────────────────── link / banner ───────────────────────────

/// Status-poll connection to the daemon.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Link {
    /// First connection attempt still in progress.
    Connecting,
    /// Authenticated; `daemon_version` from the IPC handshake.
    Online { daemon_version: String },
    /// Unreachable; retried every 2 s.
    Offline { error: String, attempts: u32 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tone {
    Info,
    Success,
    Warning,
    Danger,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Banner {
    pub text: String,
    pub tone: Tone,
    pub until: Instant,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogLine {
    pub level: String,
    pub message: String,
}

// ───────────────────────────── App ─────────────────────────────────────

#[derive(Debug, Clone)]
pub struct App {
    pub link: Link,
    /// Whether the separate `Subscribe` event stream is connected.
    pub events_online: bool,
    pub events_error: Option<String>,
    pub status: Option<StatusReport>,
    pub decision: Option<OptimizerDecision>,
    pub last_audit: Option<AuditReport>,
    pub rx: RateSeries,
    pub tx: RateSeries,
    last_sample: Option<CounterSample>,
    pub banner: Option<Banner>,
    pub focus: Focus,
    pub confirm_disarm: bool,
    pub in_flight: Vec<Command>,
    pub logs: VecDeque<LogLine>,
    pub should_quit: bool,
}

impl Default for App {
    fn default() -> Self {
        Self::new()
    }
}

impl App {
    pub fn new() -> Self {
        Self {
            link: Link::Connecting,
            events_online: false,
            events_error: None,
            status: None,
            decision: None,
            last_audit: None,
            rx: RateSeries::default(),
            tx: RateSeries::default(),
            last_sample: None,
            banner: None,
            focus: Focus::Overview,
            confirm_disarm: false,
            in_flight: Vec::new(),
            logs: VecDeque::new(),
            should_quit: false,
        }
    }

    pub fn is_online(&self) -> bool {
        matches!(self.link, Link::Online { .. })
    }

    pub fn state(&self) -> Option<DomeState> {
        self.status.as_ref().map(|s| s.state)
    }

    // ── link ───────────────────────────────────────────────────────────

    pub fn link_up(&mut self, daemon_version: String) {
        self.link = Link::Online { daemon_version };
    }

    /// The daemon became unreachable: drop everything it told us so the UI
    /// never shows stale data as live.
    pub fn link_down(&mut self, error: String) {
        let attempts = match &self.link {
            Link::Offline { attempts, .. } => attempts.saturating_add(1),
            _ => 1,
        };
        self.link = Link::Offline { error, attempts };
        self.status = None;
        self.decision = None;
        self.last_sample = None;
        self.rx.clear();
        self.tx.clear();
        self.in_flight.clear();
        self.confirm_disarm = false;
    }

    pub fn events_up(&mut self) {
        self.events_online = true;
        self.events_error = None;
    }

    pub fn events_down(&mut self, error: String) {
        self.events_online = false;
        self.events_error = Some(error);
    }

    // ── daemon data ────────────────────────────────────────────────────

    pub fn apply_status(&mut self, report: StatusReport) {
        self.apply_status_at(report, Instant::now());
    }

    pub fn apply_status_at(&mut self, report: StatusReport, now: Instant) {
        self.sample_telemetry(&report.telemetry, now);
        if report.decision.is_some() {
            self.decision = report.decision.clone();
        }
        if let Link::Connecting = self.link {
            self.link = Link::Online {
                daemon_version: report.daemon_version.clone(),
            };
        }
        self.status = Some(report);
    }

    pub fn apply_event(&mut self, event: DaemonEvent) {
        self.apply_event_at(event, Instant::now());
    }

    pub fn apply_event_at(&mut self, event: DaemonEvent, now: Instant) {
        match event {
            DaemonEvent::StateChanged { from, to } => {
                if let Some(s) = self.status.as_mut() {
                    s.state = to;
                }
                self.push_log("state", format!("{from:?} → {to:?}"));
            }
            DaemonEvent::Telemetry(t) => {
                self.sample_telemetry(&t, now);
                if let Some(s) = self.status.as_mut() {
                    s.telemetry = t;
                }
            }
            DaemonEvent::Audit(report) => self.apply_audit(report),
            DaemonEvent::Decision(d) => {
                if let Some(s) = self.status.as_mut() {
                    s.decision = Some(d.clone());
                }
                self.decision = Some(d);
            }
            DaemonEvent::Log { level, message } => self.push_log(&level, message),
            // The live DNS inspector carries queried names; the dashboard
            // deliberately never renders or stores them.
            DaemonEvent::DnsInspect { .. } => {}
        }
    }

    pub fn apply_audit(&mut self, report: AuditReport) {
        self.last_audit = Some(report);
    }

    fn sample_telemetry(&mut self, t: &TelemetrySnapshot, now: Instant) {
        let sample = CounterSample {
            at: now,
            rx_bytes: t.rx_bytes,
            tx_bytes: t.tx_bytes,
        };
        let Some(prev) = self.last_sample else {
            self.last_sample = Some(sample);
            return;
        };
        let elapsed = now.saturating_duration_since(prev.at);
        if elapsed < MIN_SAMPLE_GAP {
            return;
        }
        match (
            rate_between(prev.rx_bytes, t.rx_bytes, elapsed),
            rate_between(prev.tx_bytes, t.tx_bytes, elapsed),
        ) {
            (Some(rx), Some(tx)) => {
                self.rx.push(rx);
                self.tx.push(tx);
            }
            // Counters reset (daemon restarted): start a fresh baseline.
            _ => {
                self.rx.clear();
                self.tx.clear();
            }
        }
        self.last_sample = Some(sample);
    }

    fn push_log(&mut self, level: &str, message: String) {
        if self.logs.len() == LOG_CAP {
            self.logs.pop_front();
        }
        self.logs.push_back(LogLine {
            level: level.to_string(),
            message,
        });
    }

    // ── user actions ───────────────────────────────────────────────────

    pub fn set_banner(&mut self, text: impl Into<String>, tone: Tone, now: Instant) {
        self.banner = Some(Banner {
            text: text.into(),
            tone,
            until: now + BANNER_TTL,
        });
    }

    /// Expire timed UI elements.
    pub fn tick(&mut self, now: Instant) {
        if self.banner.as_ref().is_some_and(|b| now >= b.until) {
            self.banner = None;
        }
    }

    /// Apply an action to UI state; returns the daemon command to send, if any.
    pub fn perform(&mut self, action: Action, now: Instant) -> Option<Command> {
        let cmd = match action {
            Action::None => return None,
            Action::Quit => {
                self.should_quit = true;
                return None;
            }
            Action::FocusNext => {
                self.focus = self.focus.next();
                return None;
            }
            Action::FocusPrev => {
                self.focus = self.focus.prev();
                return None;
            }
            Action::RequestDisarm => {
                if self.is_online() {
                    self.confirm_disarm = true;
                } else {
                    self.set_banner("Daemon unreachable — disarm not sent", Tone::Warning, now);
                }
                return None;
            }
            Action::CancelConfirm => {
                self.confirm_disarm = false;
                self.set_banner("Disarm cancelled — lockdown unchanged", Tone::Info, now);
                return None;
            }
            Action::ConfirmDisarm => {
                self.confirm_disarm = false;
                Command::Disarm
            }
            Action::Panic => Command::Panic,
            Action::Connect => Command::Connect,
            Action::Disconnect => Command::Disconnect,
            Action::Audit => Command::Audit,
            Action::Optimize => Command::Optimize,
        };
        if !self.is_online() {
            self.set_banner(
                format!("Daemon unreachable — {} not sent", cmd.label()),
                Tone::Warning,
                now,
            );
            return None;
        }
        if self.in_flight.contains(&cmd) {
            self.set_banner(
                format!("{} already in progress", cmd.label()),
                Tone::Info,
                now,
            );
            return None;
        }
        self.in_flight.push(cmd);
        Some(cmd)
    }

    /// Record the daemon's answer to a command.
    pub fn apply_command_result(
        &mut self,
        cmd: Command,
        result: Result<Response, String>,
        now: Instant,
    ) {
        self.in_flight.retain(|c| *c != cmd);
        let resp = match result {
            Ok(r) => r,
            Err(e) => {
                let text = match cmd {
                    Command::Panic => format!("PANIC ROTATION FAILED — {e}"),
                    _ => format!("{} failed — {e}", cmd.label()),
                };
                self.set_banner(text, Tone::Danger, now);
                return;
            }
        };
        match resp {
            Response::Status(ref r) => self.apply_status_at((**r).clone(), now),
            Response::Audit(ref a) => self.apply_audit(a.clone()),
            Response::Optimized(ref d) => {
                if let Some(s) = self.status.as_mut() {
                    s.decision = Some((**d).clone());
                }
                self.decision = Some((**d).clone());
            }
            _ => {}
        }
        let (text, tone) = match (cmd, &resp) {
            (Command::Panic, _) => (
                "IDENTITY ROTATED — fresh WG + PQ keys, DNS flushed, exit switched; firewall stayed locked"
                    .to_string(),
                Tone::Success,
            ),
            (Command::Audit, Response::Audit(a)) => {
                let passed = a.checks.iter().filter(|c| c.passed).count();
                if a.passed {
                    (
                        format!("AUDIT PASSED — {passed}/{} checks", a.checks.len()),
                        Tone::Success,
                    )
                } else {
                    (
                        format!(
                            "AUDIT FAILED — {} of {} checks failed",
                            a.checks.len() - passed,
                            a.checks.len()
                        ),
                        Tone::Danger,
                    )
                }
            }
            (Command::Audit, _) => ("Audit requested".to_string(), Tone::Info),
            (Command::Optimize, Response::Optimized(d)) => (
                format!(
                    "Optimizer chose {} via {}",
                    if d.hops.is_empty() {
                        "no hops".to_string()
                    } else {
                        d.hops.join(" → ")
                    },
                    d.transport.label()
                ),
                Tone::Success,
            ),
            (Command::Optimize, _) => ("Optimizer re-run requested".to_string(), Tone::Info),
            (Command::Connect, _) => ("Connect (Auto) accepted".to_string(), Tone::Info),
            (Command::Disconnect, _) => (
                "Disconnected — lockdown kept armed (no traffic leaves)".to_string(),
                Tone::Warning,
            ),
            (Command::Disarm, _) => (
                "Disarmed — firewall lockdown removed, traffic is NOT protected".to_string(),
                Tone::Danger,
            ),
        };
        self.set_banner(text, tone, now);
    }
}
