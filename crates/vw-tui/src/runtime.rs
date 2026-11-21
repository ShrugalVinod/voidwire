//! Async driver: status poller, event subscriber, command tasks and the
//! keyboard, multiplexed with `tokio::select!`.

use std::fmt::Display;
use std::future::Future;
use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crossterm::event::Event;
use futures_util::{Stream, StreamExt};
use ratatui::backend::Backend;
use ratatui::Terminal;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use vw_core::ipc::{DaemonEvent, IpcClient, Request, Response, StatusReport};

use crate::app::{map_key, App, Command};
use crate::ui;

/// Status is polled this often on the dedicated status connection.
pub const POLL_INTERVAL: Duration = Duration::from_secs(1);
/// Delay between reconnection attempts when the daemon is unreachable.
pub const RETRY_INTERVAL: Duration = Duration::from_secs(2);
/// UI housekeeping tick (banner expiry, redraw).
const UI_TICK: Duration = Duration::from_millis(250);

/// Set by the panic hook so the UI loop stops drawing after the terminal
/// has been restored.
pub(crate) static PANICKED: AtomicBool = AtomicBool::new(false);

#[derive(Debug)]
pub(crate) enum Msg {
    LinkUp(String),
    LinkDown(String),
    Status(Box<StatusReport>),
    EventsUp,
    EventsDown(String),
    Event(Box<DaemonEvent>),
    Command(Command, Result<Response, String>),
}

fn response_name(r: &Response) -> &'static str {
    match r {
        Response::Ok => "Ok",
        Response::Error { .. } => "Error",
        Response::Status(_) => "Status",
        Response::Audit(_) => "Audit",
        Response::Optimized(_) => "Optimized",
        Response::Settings(_) => "Settings",
        Response::Nodes(_) => "Nodes",
        Response::Telemetry(_) => "Telemetry",
        Response::Exec(_) => "Exec",
        Response::Event(_) => "Event",
    }
}

async fn status_poller<F, Fut, E>(connect: Arc<F>, tx: mpsc::Sender<Msg>)
where
    F: Fn() -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Result<IpcClient, E>> + Send + 'static,
    E: Display + Send + 'static,
{
    loop {
        match (*connect)().await {
            Err(e) => {
                if tx.send(Msg::LinkDown(e.to_string())).await.is_err() {
                    return;
                }
            }
            Ok(mut client) => {
                if tx
                    .send(Msg::LinkUp(client.daemon_version.clone()))
                    .await
                    .is_err()
                {
                    return;
                }
                let mut tick = tokio::time::interval(POLL_INTERVAL);
                tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
                loop {
                    tick.tick().await;
                    let msg = match client.request(&Request::Status).await {
                        Ok(Response::Status(r)) => Msg::Status(r),
                        Ok(other) => Msg::LinkDown(format!(
                            "daemon answered Status with an unexpected {} response",
                            response_name(&other)
                        )),
                        Err(e) => Msg::LinkDown(e.to_string()),
                    };
                    let lost = matches!(msg, Msg::LinkDown(_));
                    if tx.send(msg).await.is_err() {
                        return;
                    }
                    if lost {
                        break;
                    }
                }
            }
        }
        tokio::time::sleep(RETRY_INTERVAL).await;
    }
}

async fn event_subscriber<F, Fut, E>(connect: Arc<F>, tx: mpsc::Sender<Msg>)
where
    F: Fn() -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Result<IpcClient, E>> + Send + 'static,
    E: Display + Send + 'static,
{
    loop {
        let err = match (*connect)().await {
            Err(e) => e.to_string(),
            Ok(client) => match client.subscribe().await {
                Err(e) => e.to_string(),
                Ok(mut events) => {
                    if tx.send(Msg::EventsUp).await.is_err() {
                        return;
                    }
                    loop {
                        match events.next().await {
                            Ok(ev) => {
                                if tx.send(Msg::Event(Box::new(ev))).await.is_err() {
                                    return;
                                }
                            }
                            Err(e) => break e.to_string(),
                        }
                    }
                }
            },
        };
        if tx.send(Msg::EventsDown(err)).await.is_err() {
            return;
        }
        tokio::time::sleep(RETRY_INTERVAL).await;
    }
}

fn spawn_command<F, Fut, E>(connect: Arc<F>, tx: mpsc::Sender<Msg>, cmd: Command)
where
    F: Fn() -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Result<IpcClient, E>> + Send + 'static,
    E: Display + Send + 'static,
{
    tokio::spawn(async move {
        let result = match (*connect)().await {
            Err(e) => Err(e.to_string()),
            Ok(mut client) => client
                .request(&cmd.request())
                .await
                .map_err(|e| e.to_string()),
        };
        // The UI may already have quit; nothing to report to then.
        let _ = tx.send(Msg::Command(cmd, result)).await;
    });
}

fn apply_msg(app: &mut App, msg: Msg) {
    let now = Instant::now();
    match msg {
        Msg::LinkUp(v) => app.link_up(v),
        Msg::LinkDown(e) => app.link_down(e),
        Msg::Status(r) => app.apply_status_at(*r, now),
        Msg::EventsUp => app.events_up(),
        Msg::EventsDown(e) => app.events_down(e),
        Msg::Event(ev) => app.apply_event_at(*ev, now),
        Msg::Command(cmd, res) => app.apply_command_result(cmd, res, now),
    }
}

struct AbortOnDrop(Vec<JoinHandle<()>>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        for h in &self.0 {
            h.abort();
        }
    }
}

/// Run the dashboard on any ratatui backend with any key-event source.
pub(crate) async fn drive<B, I, F, Fut, E>(
    terminal: &mut Terminal<B>,
    mut input: I,
    connect: F,
) -> anyhow::Result<App>
where
    B: Backend,
    I: Stream<Item = io::Result<Event>> + Unpin,
    F: Fn() -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Result<IpcClient, E>> + Send + 'static,
    E: Display + Send + 'static,
{
    let connect = Arc::new(connect);
    let (tx, mut rx) = mpsc::channel::<Msg>(256);
    let _tasks = AbortOnDrop(vec![
        tokio::spawn(status_poller(connect.clone(), tx.clone())),
        tokio::spawn(event_subscriber(connect.clone(), tx.clone())),
    ]);
    let mut app = App::new();
    let mut tick = tokio::time::interval(UI_TICK);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        if PANICKED.load(Ordering::SeqCst) {
            anyhow::bail!("vw-tui task panicked; terminal restored");
        }
        terminal.draw(|f| ui::draw(f, &app))?;
        if app.should_quit {
            return Ok(app);
        }
        tokio::select! {
            msg = rx.recv() => {
                if let Some(msg) = msg {
                    apply_msg(&mut app, msg);
                    // Drain whatever else is queued before the next redraw.
                    while let Ok(more) = rx.try_recv() {
                        apply_msg(&mut app, more);
                    }
                }
            }
            ev = input.next() => match ev {
                Some(Ok(Event::Key(key))) => {
                    let action = map_key(key, app.confirm_disarm);
                    if let Some(cmd) = app.perform(action, Instant::now()) {
                        spawn_command(connect.clone(), tx.clone(), cmd);
                    }
                }
                Some(Ok(_)) => {}
                Some(Err(e)) => return Err(anyhow::Error::new(e).context("reading terminal input")),
                None => return Ok(app),
            },
            _ = tick.tick() => app.tick(Instant::now()),
        }
    }
}

// ───────────────────────────── terminal ────────────────────────────────

fn restore_terminal() {
    let _ = crossterm::terminal::disable_raw_mode();
    let _ = crossterm::execute!(
        io::stdout(),
        crossterm::terminal::LeaveAlternateScreen,
        crossterm::cursor::Show
    );
}

/// Restores the terminal when dropped (normal exit and error paths).
struct TerminalGuard;

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        restore_terminal();
    }
}

fn install_panic_hook() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        let previous = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            PANICKED.store(true, Ordering::SeqCst);
            restore_terminal();
            previous(info);
        }));
    });
}

/// Enter the alternate screen and run the dashboard until the user quits.
pub async fn run_with<F, Fut, E>(connect: F) -> anyhow::Result<()>
where
    F: Fn() -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Result<IpcClient, E>> + Send + 'static,
    E: Display + Send + 'static,
{
    install_panic_hook();
    crossterm::terminal::enable_raw_mode()?;
    let guard = TerminalGuard;
    crossterm::execute!(
        io::stdout(),
        crossterm::terminal::EnterAlternateScreen,
        crossterm::cursor::Hide
    )?;
    let mut terminal = Terminal::new(ratatui::backend::CrosstermBackend::new(io::stdout()))?;
    terminal.clear()?;
    let result = drive(&mut terminal, crossterm::event::EventStream::new(), connect).await;
    drop(terminal);
    drop(guard);
    result.map(|_| ())
}

/// Run the dashboard against the local `voidwired` using the on-disk token.
pub async fn run() -> anyhow::Result<()> {
    run_with(IpcClient::connect_default).await
}
