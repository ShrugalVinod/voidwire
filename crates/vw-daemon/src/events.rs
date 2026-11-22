//! Daemon event broadcast and the sanitized log forwarder.

use tokio::sync::broadcast;
use tracing::{Event, Level, Subscriber};
use tracing_subscriber::layer::Context;
use tracing_subscriber::Layer;
use vw_core::ipc::DaemonEvent;

/// Fan-out of [`DaemonEvent`]s to every `Subscribe`d IPC client.
#[derive(Debug, Clone)]
pub struct EventHub {
    tx: broadcast::Sender<DaemonEvent>,
}

impl Default for EventHub {
    fn default() -> Self {
        Self::new()
    }
}

impl EventHub {
    pub fn new() -> Self {
        let (tx, _) = broadcast::channel(512);
        Self { tx }
    }

    pub fn emit(&self, e: DaemonEvent) {
        let _ = self.tx.send(e);
    }

    pub fn subscribe(&self) -> broadcast::Receiver<DaemonEvent> {
        self.tx.subscribe()
    }

    pub fn has_subscribers(&self) -> bool {
        self.tx.receiver_count() > 0
    }

    pub fn log(&self, level: &str, message: impl Into<String>) {
        self.emit(DaemonEvent::Log {
            level: level.into(),
            message: vw_firewall::scrub_addresses(&message.into()),
        });
    }
}

/// `tracing` layer forwarding info/warn/error events as `DaemonEvent::Log`.
/// The workspace never logs addresses or names at these levels; addresses are
/// still scrubbed as defence in depth.
pub struct LogForward {
    hub: EventHub,
}

impl LogForward {
    pub fn new(hub: EventHub) -> Self {
        Self { hub }
    }
}

struct Msg(String);

impl tracing::field::Visit for Msg {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            self.0 = format!("{value:?}");
        } else if !self.0.is_empty() {
            self.0.push_str(&format!(" {}={value:?}", field.name()));
        }
    }
}

impl<S: Subscriber> Layer<S> for LogForward {
    fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
        let lvl = *event.metadata().level();
        if lvl > Level::INFO || !self.hub.has_subscribers() {
            return;
        }
        let mut m = Msg(String::new());
        event.record(&mut m);
        self.hub
            .log(&lvl.to_string().to_ascii_lowercase(), m.0.trim_matches('"'));
    }
}
