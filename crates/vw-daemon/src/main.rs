//! `voidwired` — the privileged VoidWire client service.

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "voidwired",
    version,
    about = "VoidWire privileged client daemon"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Run in the foreground (started by launchd / the Windows SCM / systemd).
    Run,
    /// Install and start the system service (root / Administrator).
    Install,
    /// Disarm, stop and remove the service.
    Uninstall {
        /// Keep the client store and IPC token.
        #[arg(long)]
        keep_config: bool,
    },
    /// Print whether the service is installed and running.
    Status,
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Run => {
            #[cfg(windows)]
            {
                if vw_daemon::service::windows::dispatch()? {
                    return Ok(());
                }
            }
            let events = vw_daemon::events::EventHub::new();
            vw_daemon::service::init_tracing(events.clone());
            let rt = tokio::runtime::Runtime::new()?;
            rt.block_on(vw_daemon::service::run_daemon(events, shutdown_signal()))
        }
        Cmd::Install => {
            vw_daemon::service::init_tracing(vw_daemon::events::EventHub::new());
            tokio::runtime::Runtime::new()?.block_on(vw_daemon::service::install())?;
            println!("voidwired installed and started");
            Ok(())
        }
        Cmd::Uninstall { keep_config } => {
            vw_daemon::service::init_tracing(vw_daemon::events::EventHub::new());
            tokio::runtime::Runtime::new()?.block_on(vw_daemon::service::uninstall(keep_config))?;
            println!("voidwired disarmed and uninstalled");
            Ok(())
        }
        Cmd::Status => {
            let s = vw_daemon::service::status()?;
            println!(
                "installed: {}\nrunning: {}",
                if s.installed { "yes" } else { "no" },
                if s.running { "yes" } else { "no" }
            );
            Ok(())
        }
    }
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        match signal(SignalKind::terminate()) {
            Ok(mut term) => {
                tokio::select! {
                    _ = term.recv() => {}
                    _ = tokio::signal::ctrl_c() => {}
                }
            }
            Err(_) => {
                let _ = tokio::signal::ctrl_c().await;
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}
