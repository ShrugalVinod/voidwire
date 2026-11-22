//! `voidwire-node` binary (ARCHITECTURE.md §13).

use anyhow::{bail, Context, Result};
use clap::Parser;
use vw_server::cli::{parse_bandwidth_arg, Cli, Command};

fn init_logging() {
    // Default: off. Only `VOIDWIRE_NODE_LOG` enables output, to stderr.
    let filter = tracing_subscriber::EnvFilter::try_from_env("VOIDWIRE_NODE_LOG")
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("off"));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .with_ansi(false)
        .try_init();
}

#[tokio::main]
async fn main() -> Result<()> {
    init_logging();
    let cli = Cli::parse();
    match cli.command {
        Command::Run(args) => vw_server::run::run(args)
            .await
            .context("voidwire-node run")?,
        Command::Uri { state, qr } => {
            let uri = vw_server::state::read_node_uri(&state)?;
            println!("{uri}");
            if qr {
                println!("{}", vw_freecloud::qr::render_terminal(&uri)?);
            }
        }
        Command::Invite {
            state,
            bandwidth_limit,
            expires,
        } => invite(&state, &bandwidth_limit, &expires).await?,
        Command::Attest { state, nonce } => attest(&state, nonce).await?,
    }
    Ok(())
}

#[cfg(unix)]
async fn invite(state: &std::path::Path, bandwidth: &str, expires: &str) -> Result<()> {
    use vw_server::control::{request, ControlRequest, ControlResponse};
    let bandwidth_bps = parse_bandwidth_arg(bandwidth)?;
    let expires_in_secs = vw_crypto::parse_duration(expires)?.as_secs();
    let resp = request(
        state,
        &ControlRequest::Invite {
            bandwidth_bps,
            expires_in_secs,
        },
    )
    .await?;
    match resp {
        ControlResponse::Invite {
            uri,
            tier,
            bandwidth_bps,
            expires_unix,
        } => {
            eprintln!(
                "single-use invite: tier {tier} ({}), expires at unix {expires_unix}; treat it as a secret",
                vw_server::admission::format_bandwidth(bandwidth_bps)
            );
            println!("{uri}");
            println!("{}", vw_freecloud::qr::render_terminal(&uri)?);
            Ok(())
        }
        ControlResponse::Error { message } => bail!("node refused: {message}"),
        ControlResponse::Attest { .. } => bail!("unexpected response from node"),
    }
}

#[cfg(unix)]
async fn attest(state: &std::path::Path, nonce: Option<String>) -> Result<()> {
    use vw_server::control::{request, ControlRequest, ControlResponse};
    let nonce = match nonce {
        Some(n) => n,
        None => hex::encode(rand::random::<[u8; 32]>()),
    };
    match request(state, &ControlRequest::Attest { nonce }).await? {
        ControlResponse::Attest { attestation } => {
            attestation
                .verify_signature()
                .context("node returned an invalid signature")?;
            println!("{}", serde_json::to_string_pretty(&attestation)?);
            Ok(())
        }
        ControlResponse::Error { message } => bail!("node refused: {message}"),
        ControlResponse::Invite { .. } => bail!("unexpected response from node"),
    }
}

#[cfg(not(unix))]
async fn invite(_: &std::path::Path, bandwidth: &str, expires: &str) -> Result<()> {
    parse_bandwidth_arg(bandwidth)?;
    vw_crypto::parse_duration(expires)?;
    bail!("the node control socket requires a Unix system")
}

#[cfg(not(unix))]
async fn attest(_: &std::path::Path, _: Option<String>) -> Result<()> {
    bail!("the node control socket requires a Unix system")
}
