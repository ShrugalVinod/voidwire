//! `voidwire-node` command line (ARCHITECTURE.md §13).

use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};
use vw_core::consts::{DEFAULT_MASQUE_PORT, DEFAULT_NODE_UDP_PORT, DEFAULT_TLS_PORT};

use crate::node::DEFAULT_MAX_PEERS;

#[derive(Debug, Parser)]
#[command(
    name = "voidwire-node",
    version,
    about = "RAM-only VoidWire exit/relay node"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Create the identity on first start, write DIR/node.uri, then serve.
    Run(RunArgs),
    /// Print the voidwire://node/... URI.
    Uri {
        #[arg(long, value_name = "DIR")]
        state: PathBuf,
        /// Also render a terminal QR code.
        #[arg(long)]
        qr: bool,
    },
    /// Ask the running node for a single-use voidwire://f2f/... invite.
    Invite {
        #[arg(long, value_name = "DIR")]
        state: PathBuf,
        /// e.g. 50Mbps, 200Mbps, or "unlimited" (rounded down to a tier).
        #[arg(long, value_name = "RATE")]
        bandwidth_limit: String,
        /// e.g. 30d, 12h.
        #[arg(long, value_name = "DURATION")]
        expires: String,
    },
    /// Print a fresh signed attestation (JSON) from the running node.
    Attest {
        #[arg(long, value_name = "DIR")]
        state: PathBuf,
        /// Verifier nonce (64 hex chars); random when omitted.
        #[arg(long, value_name = "HEX")]
        nonce: Option<String>,
    },
}

#[derive(Debug, Clone, Args)]
pub struct RunArgs {
    /// State directory (must be tmpfs/ramfs with --ram-only).
    #[arg(long, value_name = "DIR")]
    pub state: PathBuf,
    /// Refuse to start unless the state dir is RAM-backed and swap is off.
    #[arg(long)]
    pub ram_only: bool,
    /// Node name shown to clients.
    #[arg(long, default_value = "voidwire-node")]
    pub name: String,
    /// Shared WireGuard + AmneziaWG UDP listener.
    #[arg(long, value_name = "HOST:PORT", default_value_t = format!("0.0.0.0:{DEFAULT_NODE_UDP_PORT}"))]
    pub listen_udp: String,
    /// MASQUE (QUIC) listener.
    #[arg(long, value_name = "HOST:PORT", default_value_t = format!("0.0.0.0:{DEFAULT_MASQUE_PORT}"))]
    pub listen_quic: String,
    /// TLS-WebSocket listener.
    #[arg(long, value_name = "HOST:PORT", default_value_t = format!("0.0.0.0:{DEFAULT_TLS_PORT}"))]
    pub listen_tls: String,
    /// TLS / QUIC server name for the node certificate.
    #[arg(long, value_name = "NAME")]
    pub sni: String,
    /// Owner device WireGuard public key (base64), repeatable.
    #[arg(long = "authorize", value_name = "WGPUB")]
    pub authorize: Vec<String>,
    /// Serve this static site as the TLS-WS decoy.
    #[arg(long, value_name = "DIR")]
    pub decoy_dir: Option<PathBuf>,
    /// Internet-facing interface (auto-detected via `ip route get`).
    #[arg(long, value_name = "IFACE")]
    pub egress_iface: Option<String>,
    /// Address or name clients use to reach the node (default: the egress
    /// interface's IPv4 address).
    #[arg(long, value_name = "HOST", env = "VOIDWIRE_PUBLIC_HOST")]
    pub public_host: Option<String>,
    /// Maximum simultaneous non-owner WireGuard peers.
    #[arg(long, default_value_t = DEFAULT_MAX_PEERS)]
    pub max_peers: usize,
}

/// Parse `--bandwidth-limit` (bits/s, 0 = unlimited).
pub fn parse_bandwidth_arg(s: &str) -> vw_core::Result<u64> {
    let t = s.trim();
    if t.eq_ignore_ascii_case("unlimited") || t == "0" {
        return Ok(0);
    }
    Ok(vw_crypto::parse_bandwidth(t)?)
}

/// Parse a base64 WireGuard public key.
pub fn parse_wg_key(s: &str) -> vw_core::Result<[u8; 32]> {
    vw_core::config::Bytes32::from_base64(s)
        .map(|b| b.0)
        .ok_or_else(|| {
            vw_core::VwError::Config("--authorize expects a base64 WireGuard key".into())
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cli_contract() {
        let c = Cli::try_parse_from([
            "voidwire-node",
            "run",
            "--state",
            "/run/voidwire",
            "--ram-only",
            "--name",
            "n1",
            "--listen-udp",
            "0.0.0.0:51820",
            "--listen-quic",
            "0.0.0.0:443",
            "--listen-tls",
            "0.0.0.0:443",
            "--sni",
            "cdn.example.net",
            "--authorize",
            "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=",
            "--authorize",
            "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=",
            "--egress-iface",
            "eth0",
        ])
        .unwrap();
        let Command::Run(r) = c.command else {
            panic!("expected run")
        };
        assert!(r.ram_only);
        assert_eq!(r.authorize.len(), 2);
        assert_eq!(parse_wg_key(&r.authorize[0]).unwrap(), [1; 32]);
        assert!(parse_wg_key("nope").is_err());
        assert_eq!(r.egress_iface.as_deref(), Some("eth0"));

        let c =
            Cli::try_parse_from(["voidwire-node", "run", "--state", "/s", "--sni", "x"]).unwrap();
        let Command::Run(r) = c.command else {
            panic!("expected run")
        };
        assert_eq!(r.listen_udp, "0.0.0.0:51820");
        assert_eq!(r.name, "voidwire-node");

        assert!(Cli::try_parse_from(["voidwire-node", "uri", "--state", "/s", "--qr"]).is_ok());
        assert!(Cli::try_parse_from([
            "voidwire-node",
            "invite",
            "--state",
            "/s",
            "--bandwidth-limit",
            "50Mbps",
            "--expires",
            "30d"
        ])
        .is_ok());
        assert!(Cli::try_parse_from(["voidwire-node", "attest", "--state", "/s"]).is_ok());
        assert!(Cli::try_parse_from(["voidwire-node", "serve"]).is_err());
        assert_eq!(parse_bandwidth_arg("50Mbps").unwrap(), 50_000_000);
        assert_eq!(parse_bandwidth_arg("unlimited").unwrap(), 0);
        assert!(parse_bandwidth_arg("fast").is_err());
    }
}
