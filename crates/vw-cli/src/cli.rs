//! Command-line grammar (ARCHITECTURE.md §13, `voidwire`).

use std::ffi::OsString;
use std::path::PathBuf;

use clap::{Args, Parser, Subcommand, ValueEnum};
use vw_core::config::{Profile, TransportKind};
use vw_freecloud::Provider;

/// Default time `voidwire up` waits for `TunnelActive`.
pub const DEFAULT_UP_TIMEOUT_SECS: u64 = 180;

#[derive(Debug, Parser)]
#[command(
    name = "voidwire",
    version,
    about = "VoidWire: fail-closed, post-quantum, censorship-resistant VPN",
    long_about = "Controls the local VoidWire daemon (voidwired) over its authenticated IPC channel.\n\
                  Colors are disabled when NO_COLOR is set or output is not a terminal."
)]
pub struct Cli {
    /// Machine-readable JSON output instead of human text.
    #[arg(long, global = true)]
    pub json: bool,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Arm the lockdown and bring the tunnel up, following every state change.
    Up(UpArgs),
    /// Bring the tunnel down (and release the lockdown unless --keep-lockdown).
    Down {
        /// Keep the firewall locked after the tunnel goes down (nothing leaks).
        #[arg(long)]
        keep_lockdown: bool,
    },
    /// Remove the lockdown entirely; traffic then flows unprotected.
    Disarm {
        /// Do not ask for confirmation.
        #[arg(short, long)]
        yes: bool,
    },
    /// Show tunnel, route, crypto and firewall status.
    Status {
        /// Also run the live canary leak audit and print its proof table.
        #[arg(long)]
        audit: bool,
    },
    /// Emergency rotation: new WG + PQ keys, DNS flush, new exit; firewall stays locked.
    Panic,
    /// Run a command whose traffic is confined to the tunnel.
    Exec {
        /// Program and arguments (use `--` before them if they start with `-`).
        #[arg(
            required = true,
            num_args = 1..,
            trailing_var_arg = true,
            allow_hyphen_values = true,
            value_parser = clap::value_parser!(OsString),
            value_name = "CMD"
        )]
        cmd: Vec<OsString>,
    },
    /// Re-run the gateway/transport optimizer and show its decision.
    Optimize,
    /// Manage known gateways and exits.
    #[command(subcommand)]
    Nodes(NodesCommand),
    /// Friend-to-friend invites.
    #[command(subcommand)]
    Invite(InviteCommand),
    /// Anonymous Cloudflare WARP registration.
    #[command(subcommand)]
    Warp(WarpCommand),
    /// Read or replace daemon settings.
    #[command(subcommand)]
    Settings(SettingsCommand),
    /// Free-tier node deployment bundles.
    #[command(subcommand)]
    Cloud(CloudCommand),
    /// Open the terminal dashboard.
    Tui,
    /// Print a shell completion script.
    Completions {
        #[arg(value_enum)]
        shell: clap_complete::Shell,
    },
}

#[derive(Debug, Args)]
pub struct UpArgs {
    /// Connection profile (defaults to the daemon's `default_profile` setting).
    #[arg(long, value_enum)]
    pub profile: Option<ProfileArg>,
    /// Only consider gateways in this country (ISO 3166-1 alpha-2).
    #[arg(long, value_name = "CC", value_parser = parse_country)]
    pub country: Option<String>,
    /// Force a transport instead of letting the optimizer choose.
    #[arg(long, value_enum)]
    pub transport: Option<TransportArg>,
    /// Seconds to wait for the tunnel to become active.
    #[arg(long, value_name = "SECS", default_value_t = DEFAULT_UP_TIMEOUT_SECS,
          value_parser = clap::value_parser!(u64).range(1..=3600))]
    pub timeout: u64,
}

#[derive(Debug, Subcommand)]
pub enum NodesCommand {
    /// List imported nodes.
    List,
    /// Import a `voidwire://node/...` (or `voidwire://f2f/...`) URI.
    Import { uri: String },
    /// Remove a node by name.
    Remove { name: String },
}

#[derive(Debug, Subcommand)]
pub enum InviteCommand {
    /// Redeem a `voidwire://f2f/...` invite from a friend.
    Redeem { uri: String },
}

#[derive(Debug, Subcommand)]
pub enum WarpCommand {
    /// Register an anonymous WARP device (requires accepting Cloudflare's terms).
    Register {
        /// Accept the Cloudflare WARP terms of service without prompting.
        #[arg(long)]
        accept_tos: bool,
    },
}

#[derive(Debug, Subcommand)]
pub enum SettingsCommand {
    /// Print the current settings as JSON.
    Get,
    /// Replace the settings with a full JSON document (`@FILE` reads a file, `@-` stdin).
    Set {
        #[arg(value_name = "JSON|@FILE")]
        value: String,
    },
}

#[derive(Debug, Subcommand)]
pub enum CloudCommand {
    /// Write a RAM-only node deployment bundle for a provider.
    Generate(CloudArgs),
}

#[derive(Debug, Args)]
pub struct CloudArgs {
    #[arg(long, value_enum)]
    pub provider: ProviderArg,
    /// Output directory (default: ./voidwire-node-<provider>).
    #[arg(long, value_name = "DIR")]
    pub out: Option<PathBuf>,
    /// Release version of voidwire-node to install (default: this CLI's version).
    #[arg(long = "version", value_name = "V")]
    pub release_version: Option<String>,
    /// Node name.
    #[arg(long, value_name = "N")]
    pub name: Option<String>,
    /// Provider region.
    #[arg(long, value_name = "R")]
    pub region: Option<String>,
    /// SSH public key file installed for the default user.
    #[arg(long, value_name = "PATH")]
    pub ssh_key: Option<PathBuf>,
    /// This device's WireGuard public key (base64), pre-authorised as node owner.
    #[arg(long, value_name = "BASE64")]
    pub owner_key: Option<String>,
    /// Pre-authorise this device as the node owner (requires --owner-key today).
    #[arg(long)]
    pub authorize_me: bool,
    /// Overwrite files that already exist in the output directory.
    #[arg(long)]
    pub force: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum ProfileArg {
    Auto,
    Warp,
    Multihop,
    Stealth,
    F2f,
    MaxAnonymity,
}

impl From<ProfileArg> for Profile {
    fn from(p: ProfileArg) -> Self {
        match p {
            ProfileArg::Auto => Profile::Auto,
            ProfileArg::Warp => Profile::Warp,
            ProfileArg::Multihop => Profile::Multihop,
            ProfileArg::Stealth => Profile::Stealth,
            ProfileArg::F2f => Profile::F2f,
            ProfileArg::MaxAnonymity => Profile::MaxAnonymity,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum TransportArg {
    NativeUdp,
    AmneziaWg,
    MasqueQuic,
    TlsWebsocket,
}

impl From<TransportArg> for TransportKind {
    fn from(t: TransportArg) -> Self {
        match t {
            TransportArg::NativeUdp => TransportKind::NativeUdp,
            TransportArg::AmneziaWg => TransportKind::AmneziaWg,
            TransportArg::MasqueQuic => TransportKind::MasqueQuic,
            TransportArg::TlsWebsocket => TransportKind::TlsWebsocket,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum ProviderArg {
    OracleFree,
    GcpFree,
    Fly,
    Docker,
    Ssh,
}

impl ProviderArg {
    pub const fn slug(self) -> &'static str {
        match self {
            ProviderArg::OracleFree => "oracle-free",
            ProviderArg::GcpFree => "gcp-free",
            ProviderArg::Fly => "fly",
            ProviderArg::Docker => "docker",
            ProviderArg::Ssh => "ssh",
        }
    }
}

impl From<ProviderArg> for Provider {
    fn from(p: ProviderArg) -> Self {
        match p {
            ProviderArg::OracleFree => Provider::OracleFree,
            ProviderArg::GcpFree => Provider::GcpFree,
            ProviderArg::Fly => Provider::Fly,
            ProviderArg::Docker => Provider::Docker,
            ProviderArg::Ssh => Provider::Ssh,
        }
    }
}

/// Two ASCII letters, normalised to upper case.
pub fn parse_country(s: &str) -> Result<String, String> {
    let s = s.trim();
    if s.len() == 2 && s.chars().all(|c| c.is_ascii_alphabetic()) {
        Ok(s.to_ascii_uppercase())
    } else {
        Err("expected a two-letter ISO 3166-1 country code such as DE or US".into())
    }
}
