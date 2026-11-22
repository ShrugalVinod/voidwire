//! `voidwire-node run`: state, descriptor, listeners, TUN, NAT, control socket.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use vw_core::{Result, VwError};

use crate::cli::RunArgs;

/// Resolve a `HOST:PORT` listen argument (names like `fly-global-services`
/// are allowed).
pub async fn resolve_listen(s: &str) -> Result<SocketAddr> {
    if let Ok(a) = s.parse() {
        return Ok(a);
    }
    tokio::net::lookup_host(s)
        .await?
        .next()
        .ok_or_else(|| VwError::Config(format!("cannot resolve listen address {s}")))
}

/// The nearest existing ancestor of `p` (the directory itself if it exists).
pub fn existing_ancestor(p: &Path) -> PathBuf {
    let mut cur = p.to_path_buf();
    loop {
        if cur.exists() {
            return cur;
        }
        match cur.parent() {
            Some(parent) if parent != cur => cur = parent.to_path_buf(),
            _ => return PathBuf::from("/"),
        }
    }
}

/// `--ram-only` preconditions, checked before anything is written.
pub fn check_ram_only(state: &Path, ram_backed: bool, swap_off: bool) -> Result<()> {
    if !ram_backed {
        return Err(VwError::Config(format!(
            "--ram-only: {} is not on tmpfs/ramfs (mount one, e.g. `mount -t tmpfs -o mode=0700,size=64m tmpfs {}`)",
            state.display(),
            state.display()
        )));
    }
    if !swap_off {
        return Err(VwError::Config(
            "--ram-only: swap is enabled (run `swapoff -a`)".into(),
        ));
    }
    Ok(())
}

/// Validate arguments that do not depend on the OS.
pub fn validate_args(args: &RunArgs) -> Result<Vec<[u8; 32]>> {
    if args.decoy_dir.is_some() {
        return Err(VwError::Config(
            "--decoy-dir is not supported by this build: the TLS-WS listener serves its built-in decoy site".into(),
        ));
    }
    if args.name.is_empty() || args.name.len() > 64 {
        return Err(VwError::Config("--name must be 1..=64 characters".into()));
    }
    if args.sni.is_empty() {
        return Err(VwError::Config("--sni must not be empty".into()));
    }
    args.authorize
        .iter()
        .map(|k| crate::cli::parse_wg_key(k))
        .collect()
}

/// Run the node until SIGTERM/SIGINT.
pub async fn run(args: RunArgs) -> Result<()> {
    let owners = validate_args(&args)?;
    #[cfg(target_os = "linux")]
    {
        linux::run(args, owners).await
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = owners;
        Err(VwError::Unsupported(
            "voidwire-node run requires Linux (TUN, nftables, /proc)",
        ))
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use std::sync::{Arc, Mutex};

    use tokio::sync::watch;
    use vw_core::consts::{NODE_GATEWAY_V4, NODE_GATEWAY_V6, SAFE_TUNNEL_MTU};
    use vw_core::transport::TunDevice;
    use vw_stealth::{MasqueListener, ServerTransport, TlsWsListener, UdpListener};
    use vw_wg::{OsTun, OsTunConfig};

    use crate::admission::SpentLedger;
    use crate::attestation;
    use crate::forward::{detect_egress, Forwarding, NatPlan};
    use crate::listeners::{serve, Listeners};
    use crate::node::{system_unix_now, CoreConfig, NodeCore};
    use crate::state::{
        build_descriptor, discover_public, is_private_v4, write_node_uri, Advertise, NodeState,
        CONTROL_SOCK, SPENT_LEDGER,
    };

    pub async fn run(args: RunArgs, owners: Vec<[u8; 32]>) -> Result<()> {
        if args.ram_only {
            let probe = existing_ancestor(&args.state);
            check_ram_only(
                &args.state,
                attestation::is_ram_backed(&probe),
                attestation::swap_disabled(),
            )?;
        }
        let udp_addr = resolve_listen(&args.listen_udp).await?;
        let quic_addr = resolve_listen(&args.listen_quic).await?;
        let tls_addr = resolve_listen(&args.listen_tls).await?;

        let st = NodeState::load_or_create(&args.state, &args.sni, system_unix_now())?;
        if args.ram_only && !attestation::is_ram_backed(&args.state) {
            return Err(VwError::Config(
                "--ram-only: state directory is not RAM-backed".into(),
            ));
        }

        let (v4, global_v6) = discover_public();
        let host = match (&args.public_host, v4) {
            (Some(h), _) => h.clone(),
            (None, Some(a)) => {
                if is_private_v4(a) {
                    eprintln!(
                        "voidwire-node: the egress address is not public; pass --public-host (or VOIDWIRE_PUBLIC_HOST) if clients cannot reach it"
                    );
                }
                a.to_string()
            }
            (None, None) => {
                return Err(VwError::Config(
                    "cannot determine the public address; pass --public-host".into(),
                ))
            }
        };
        let egress = match &args.egress_iface {
            Some(i) => i.clone(),
            None => detect_egress(false)?,
        };
        let ipv6_exit = global_v6 && detect_egress(true).is_ok_and(|i| i == egress);

        let adv = Advertise {
            name: args.name.clone(),
            host,
            udp_port: udp_addr.port(),
            quic_port: quic_addr.port(),
            tls_port: tls_addr.port(),
            ipv6_exit,
        };
        let descriptor = build_descriptor(&st, &adv)?;
        let node_uri: Arc<str> = write_node_uri(&st.dir, &descriptor)?.into();

        let binary = attestation::self_binary_hash()?;
        let dir = st.dir.clone();
        let facts = Box::new(move || attestation::collect(&binary, &dir));
        let ledger = SpentLedger::open(&st.dir.join(SPENT_LEDGER))?;

        let udp = UdpListener::bind(udp_addr).await?;
        let masque: Arc<dyn ServerTransport> = Arc::new(MasqueListener::bind(
            quic_addr,
            &st.cert_der,
            st.key_der.expose(),
            Some(&st.masque_token),
        )?);
        let tlsws: Arc<dyn ServerTransport> = Arc::new(
            TlsWsListener::bind(tls_addr, &st.cert_der, st.key_der.expose(), &st.ws_token).await?,
        );
        let listeners = Arc::new(Listeners::new(
            Some((udp, st.amnezia)),
            vec![masque, tlsws],
        )?);

        let tun = OsTun::create(&OsTunConfig {
            mtu: SAFE_TUNNEL_MTU,
            ipv4: Some((NODE_GATEWAY_V4, vw_core::consts::CLIENT_POOL_V4.1)),
            ipv6: ipv6_exit.then_some((NODE_GATEWAY_V6, vw_core::consts::CLIENT_POOL_V6.1)),
        })?;
        let mut fwd = Forwarding::install(&NatPlan {
            tun: tun.name(),
            egress,
            ipv6: ipv6_exit,
        })?;
        let tun: Arc<dyn TunDevice> = Arc::new(tun);

        let NodeState {
            identity,
            wg_key,
            issuers,
            dir,
            ..
        } = st;
        let core = Arc::new(Mutex::new(NodeCore::new(
            CoreConfig {
                wg_key,
                identity,
                owners,
                issuers,
                ledger,
                max_peers: args.max_peers,
            },
            facts,
        )));

        let sock_path = dir.join(CONTROL_SOCK);
        let control = crate::control::bind(&sock_path)?;
        let control_task = tokio::spawn(crate::control::serve(control, core.clone(), node_uri));

        let (tx, rx) = watch::channel(false);
        let signals = tokio::spawn(async move {
            use tokio::signal::unix::{signal, SignalKind};
            let (Ok(mut term), Ok(mut int)) = (
                signal(SignalKind::terminate()),
                signal(SignalKind::interrupt()),
            ) else {
                return;
            };
            tokio::select! {
                _ = term.recv() => {},
                _ = int.recv() => {},
            }
            let _ = tx.send(true);
        });

        eprintln!(
            "voidwire-node: serving; node URI in {}",
            dir.join(crate::state::NODE_URI_FILE).display()
        );
        let result = serve(core, listeners, tun, rx).await;

        signals.abort();
        control_task.abort();
        let _ = std::fs::remove_file(&sock_path);
        let removed = fwd.remove();
        result.and(removed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    fn args(extra: &[&str]) -> RunArgs {
        let mut v = vec![
            "voidwire-node",
            "run",
            "--state",
            "/tmp/x",
            "--sni",
            "a.example",
        ];
        v.extend_from_slice(extra);
        match crate::cli::Cli::try_parse_from(v).unwrap().command {
            crate::cli::Command::Run(r) => r,
            _ => unreachable!("run subcommand"),
        }
    }

    #[test]
    fn argument_validation() {
        assert!(validate_args(&args(&[])).unwrap().is_empty());
        assert!(matches!(
            validate_args(&args(&["--decoy-dir", "/srv/site"])),
            Err(VwError::Config(_))
        ));
        assert!(validate_args(&args(&["--authorize", "bad"])).is_err());
        let long = "n".repeat(65);
        assert!(validate_args(&args(&["--name", &long])).is_err());
    }

    #[test]
    fn ram_only_checks() {
        let p = Path::new("/run/voidwire");
        assert!(check_ram_only(p, true, true).is_ok());
        let e = check_ram_only(p, false, true).unwrap_err().to_string();
        assert!(e.contains("tmpfs"));
        let e = check_ram_only(p, true, false).unwrap_err().to_string();
        assert!(e.contains("swap"));
        let anc = existing_ancestor(&std::env::temp_dir().join("vw-no/such/dir"));
        assert!(anc.exists());
    }

    #[tokio::test]
    async fn listen_resolution() {
        assert_eq!(
            resolve_listen("0.0.0.0:51820").await.unwrap(),
            "0.0.0.0:51820".parse::<SocketAddr>().unwrap()
        );
        assert_eq!(resolve_listen("localhost:443").await.unwrap().port(), 443);
    }

    #[cfg(not(target_os = "linux"))]
    #[tokio::test]
    async fn run_is_unsupported_off_linux() {
        assert!(matches!(run(args(&[])).await, Err(VwError::Unsupported(_))));
    }
}
