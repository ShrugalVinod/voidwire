//! Local control socket `<state>/control.sock` (0600, Unix only).
//!
//! One newline-terminated JSON request per connection, one JSON response.
//! `voidwire-node invite` and `voidwire-node attest` use it so invite secrets
//! and the identity key stay inside the running node.

use serde::{Deserialize, Serialize};
use vw_crypto::attest::SignedAttestation;

/// Requests to the running node.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum ControlRequest {
    /// Create a single-use invite.
    Invite {
        /// Requested bandwidth (bits/s, 0 = unlimited).
        bandwidth_bps: u64,
        /// Lifetime in seconds.
        expires_in_secs: u64,
    },
    /// Fresh attestation for a hex nonce (32 bytes).
    Attest { nonce: String },
}

/// Responses from the node.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum ControlResponse {
    Invite {
        uri: String,
        tier: u8,
        bandwidth_bps: u64,
        expires_unix: u64,
    },
    Attest {
        attestation: SignedAttestation,
    },
    Error {
        message: String,
    },
}

/// Maximum request size accepted by the server.
pub const MAX_REQUEST: usize = 4096;

#[cfg(unix)]
pub use unix::*;

#[cfg(unix)]
mod unix {
    use super::*;
    use std::path::{Path, PathBuf};
    use std::sync::{Arc, Mutex};

    use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
    use tokio::net::{UnixListener, UnixStream};
    use vw_core::{Result, VwError};

    use crate::listeners::Remote;
    use crate::node::{system_unix_now, NodeCore};

    /// Handle one request against the core.
    pub fn handle(
        core: &Mutex<NodeCore<Remote>>,
        node_uri: &str,
        req: ControlRequest,
    ) -> ControlResponse {
        let Ok(mut c) = core.lock() else {
            return ControlResponse::Error {
                message: "node state unavailable".into(),
            };
        };
        match req {
            ControlRequest::Invite {
                bandwidth_bps,
                expires_in_secs,
            } => {
                let expires_unix = system_unix_now().saturating_add(expires_in_secs);
                match c.create_invite(bandwidth_bps, expires_unix, node_uri) {
                    Ok((uri, t)) => ControlResponse::Invite {
                        uri,
                        tier: t.id,
                        bandwidth_bps: t.bandwidth_bps,
                        expires_unix,
                    },
                    Err(e) => ControlResponse::Error {
                        message: e.to_string(),
                    },
                }
            }
            ControlRequest::Attest { nonce } => {
                let parsed = hex::decode(nonce.trim())
                    .ok()
                    .and_then(|v| <[u8; 32]>::try_from(v).ok());
                match parsed {
                    Some(n) => match c.attestation(n) {
                        Ok(attestation) => ControlResponse::Attest { attestation },
                        Err(e) => ControlResponse::Error {
                            message: e.to_string(),
                        },
                    },
                    None => ControlResponse::Error {
                        message: "nonce must be 32 bytes of hex".into(),
                    },
                }
            }
        }
    }

    /// Bind the control socket with mode 0600 (removing a stale one).
    pub fn bind(path: &Path) -> Result<UnixListener> {
        use std::os::unix::fs::PermissionsExt;
        if path.exists() {
            if std::os::unix::net::UnixStream::connect(path).is_ok() {
                return Err(VwError::Config(
                    "another voidwire-node is already running on this state directory".into(),
                ));
            }
            std::fs::remove_file(path)?;
        }
        let l = UnixListener::bind(path)?;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
        Ok(l)
    }

    /// Accept loop; runs until the task is aborted.
    pub async fn serve(
        listener: UnixListener,
        core: Arc<Mutex<NodeCore<Remote>>>,
        node_uri: Arc<str>,
    ) {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                continue;
            };
            let core = core.clone();
            let uri = node_uri.clone();
            tokio::spawn(async move {
                let _ = serve_one(stream, &core, &uri).await;
            });
        }
    }

    async fn serve_one(
        stream: UnixStream,
        core: &Mutex<NodeCore<Remote>>,
        uri: &str,
    ) -> Result<()> {
        let (r, mut w) = stream.into_split();
        let mut line = String::new();
        BufReader::new(r.take(MAX_REQUEST as u64))
            .read_line(&mut line)
            .await?;
        let resp = match serde_json::from_str::<ControlRequest>(&line) {
            Ok(req) => handle(core, uri, req),
            Err(_) => ControlResponse::Error {
                message: "malformed request".into(),
            },
        };
        let mut out = serde_json::to_vec(&resp)?;
        out.push(b'\n');
        w.write_all(&out).await?;
        w.shutdown().await?;
        Ok(())
    }

    /// Client side: send one request to the node at `state_dir`.
    pub async fn request(state_dir: &Path, req: &ControlRequest) -> Result<ControlResponse> {
        let path: PathBuf = state_dir.join(crate::state::CONTROL_SOCK);
        let stream = UnixStream::connect(&path).await.map_err(|e| {
            VwError::Config(format!(
                "cannot reach the running node at {}: {e}",
                path.display()
            ))
        })?;
        let (r, mut w) = stream.into_split();
        let mut body = serde_json::to_vec(req)?;
        body.push(b'\n');
        w.write_all(&body).await?;
        w.shutdown().await?;
        let mut line = String::new();
        BufReader::new(r).read_line(&mut line).await?;
        Ok(serde_json::from_str(&line)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wire_format() {
        let r = ControlRequest::Invite {
            bandwidth_bps: 50_000_000,
            expires_in_secs: 3600,
        };
        let j = serde_json::to_string(&r).unwrap();
        assert_eq!(
            j,
            r#"{"op":"invite","bandwidth_bps":50000000,"expires_in_secs":3600}"#
        );
        assert_eq!(serde_json::from_str::<ControlRequest>(&j).unwrap(), r);
        let e = serde_json::to_string(&ControlResponse::Error {
            message: "x".into(),
        })
        .unwrap();
        assert_eq!(e, r#"{"status":"error","message":"x"}"#);
    }
}
