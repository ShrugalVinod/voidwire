//! VWIPC: framed, authenticated local control protocol (ARCHITECTURE.md §5).

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::config::{NodeKind, NodeRole, Profile, Settings, ShieldCategory, TransportKind};
use crate::consts::{IPC_MAX_FRAME, IPC_VERSION};
use crate::error::{Result, VwError};
use crate::probe::OptimizerDecision;
use crate::secret::Key32;
use crate::state::DomeState;
use crate::telemetry::TelemetrySnapshot;

// ───────────────────────────── handshake ─────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", content = "data")]
pub enum Handshake {
    ClientHello { version: u32 },
    Challenge { nonce: String },
    Auth { mac: String },
    AuthOk { daemon_version: String },
    AuthFail,
}

const AUTH_CONTEXT: &[u8] = b"vwipc-auth-v1";

pub fn auth_mac(token: &Key32, nonce: &[u8; 32]) -> [u8; 32] {
    let mut h = blake3::Hasher::new_keyed(token.expose());
    h.update(AUTH_CONTEXT);
    h.update(nonce);
    *h.finalize().as_bytes()
}

pub fn verify_auth_mac(token: &Key32, nonce: &[u8; 32], mac_hex: &str) -> bool {
    let Ok(mac) = hex::decode(mac_hex) else {
        return false;
    };
    let expected = auth_mac(token, nonce);
    mac.len() == 32 && bool::from(expected.ct_eq(&mac))
}

// ───────────────────────────── requests ──────────────────────────────

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", content = "data")]
pub enum Request {
    Status,
    Up {
        profile: Profile,
        #[serde(default)]
        country: Option<String>,
        #[serde(default)]
        transport: Option<TransportKind>,
    },
    Down {
        keep_lockdown: bool,
    },
    /// Remove the lockdown entirely (only way out of FailsafeLockdown).
    Disarm,
    /// Rotate WG + PQ keys, flush DNS, switch exit, firewall stays locked.
    Panic,
    /// Run the live canary leak audit.
    Audit,
    /// Re-run the gateway/transport optimizer.
    Optimize,
    GetSettings,
    SetSettings(Box<Settings>),
    ListNodes,
    ImportNode {
        uri: String,
    },
    RemoveNode {
        name: String,
    },
    RedeemInvite {
        uri: String,
    },
    RegisterWarp,
    Telemetry,
    /// Stream `Response::Event` frames until the connection closes.
    Subscribe,
    /// Prepare an isolated exec environment for `voidwire exec`.
    ExecPrepare,
}

// ───────────────────────────── responses ─────────────────────────────

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HopInfo {
    pub name: String,
    pub kind: NodeKind,
    pub role: NodeRole,
    pub country: Option<String>,
    pub transport: TransportKind,
    pub post_quantum: bool,
    pub rtt_ms: Option<f64>,
    /// Approximate map coordinates (lat, lon) for the GUI/TUI route map.
    pub coords: Option<(f64, f64)>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FirewallMatrix {
    pub ipv4_locked: bool,
    pub ipv6_locked: bool,
    pub dns_vault: bool,
    pub stun_filter: bool,
    pub tunnelvision_guard: bool,
    pub boot_lock: bool,
    pub backend: String,
}

impl Default for FirewallMatrix {
    fn default() -> Self {
        Self {
            ipv4_locked: false,
            ipv6_locked: false,
            dns_vault: false,
            stun_filter: false,
            tunnelvision_guard: false,
            boot_lock: false,
            backend: "none".into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StatusReport {
    pub state: DomeState,
    pub profile: Option<Profile>,
    pub hops: Vec<HopInfo>,
    pub transport: Option<TransportKind>,
    pub crypto_suite: String,
    pub uptime_secs: u64,
    pub mtu: Option<u16>,
    pub daita: bool,
    pub firewall: FirewallMatrix,
    pub last_rotation_secs_ago: Option<u64>,
    pub telemetry: TelemetrySnapshot,
    pub decision: Option<OptimizerDecision>,
    pub platform: String,
    pub daemon_version: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditCheck {
    pub name: String,
    pub passed: bool,
    pub detail: String,
    /// Evidence: BLAKE3 digest of probe transcript / counter deltas.
    pub proof: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditReport {
    pub passed: bool,
    pub checks: Vec<AuditCheck>,
    pub unix_time: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NodeSummary {
    pub name: String,
    pub kind: NodeKind,
    pub role: NodeRole,
    pub country: Option<String>,
    pub transports: Vec<TransportKind>,
    pub post_quantum: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecTicket {
    /// Linux network namespace name to enter, if namespace isolation is used.
    pub netns: Option<String>,
    /// Human explanation of the isolation guarantee in effect.
    pub isolation: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", content = "data")]
pub enum DaemonEvent {
    StateChanged {
        from: DomeState,
        to: DomeState,
    },
    Telemetry(TelemetrySnapshot),
    Audit(AuditReport),
    Decision(OptimizerDecision),
    /// Sanitized log line (never contains IPs, names or keys).
    Log {
        level: String,
        message: String,
    },
    /// Volatile live DNS inspector entry (only when enabled, never persisted).
    DnsInspect {
        name: String,
        category: Option<ShieldCategory>,
        blocked: bool,
    },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", content = "data")]
pub enum Response {
    Ok,
    Error { message: String },
    Status(Box<StatusReport>),
    Audit(AuditReport),
    Optimized(Box<OptimizerDecision>),
    Settings(Box<Settings>),
    Nodes(Vec<NodeSummary>),
    Telemetry(TelemetrySnapshot),
    Exec(ExecTicket),
    Event(Box<DaemonEvent>),
}

// ───────────────────────────── framing ───────────────────────────────

pub async fn write_frame<W, T>(w: &mut W, msg: &T) -> Result<()>
where
    W: AsyncWrite + Unpin + ?Sized,
    T: Serialize,
{
    let body = serde_json::to_vec(msg)?;
    if body.len() > IPC_MAX_FRAME {
        return Err(VwError::Ipc("frame too large".into()));
    }
    w.write_all(&(body.len() as u32).to_be_bytes()).await?;
    w.write_all(&body).await?;
    w.flush().await?;
    Ok(())
}

pub async fn read_frame<R, T>(r: &mut R) -> Result<T>
where
    R: AsyncRead + Unpin + ?Sized,
    T: DeserializeOwned,
{
    let mut len = [0u8; 4];
    r.read_exact(&mut len).await?;
    let len = u32::from_be_bytes(len) as usize;
    if len > IPC_MAX_FRAME {
        return Err(VwError::Ipc("frame too large".into()));
    }
    let mut body = vec![0u8; len];
    r.read_exact(&mut body).await?;
    Ok(serde_json::from_slice(&body)?)
}

// ───────────────────────────── token ─────────────────────────────────

pub fn parse_token(text: &str) -> Result<Key32> {
    let raw = hex::decode(text.trim()).map_err(|_| VwError::Auth)?;
    Key32::from_slice(&raw).ok_or(VwError::Auth)
}

pub fn load_token(path: &std::path::Path) -> Result<Key32> {
    let text = std::fs::read_to_string(path).map_err(|e| {
        VwError::Permission(format!(
            "cannot read IPC token {} ({e}); is voidwired installed and are you an administrator?",
            path.display()
        ))
    })?;
    parse_token(&text)
}

// ───────────────────────────── client ────────────────────────────────

pub trait IpcStream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> IpcStream for T {}

/// Authenticated client connection to `voidwired`.
pub struct IpcClient {
    stream: Box<dyn IpcStream>,
    pub daemon_version: String,
}

impl IpcClient {
    /// Connect to the platform default endpoint with the on-disk token.
    pub async fn connect_default() -> Result<Self> {
        let token = load_token(&crate::paths::token_file())?;
        Self::connect(&crate::paths::ipc_endpoint(), &token).await
    }

    pub async fn connect(endpoint: &str, token: &Key32) -> Result<Self> {
        let stream = open_stream(endpoint).await?;
        Self::handshake(stream, token).await
    }

    /// Run the client side of the auth handshake over any stream.
    pub async fn handshake(mut stream: Box<dyn IpcStream>, token: &Key32) -> Result<Self> {
        write_frame(
            &mut stream,
            &Handshake::ClientHello {
                version: IPC_VERSION,
            },
        )
        .await?;
        let nonce = match read_frame::<_, Handshake>(&mut stream).await? {
            Handshake::Challenge { nonce } => {
                let raw = hex::decode(nonce).map_err(|_| VwError::Ipc("bad nonce".into()))?;
                <[u8; 32]>::try_from(raw.as_slice())
                    .map_err(|_| VwError::Ipc("bad nonce length".into()))?
            }
            _ => return Err(VwError::Ipc("expected challenge".into())),
        };
        let mac = hex::encode(auth_mac(token, &nonce));
        write_frame(&mut stream, &Handshake::Auth { mac }).await?;
        match read_frame::<_, Handshake>(&mut stream).await? {
            Handshake::AuthOk { daemon_version } => Ok(Self {
                stream,
                daemon_version,
            }),
            _ => Err(VwError::Auth),
        }
    }

    pub async fn request(&mut self, req: &Request) -> Result<Response> {
        write_frame(&mut self.stream, req).await?;
        let resp: Response = read_frame(&mut self.stream).await?;
        if let Response::Error { message } = &resp {
            return Err(VwError::Ipc(message.clone()));
        }
        Ok(resp)
    }

    /// Switch to event-stream mode.
    pub async fn subscribe(mut self) -> Result<EventStream> {
        write_frame(&mut self.stream, &Request::Subscribe).await?;
        Ok(EventStream {
            stream: self.stream,
        })
    }
}

pub struct EventStream {
    stream: Box<dyn IpcStream>,
}

impl EventStream {
    pub async fn next(&mut self) -> Result<DaemonEvent> {
        loop {
            match read_frame::<_, Response>(&mut self.stream).await? {
                Response::Event(e) => return Ok(*e),
                Response::Ok => continue,
                Response::Error { message } => return Err(VwError::Ipc(message)),
                _ => continue,
            }
        }
    }
}

#[cfg(unix)]
async fn open_stream(endpoint: &str) -> Result<Box<dyn IpcStream>> {
    let s = tokio::net::UnixStream::connect(endpoint)
        .await
        .map_err(|e| {
            VwError::Ipc(format!(
                "cannot reach voidwired at {endpoint} ({e}); is the daemon running?"
            ))
        })?;
    Ok(Box::new(s))
}

#[cfg(windows)]
async fn open_stream(endpoint: &str) -> Result<Box<dyn IpcStream>> {
    use tokio::net::windows::named_pipe::ClientOptions;
    const ERROR_PIPE_BUSY: i32 = 231;
    for _ in 0..50 {
        match ClientOptions::new().open(endpoint) {
            Ok(c) => return Ok(Box::new(c)),
            Err(e) if e.raw_os_error() == Some(ERROR_PIPE_BUSY) => {
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
            Err(e) => {
                return Err(VwError::Ipc(format!(
                    "cannot reach voidwired at {endpoint} ({e}); is the service running?"
                )))
            }
        }
    }
    Err(VwError::Timeout)
}

/// Server-side handshake helper used by `voidwired` and tests.
pub async fn server_handshake<S>(stream: &mut S, token: &Key32, daemon_version: &str) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + ?Sized,
{
    match read_frame::<_, Handshake>(stream).await? {
        Handshake::ClientHello { version } if version == IPC_VERSION => {}
        _ => return Err(VwError::Ipc("unsupported client version".into())),
    }
    let mut nonce = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut nonce);
    write_frame(
        stream,
        &Handshake::Challenge {
            nonce: hex::encode(nonce),
        },
    )
    .await?;
    let ok = match read_frame::<_, Handshake>(stream).await? {
        Handshake::Auth { mac } => verify_auth_mac(token, &nonce, &mac),
        _ => false,
    };
    if !ok {
        write_frame(stream, &Handshake::AuthFail).await?;
        return Err(VwError::Auth);
    }
    write_frame(
        stream,
        &Handshake::AuthOk {
            daemon_version: daemon_version.to_string(),
        },
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn handshake_and_request() {
        let token = Key32::random();
        let (a, mut b) = tokio::io::duplex(4096);
        let t2 = token.clone();
        let server = tokio::spawn(async move {
            server_handshake(&mut b, &t2, "test").await.unwrap();
            let req: Request = read_frame(&mut b).await.unwrap();
            assert_eq!(req, Request::Status);
            write_frame(&mut b, &Response::Ok).await.unwrap();
        });
        let mut c = IpcClient::handshake(Box::new(a), &token).await.unwrap();
        assert_eq!(c.daemon_version, "test");
        assert_eq!(c.request(&Request::Status).await.unwrap(), Response::Ok);
        server.await.unwrap();
    }

    #[tokio::test]
    async fn wrong_token_rejected() {
        let (a, mut b) = tokio::io::duplex(4096);
        let server = tokio::spawn(async move {
            let good = Key32::random();
            server_handshake(&mut b, &good, "test").await
        });
        let bad = Key32::random();
        assert!(IpcClient::handshake(Box::new(a), &bad).await.is_err());
        assert!(matches!(server.await.unwrap(), Err(VwError::Auth)));
    }

    #[tokio::test]
    async fn oversized_frame_rejected() {
        let (mut a, mut b) = tokio::io::duplex(64);
        tokio::spawn(async move {
            let _ = a.write_all(&(u32::MAX).to_be_bytes()).await;
        });
        assert!(read_frame::<_, Request>(&mut b).await.is_err());
    }

    #[test]
    fn json_shape_is_stable() {
        let j = serde_json::to_string(&Request::Down {
            keep_lockdown: true,
        })
        .unwrap();
        assert_eq!(j, r#"{"type":"Down","data":{"keep_lockdown":true}}"#);
        assert_eq!(
            serde_json::to_string(&Request::Status).unwrap(),
            r#"{"type":"Status"}"#
        );
    }
}
