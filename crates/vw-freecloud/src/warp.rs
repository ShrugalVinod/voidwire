//! Anonymous Cloudflare WARP device registration.
//!
//! WARP is free with no data cap, but it is classical (non post-quantum)
//! WireGuard and Cloudflare sees your real IP: VoidWire uses it as a fast entry
//! hop or as a single-hop "Instant Free" mode, and says so in every UI.
//! Registering a device accepts Cloudflare's terms of service
//! (<https://www.cloudflare.com/application/terms/>), so callers must pass
//! `accept_tos = true` only after the user agreed.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use hyper::Method;
use serde_json::{json, Value};
use vw_core::config::{Bytes32, WarpAccount};
use vw_core::consts::{WARP_API_BASE, WARP_ENDPOINT_HOST, WARP_ENDPOINT_PORT};
use vw_core::secret::{Key32, SecretVec};
use vw_core::{Result, VwError};
use x25519_dalek::{PublicKey, StaticSecret};

use crate::http::{HttpsClient, HttpsUrl};

/// Client version header matching the API build used in `WARP_API_BASE`.
pub const WARP_CLIENT_VERSION: &str = "a-6.30-2158";
pub const WARP_USER_AGENT: &str = "okhttp/3.12.1";
pub const WARP_TOS_URL: &str = "https://www.cloudflare.com/application/terms/";

/// WARP anycast prefixes and UDP ports accepted by the WARP edge.
/// The optimizer probes a sample of these and keeps the fastest.
pub const WARP_ANYCAST_V4: [Ipv4Addr; 6] = [
    Ipv4Addr::new(162, 159, 192, 1),
    Ipv4Addr::new(162, 159, 193, 1),
    Ipv4Addr::new(162, 159, 195, 1),
    Ipv4Addr::new(188, 114, 96, 1),
    Ipv4Addr::new(188, 114, 97, 1),
    Ipv4Addr::new(188, 114, 98, 1),
];
/// Anycast addresses of `api.cloudflareclient.com`, used only when no DNS
/// answer is available.
pub const WARP_API_FALLBACK_V4: [Ipv4Addr; 2] = [
    Ipv4Addr::new(162, 159, 143, 174),
    Ipv4Addr::new(172, 66, 3, 170),
];
pub const WARP_PORTS: [u16; 8] = [2408, 500, 1701, 4500, 878, 894, 908, 2371];

/// Registers, enables and deletes anonymous WARP devices.
#[derive(Debug, Clone)]
pub struct WarpRegistrar {
    http: HttpsClient,
    api_base: String,
}

impl WarpRegistrar {
    pub fn new(http: HttpsClient) -> Self {
        Self {
            http: http.with_user_agent(WARP_USER_AGENT),
            api_base: WARP_API_BASE.to_string(),
        }
    }

    /// Override the API base (tests, future API versions).
    pub fn with_api_base(mut self, base: impl Into<String>) -> Self {
        self.api_base = base.into();
        self
    }

    /// HTTPS client with the API host's addresses pinned. Networks that
    /// block the WARP API through DNS (schools, offices) or a broken resolver
    /// must not stop sign-up: system DNS first, then Cloudflare DNS-over-HTTPS,
    /// then the API's well-known anycast addresses.
    async fn client(&self) -> HttpsClient {
        if self.http.pinned.is_some() {
            return self.http.clone();
        }
        let host = HttpsUrl::parse(&self.api_base)
            .map(|u| u.host)
            .unwrap_or_default();
        if let Ok(found) = tokio::net::lookup_host((host.as_str(), 443)).await {
            let addrs: Vec<SocketAddr> = found.collect();
            if !addrs.is_empty() {
                return self.http.clone().with_pinned(addrs);
            }
        }
        if let Ok(ips) = crate::http::bootstrap_resolve(&host, self.http.mark).await {
            let addrs = ips.into_iter().map(|ip| SocketAddr::new(ip, 443)).collect();
            return self.http.clone().with_pinned(addrs);
        }
        self.http.clone().with_pinned(
            WARP_API_FALLBACK_V4
                .iter()
                .map(|ip| SocketAddr::new(IpAddr::V4(*ip), 443))
                .collect(),
        )
    }

    fn headers() -> [(&'static str, &'static str); 1] {
        [("CF-Client-Version", WARP_CLIENT_VERSION)]
    }

    /// Register a fresh anonymous device with a new WireGuard keypair.
    pub async fn register(&self, accept_tos: bool) -> Result<WarpAccount> {
        if !accept_tos {
            return Err(VwError::Permission(format!(
                "Cloudflare WARP registration requires accepting {WARP_TOS_URL}"
            )));
        }
        let private = Key32::random();
        let public = PublicKey::from(&StaticSecret::from(*private.expose()));
        let body = registration_body(public.as_bytes(), unix_now());
        let url = format!("{}/reg", self.api_base);
        let resp = self
            .client()
            .await
            .request(Method::POST, &url, &Self::headers(), Some(&body))
            .await?;
        if !(200..300).contains(&resp.status) {
            return Err(VwError::Transport(format!(
                "WARP registration failed with HTTP {}",
                resp.status
            )));
        }
        let mut account = parse_registration(&resp.json()?, private)?;
        self.enable(&account).await?;
        if account.endpoint_v4.is_none() {
            account.endpoint_v4 = Some(WARP_ANYCAST_V4[0]);
        }
        Ok(account)
    }

    /// Mark the device WARP-enabled (required before the edge accepts traffic).
    pub async fn enable(&self, account: &WarpAccount) -> Result<()> {
        let url = format!("{}/reg/{}", self.api_base, account.device_id);
        let auth = bearer(&account.access_token)?;
        let mut headers = Self::headers().to_vec();
        headers.push(("Authorization", auth.as_str()));
        let resp = self
            .client()
            .await
            .request(
                Method::PATCH,
                &url,
                &headers,
                Some(&json!({ "warp_enabled": true })),
            )
            .await?;
        if !(200..300).contains(&resp.status) {
            return Err(VwError::Transport(format!(
                "WARP enable failed with HTTP {}",
                resp.status
            )));
        }
        Ok(())
    }

    /// Delete the device (used by panic identity rotation before re-registering).
    pub async fn delete(&self, account: &WarpAccount) -> Result<()> {
        let url = format!("{}/reg/{}", self.api_base, account.device_id);
        let auth = bearer(&account.access_token)?;
        let mut headers = Self::headers().to_vec();
        headers.push(("Authorization", auth.as_str()));
        let resp = self
            .client()
            .await
            .request(Method::DELETE, &url, &headers, None)
            .await?;
        if !(200..300).contains(&resp.status) && resp.status != 404 {
            return Err(VwError::Transport(format!(
                "WARP delete failed with HTTP {}",
                resp.status
            )));
        }
        Ok(())
    }
}

fn bearer(token: &SecretVec) -> Result<String> {
    let t = std::str::from_utf8(token.expose())
        .map_err(|_| VwError::Config("WARP token is not UTF-8".into()))?;
    Ok(format!("Bearer {t}"))
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// RFC 3339 UTC timestamp (`2026-11-21T12:00:00.000Z`) from unix seconds.
pub fn rfc3339(unix: u64) -> String {
    let days = (unix / 86_400) as i64;
    let secs = unix % 86_400;
    // Howard Hinnant's civil-from-days.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let mut y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    if m <= 2 {
        y += 1;
    }
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}.000Z",
        secs / 3600,
        (secs / 60) % 60,
        secs % 60
    )
}

/// Registration request body (anonymous: no install id, serial or push token).
pub fn registration_body(public_key: &[u8; 32], unix: u64) -> Value {
    json!({
        "key": B64.encode(public_key),
        "install_id": "",
        "fcm_token": "",
        "tos": rfc3339(unix),
        "model": "PC",
        "serial_number": "",
        "type": "Android",
        "locale": "en_US",
    })
}

fn get<'a>(v: &'a Value, path: &[&str]) -> Result<&'a Value> {
    let mut cur = v;
    for p in path {
        cur = cur
            .get(*p)
            .ok_or_else(|| VwError::Config(format!("WARP response missing {}", path.join("."))))?;
    }
    Ok(cur)
}

fn get_str<'a>(v: &'a Value, path: &[&str]) -> Result<&'a str> {
    get(v, path)?
        .as_str()
        .ok_or_else(|| VwError::Config(format!("WARP field {} is not a string", path.join("."))))
}

/// Parse a successful registration response into a stored account.
pub fn parse_registration(v: &Value, private_key: Key32) -> Result<WarpAccount> {
    let device_id = get_str(v, &["id"])?.to_string();
    if device_id.is_empty()
        || !device_id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-')
    {
        return Err(VwError::Config("WARP device id is malformed".into()));
    }
    let token = get_str(v, &["token"])?;
    let cfg = get(v, &["config"])?;
    let client_id_b64 = get_str(cfg, &["client_id"])?;
    let client_id_raw = B64
        .decode(client_id_b64)
        .map_err(|_| VwError::Config("WARP client_id is not base64".into()))?;
    let client_id: [u8; 3] = client_id_raw
        .get(..3)
        .and_then(|s| s.try_into().ok())
        .ok_or_else(|| VwError::Config("WARP client_id shorter than 3 bytes".into()))?;
    let peer = get(cfg, &["peers"])?
        .as_array()
        .and_then(|a| a.first())
        .ok_or_else(|| VwError::Config("WARP response has no peers".into()))?;
    let peer_public_key = Bytes32::from_base64(get_str(peer, &["public_key"])?)
        .ok_or_else(|| VwError::Config("WARP peer key invalid".into()))?;
    let endpoint = get(peer, &["endpoint"])?;
    let endpoint_v4 = endpoint
        .get("v4")
        .and_then(|e| e.as_str())
        .and_then(parse_host_ip);
    let endpoint_v6 = endpoint
        .get("v6")
        .and_then(|e| e.as_str())
        .and_then(parse_host_ip);
    let (endpoint_host, endpoint_port) = endpoint
        .get("host")
        .and_then(|h| h.as_str())
        .and_then(|h| h.rsplit_once(':'))
        .and_then(|(h, p)| Some((h.to_string(), p.parse::<u16>().ok()?)))
        .unwrap_or_else(|| (WARP_ENDPOINT_HOST.to_string(), WARP_ENDPOINT_PORT));
    let v4: Ipv4Addr = get_str(cfg, &["interface", "addresses", "v4"])?
        .parse()
        .map_err(|_| VwError::Config("WARP v4 address invalid".into()))?;
    let v6: Ipv6Addr = get_str(cfg, &["interface", "addresses", "v6"])?
        .parse()
        .map_err(|_| VwError::Config("WARP v6 address invalid".into()))?;
    Ok(WarpAccount {
        device_id,
        access_token: SecretVec::new(token.as_bytes().to_vec()),
        private_key,
        peer_public_key,
        client_id,
        v4,
        v6,
        endpoint_host,
        endpoint_port: if endpoint_port == 0 {
            WARP_ENDPOINT_PORT
        } else {
            endpoint_port
        },
        endpoint_v4: endpoint_v4.and_then(|ip| match ip {
            IpAddr::V4(a) => Some(a),
            IpAddr::V6(_) => None,
        }),
        endpoint_v6: endpoint_v6.and_then(|ip| match ip {
            IpAddr::V6(a) => Some(a),
            IpAddr::V4(_) => None,
        }),
    })
}

/// Parse `"162.159.192.1:0"` / `"[2606:4700:d0::a29f:c001]:0"` / bare IPs.
fn parse_host_ip(s: &str) -> Option<IpAddr> {
    if let Ok(sa) = s.parse::<SocketAddr>() {
        return Some(sa.ip());
    }
    s.trim_matches(|c| c == '[' || c == ']').parse().ok()
}

/// Endpoint candidates for the optimizer: the account's assigned anycast
/// address first, then other WARP anycast prefixes × alternative ports.
pub fn candidate_endpoints(account: &WarpAccount, max: usize) -> Vec<SocketAddr> {
    let mut out = Vec::new();
    let primary = account.endpoint_v4.unwrap_or(WARP_ANYCAST_V4[0]);
    out.push(SocketAddr::new(IpAddr::V4(primary), account.endpoint_port));
    for port in WARP_PORTS {
        for ip in WARP_ANYCAST_V4 {
            let sa = SocketAddr::new(IpAddr::V4(ip), port);
            if !out.contains(&sa) {
                out.push(sa);
            }
        }
    }
    // Ports form the outer loop, so the list already spreads across all
    // anycast prefixes before trying alternative ports.
    out.truncate(max.max(1));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_response() -> Value {
        json!({
            "id": "a1b2c3d4-0000-4000-8000-123456789abc",
            "type": "a",
            "token": "11111111-2222-3333-4444-555555555555",
            "account": { "account_type": "free", "warp_plus": false },
            "config": {
                "client_id": B64.encode([0x12, 0x34, 0x56]),
                "peers": [{
                    "public_key": "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=",
                    "endpoint": {
                        "v4": "162.159.192.1:0",
                        "v6": "[2606:4700:d0::a29f:c001]:0",
                        "host": "engage.cloudflareclient.com:2408"
                    }
                }],
                "interface": { "addresses": { "v4": "172.16.0.2", "v6": "2606:4700:110:8a1e::1" } }
            }
        })
    }

    #[test]
    fn parses_registration() {
        let acct = parse_registration(&sample_response(), Key32::random()).unwrap();
        assert_eq!(acct.client_id, [0x12, 0x34, 0x56]);
        assert_eq!(acct.v4, Ipv4Addr::new(172, 16, 0, 2));
        assert_eq!(acct.endpoint_port, 2408);
        assert_eq!(acct.endpoint_v4, Some(Ipv4Addr::new(162, 159, 192, 1)));
        assert!(acct.endpoint_v6.is_some());
        let node = acct.to_node();
        assert_eq!(node.reserved, Some([0x12, 0x34, 0x56]));
        assert!(!node.supports_pq());
        assert!(format!("{acct:?}").contains("REDACTED"));
    }

    #[test]
    fn rejects_malformed() {
        let mut r = sample_response();
        r["config"]["client_id"] = json!("AA==");
        assert!(parse_registration(&r, Key32::random()).is_err());
        let mut r = sample_response();
        r["id"] = json!("../../etc");
        assert!(parse_registration(&r, Key32::random()).is_err());
        let mut r = sample_response();
        r["config"]["peers"] = json!([]);
        assert!(parse_registration(&r, Key32::random()).is_err());
    }

    #[test]
    fn body_is_anonymous() {
        let b = registration_body(&[7u8; 32], 0);
        assert_eq!(b["install_id"], "");
        assert_eq!(b["serial_number"], "");
        assert_eq!(b["fcm_token"], "");
        assert_eq!(b["tos"], "1970-01-01T00:00:00.000Z");
    }

    #[test]
    fn rfc3339_known_dates() {
        assert_eq!(rfc3339(951_782_400), "2000-02-29T00:00:00.000Z");
        assert_eq!(rfc3339(1_795_262_400), "2026-11-21T12:00:00.000Z");
    }

    #[test]
    fn candidates_start_with_assigned_and_are_unique() {
        let acct = parse_registration(&sample_response(), Key32::random()).unwrap();
        let c = candidate_endpoints(&acct, 12);
        assert_eq!(c.len(), 12);
        assert_eq!(c[0], "162.159.192.1:2408".parse().unwrap());
        let mut d = c.clone();
        d.sort();
        d.dedup();
        assert_eq!(d.len(), c.len());
    }

    #[tokio::test]
    async fn tos_must_be_accepted() {
        let r = WarpRegistrar::new(HttpsClient::new().unwrap());
        assert!(matches!(
            r.register(false).await,
            Err(VwError::Permission(_))
        ));
    }
}
