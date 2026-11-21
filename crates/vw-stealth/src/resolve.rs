//! Endpoint address resolution.

use std::net::{IpAddr, SocketAddr};

use tracing::debug;
use vw_core::config::Endpoint;
use vw_core::{redact, Result, VwError};

/// Resolve `endpoint` to a socket address.
///
/// `pre_resolved` (from the daemon's bootstrap resolver) wins; literal IPs are
/// used directly; otherwise the system resolver is queried and the first
/// address is returned.
pub async fn resolve_endpoint(
    endpoint: &Endpoint,
    pre_resolved: Option<SocketAddr>,
) -> Result<SocketAddr> {
    if let Some(a) = pre_resolved {
        return Ok(a);
    }
    let host = endpoint.host.trim_start_matches('[').trim_end_matches(']');
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(SocketAddr::new(ip, endpoint.port));
    }
    debug!(host = %redact::name(host), "resolving endpoint host");
    let mut addrs = tokio::net::lookup_host((host, endpoint.port)).await?;
    addrs
        .next()
        .ok_or_else(|| VwError::Transport("endpoint host has no addresses".into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use vw_core::config::TransportKind;

    fn ep(host: &str) -> Endpoint {
        Endpoint {
            transport: TransportKind::NativeUdp,
            host: host.into(),
            port: 51820,
            sni: None,
            path: None,
            cert_sha256: None,
        }
    }

    #[tokio::test]
    async fn literals_and_override() {
        let a = resolve_endpoint(&ep("192.0.2.1"), None).await.unwrap();
        assert_eq!(a, "192.0.2.1:51820".parse().unwrap());
        let a = resolve_endpoint(&ep("[2001:db8::1]"), None).await.unwrap();
        assert_eq!(a, "[2001:db8::1]:51820".parse().unwrap());
        let o: SocketAddr = "127.0.0.1:9".parse().unwrap();
        assert_eq!(
            resolve_endpoint(&ep("x.invalid"), Some(o)).await.unwrap(),
            o
        );
    }
}
