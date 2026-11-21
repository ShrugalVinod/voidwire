//! `voidwire://` URI encoding.

use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64U;
use base64::Engine;

use crate::config::NodeDescriptor;
use crate::error::{Result, VwError};

pub const NODE_PREFIX: &str = "voidwire://node/";
pub const F2F_PREFIX: &str = "voidwire://f2f/";

pub fn encode_node(n: &NodeDescriptor) -> Result<String> {
    n.validate()?;
    let json = serde_json::to_vec(n)?;
    Ok(format!("{NODE_PREFIX}{}", B64U.encode(json)))
}

pub fn decode_node(uri: &str) -> Result<NodeDescriptor> {
    let body = uri
        .trim()
        .strip_prefix(NODE_PREFIX)
        .ok_or_else(|| VwError::Uri("expected voidwire://node/ prefix".into()))?;
    let raw = B64U
        .decode(body)
        .map_err(|e| VwError::Uri(format!("bad base64: {e}")))?;
    let n: NodeDescriptor = serde_json::from_slice(&raw)?;
    n.validate()?;
    Ok(n)
}

/// Encode an opaque binary payload behind a prefix (used for F2F invites).
pub fn encode_blob(prefix: &str, data: &[u8]) -> String {
    format!("{prefix}{}", B64U.encode(data))
}

pub fn decode_blob(prefix: &str, uri: &str) -> Result<Vec<u8>> {
    let body = uri
        .trim()
        .strip_prefix(prefix)
        .ok_or_else(|| VwError::Uri(format!("expected {prefix} prefix")))?;
    B64U.decode(body)
        .map_err(|e| VwError::Uri(format!("bad base64: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::*;

    pub(crate) fn sample() -> NodeDescriptor {
        NodeDescriptor {
            version: 1,
            name: "test".into(),
            kind: NodeKind::Voidwire,
            role: NodeRole::Both,
            wg_public_key: Bytes32([1; 32]),
            identity_key: Some(Bytes32([2; 32])),
            endpoints: vec![Endpoint {
                transport: TransportKind::AmneziaWg,
                host: "192.0.2.10".into(),
                port: 51820,
                sni: None,
                path: None,
                cert_sha256: None,
            }],
            amnezia: Some(AmneziaParams::random()),
            country: Some("CH".into()),
            ipv6_exit: false,
            static_v4: None,
            static_v6: None,
            reserved: None,
            static_psk: None,
        }
    }

    #[test]
    fn roundtrip() {
        let n = sample();
        let u = encode_node(&n).unwrap();
        assert!(u.starts_with(NODE_PREFIX));
        assert_eq!(decode_node(&u).unwrap(), n);
        assert!(decode_node("voidwire://f2f/abc").is_err());
    }
}
