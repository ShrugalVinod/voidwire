//! Helpers for logging without leaking identifying data.

use std::net::{IpAddr, SocketAddr};

/// Short, salted-per-process fingerprint of an address, safe for debug logs.
pub fn ip(addr: &IpAddr) -> String {
    let salt = process_salt();
    let h = blake3::keyed_hash(&salt, addr.to_string().as_bytes());
    format!("ip#{}", &h.to_hex()[..8])
}

pub fn sock(addr: &SocketAddr) -> String {
    ip(&addr.ip())
}

/// Fingerprint of a DNS name / SNI, never the name itself.
pub fn name(n: &str) -> String {
    let salt = process_salt();
    let h = blake3::keyed_hash(&salt, n.to_ascii_lowercase().as_bytes());
    format!("name#{}", &h.to_hex()[..8])
}

fn process_salt() -> [u8; 32] {
    use std::sync::OnceLock;
    static SALT: OnceLock<[u8; 32]> = OnceLock::new();
    *SALT.get_or_init(|| {
        let mut s = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut s);
        s
    })
}

#[cfg(test)]
mod tests {
    #[test]
    fn never_contains_address() {
        let a: std::net::IpAddr = "203.0.113.99".parse().unwrap();
        let r = super::ip(&a);
        assert!(!r.contains("203"));
        assert_eq!(r, super::ip(&a));
        assert!(!super::name("tracker.example").contains("tracker"));
    }
}
