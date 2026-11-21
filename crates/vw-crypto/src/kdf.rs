//! HKDF-BLAKE3 and the VWCP key schedule (ARCHITECTURE.md §6).
//!
//! ```text
//! Extract(salt, ikm)   = BLAKE3-keyed(key = BLAKE3(salt), ikm)
//! Expand(prk, info, L) = BLAKE3-keyed-XOF(key = prk, info)[0..L]
//!
//! prk       = Extract("voidwire-pq-psk-v1", ss_x || ss_k || th)
//! psk       = Expand(prk, "psk" || session_id || epoch_be, 32)
//! confirm_c = BLAKE3-keyed(Expand(prk, "confirm", 32), "client" || th)
//! confirm_s = BLAKE3-keyed(Expand(prk, "confirm", 32), "server" || th)
//! ```

use subtle::ConstantTimeEq;
use vw_core::secret::{Key32, Secret};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Salt of the VWCP PSK extraction step.
pub const PSK_SALT: &[u8] = b"voidwire-pq-psk-v1";
/// Expand label for the WireGuard PSK.
pub const PSK_INFO: &[u8] = b"psk";
/// Expand label for the key-confirmation key.
pub const CONFIRM_INFO: &[u8] = b"confirm";
/// Confirmation role label of the client.
pub const CONFIRM_CLIENT: &[u8] = b"client";
/// Confirmation role label of the server.
pub const CONFIRM_SERVER: &[u8] = b"server";

/// HKDF-BLAKE3 extract: `BLAKE3-keyed(BLAKE3(salt), ikm)`.
pub fn extract(salt: &[u8], ikm: &[u8]) -> Key32 {
    let mut salt_key = blake3::hash(salt);
    let mut hasher = blake3::Hasher::new_keyed(salt_key.as_bytes());
    hasher.update(ikm);
    let mut prk = Key32::zero();
    let mut reader = hasher.finalize_xof();
    reader.fill(prk.expose_mut());
    reader.zeroize();
    hasher.zeroize();
    salt_key.zeroize();
    prk
}

/// HKDF-BLAKE3 expand: fills `out` with `BLAKE3-keyed-XOF(prk, info)`.
///
/// Any output length is allowed (BLAKE3's XOF is unbounded); prefixes are
/// consistent, i.e. a shorter `out` receives a prefix of a longer one.
pub fn expand(prk: &Key32, info: &[u8], out: &mut [u8]) {
    let mut hasher = blake3::Hasher::new_keyed(prk.expose());
    hasher.update(info);
    let mut reader = hasher.finalize_xof();
    reader.fill(out);
    reader.zeroize();
    hasher.zeroize();
}

/// Convenience: [`expand`] into a fresh 32-byte key.
pub fn expand_key(prk: &Key32, info: &[u8]) -> Key32 {
    let mut k = Key32::zero();
    expand(prk, info, k.expose_mut());
    k
}

/// VWCP pseudo-random key: `Extract("voidwire-pq-psk-v1", ss_x || ss_k || th)`.
pub fn pq_prk(ss_x: &Key32, ss_k: &Key32, th: &[u8; 32]) -> Key32 {
    let mut ikm = Secret::<96>::zero();
    ikm.expose_mut()[..32].copy_from_slice(ss_x.expose());
    ikm.expose_mut()[32..64].copy_from_slice(ss_k.expose());
    ikm.expose_mut()[64..].copy_from_slice(th);
    extract(PSK_SALT, ikm.expose())
}

fn psk_info(session_id: &[u8; 16], epoch: u32) -> [u8; 23] {
    let mut info = [0u8; 3 + 16 + 4];
    info[..3].copy_from_slice(PSK_INFO);
    info[3..19].copy_from_slice(session_id);
    info[19..].copy_from_slice(&epoch.to_be_bytes());
    info
}

/// Derive the WireGuard pre-shared key for one VWCP session/epoch.
pub fn derive_psk(
    ss_x: &Key32,
    ss_k: &Key32,
    th: &[u8; 32],
    session_id: &[u8; 16],
    epoch: u32,
) -> Key32 {
    let prk = pq_prk(ss_x, ss_k, th);
    expand_key(&prk, &psk_info(session_id, epoch))
}

/// Key-confirmation tag `BLAKE3-keyed(Expand(prk, "confirm", 32), role || th)`.
pub fn confirm_tag(prk: &Key32, role: &[u8], th: &[u8; 32]) -> [u8; 32] {
    let ck = expand_key(prk, CONFIRM_INFO);
    let mut hasher = blake3::Hasher::new_keyed(ck.expose());
    hasher.update(role);
    hasher.update(th);
    let tag = *hasher.finalize().as_bytes();
    hasher.zeroize();
    tag
}

/// Everything VWCP derives from one hybrid exchange.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SessionKeys {
    /// WireGuard pre-shared key.
    pub psk: Key32,
    /// Client confirmation tag (sent in ClientKem).
    pub confirm_c: [u8; 32],
    /// Server confirmation tag (sent in ServerAck).
    pub confirm_s: [u8; 32],
}

impl SessionKeys {
    /// Constant-time check of a received client confirmation tag.
    pub fn check_client(&self, tag: &[u8; 32]) -> bool {
        self.confirm_c.ct_eq(tag).into()
    }

    /// Constant-time check of a received server confirmation tag.
    pub fn check_server(&self, tag: &[u8; 32]) -> bool {
        self.confirm_s.ct_eq(tag).into()
    }
}

impl std::fmt::Debug for SessionKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SessionKeys(REDACTED)")
    }
}

/// Derive the PSK and both confirmation tags in one pass.
pub fn derive_session_keys(
    ss_x: &Key32,
    ss_k: &Key32,
    th: &[u8; 32],
    session_id: &[u8; 16],
    epoch: u32,
) -> SessionKeys {
    let prk = pq_prk(ss_x, ss_k, th);
    SessionKeys {
        psk: expand_key(&prk, &psk_info(session_id, epoch)),
        confirm_c: confirm_tag(&prk, CONFIRM_CLIENT, th),
        confirm_s: confirm_tag(&prk, CONFIRM_SERVER, th),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Independent reference implementation written directly against `blake3`.
    fn ref_extract(salt: &[u8], ikm: &[u8]) -> [u8; 32] {
        let k = blake3::hash(salt);
        *blake3::keyed_hash(k.as_bytes(), ikm).as_bytes()
    }

    fn ref_expand(prk: &[u8; 32], info: &[u8], len: usize) -> Vec<u8> {
        let mut out = vec![0u8; len];
        blake3::Hasher::new_keyed(prk)
            .update(info)
            .finalize_xof()
            .fill(&mut out);
        out
    }

    #[test]
    fn extract_matches_reference() {
        let prk = extract(b"salt", b"input keying material");
        assert_eq!(
            prk.expose(),
            &ref_extract(b"salt", b"input keying material")
        );
        // Changing either input changes the output.
        assert_ne!(prk, extract(b"salt2", b"input keying material"));
        assert_ne!(prk, extract(b"salt", b"input keying materiaL"));
    }

    #[test]
    fn expand_matches_reference_and_is_prefix_consistent() {
        let prk = Key32::new([0x42; 32]);
        let mut long = [0u8; 100];
        expand(&prk, b"info", &mut long);
        assert_eq!(long.to_vec(), ref_expand(&[0x42; 32], b"info", 100));
        let mut short = [0u8; 32];
        expand(&prk, b"info", &mut short);
        assert_eq!(&long[..32], &short);
        // 32-byte keyed XOF prefix equals the keyed hash.
        assert_eq!(short, *blake3::keyed_hash(&[0x42; 32], b"info").as_bytes());
    }

    #[test]
    fn psk_known_answer() {
        let ss_x = Key32::new([1; 32]);
        let ss_k = Key32::new([2; 32]);
        let th = [3u8; 32];
        let sid = [4u8; 16];
        let epoch = 0x0102_0304u32;

        let mut ikm = Vec::new();
        ikm.extend_from_slice(&[1; 32]);
        ikm.extend_from_slice(&[2; 32]);
        ikm.extend_from_slice(&[3; 32]);
        let prk = ref_extract(b"voidwire-pq-psk-v1", &ikm);
        let mut info = b"psk".to_vec();
        info.extend_from_slice(&sid);
        info.extend_from_slice(&[1, 2, 3, 4]);
        let psk = ref_expand(&prk, &info, 32);

        let ck = ref_expand(&prk, b"confirm", 32);
        let ck: [u8; 32] = ck.try_into().unwrap();
        let mut c_in = b"client".to_vec();
        c_in.extend_from_slice(&th);
        let mut s_in = b"server".to_vec();
        s_in.extend_from_slice(&th);
        let confirm_c = *blake3::keyed_hash(&ck, &c_in).as_bytes();
        let confirm_s = *blake3::keyed_hash(&ck, &s_in).as_bytes();

        assert_eq!(
            derive_psk(&ss_x, &ss_k, &th, &sid, epoch).expose().to_vec(),
            psk
        );
        let keys = derive_session_keys(&ss_x, &ss_k, &th, &sid, epoch);
        assert_eq!(keys.psk.expose().to_vec(), psk);
        assert_eq!(keys.confirm_c, confirm_c);
        assert_eq!(keys.confirm_s, confirm_s);
        assert_ne!(keys.confirm_c, keys.confirm_s);
        assert!(keys.check_client(&confirm_c));
        assert!(!keys.check_client(&confirm_s));
        assert!(keys.check_server(&confirm_s));
    }

    #[test]
    fn epoch_and_session_separate_psks() {
        let a = Key32::new([9; 32]);
        let b = Key32::new([8; 32]);
        let th = [7u8; 32];
        let p0 = derive_psk(&a, &b, &th, &[0; 16], 0);
        assert_ne!(p0, derive_psk(&a, &b, &th, &[0; 16], 1));
        assert_ne!(p0, derive_psk(&a, &b, &th, &[1; 16], 0));
        assert!(!format!("{:?}", derive_session_keys(&a, &b, &th, &[0; 16], 0)).contains('9'));
    }
}
