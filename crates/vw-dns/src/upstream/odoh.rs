//! Oblivious DNS over HTTPS (RFC 9230).
//!
//! The query is sealed with HPKE (DHKEM(X25519, HKDF-SHA256), HKDF-SHA256,
//! AES-128-GCM) to the *target*'s public key and POSTed to the *proxy*. The
//! proxy learns who asks but not what; the target learns what but not who.
//! Target configs come from `https://<target>/.well-known/odohconfigs`, are
//! cached, and are refreshed on decrypt failure or target rejection.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use hpke::aead::AesGcm128;
use hpke::kdf::HkdfSha256;
use hpke::kem::X25519HkdfSha256;
use hpke::{Deserializable, OpModeS, Serializable};
use ring::{aead, hkdf};
use vw_core::secret::Secret;
use zeroize::Zeroizing;

use super::doh::{http2_client, post};
use super::{check_response, Upstream, UpstreamOptions};
use crate::error::{DnsError, Result};

const NAME: &str = "odoh";
/// Content type of ObliviousDoHMessage bodies.
pub const ODOH_MESSAGE: &str = "application/oblivious-dns-message";
/// Well-known path of the target's configs.
pub const CONFIG_PATH: &str = "/.well-known/odohconfigs";

pub const ODOH_VERSION: u16 = 0x0001;
pub const KEM_X25519_HKDF_SHA256: u16 = 0x0020;
pub const KDF_HKDF_SHA256: u16 = 0x0001;
pub const AEAD_AES_128_GCM: u16 = 0x0001;

pub const MSG_QUERY: u8 = 0x01;
pub const MSG_RESPONSE: u8 = 0x02;

/// AES-128-GCM key / nonce lengths (Nk / Nn).
const NK: usize = 16;
const NN: usize = 12;
/// SHA-256 output length (Nh).
const NH: usize = 32;
/// Queries are padded to a multiple of this (RFC 8467 block-length policy).
pub const QUERY_PAD_BLOCK: usize = 128;
/// Refresh the target config at least this often.
const CONFIG_TTL: Duration = Duration::from_secs(3600);

type Kem = X25519HkdfSha256;

/// One supported `ObliviousDoHConfig` of a target.
#[derive(Clone, PartialEq, Eq)]
pub struct OdohConfig {
    /// Serialized `ObliviousDoHConfigContents` (input to the key id).
    contents: Vec<u8>,
    public_key: Vec<u8>,
    key_id: [u8; NH],
}

impl std::fmt::Debug for OdohConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OdohConfig")
            .field("key_id", &hex_prefix(&self.key_id))
            .finish()
    }
}

fn hex_prefix(b: &[u8]) -> String {
    b.iter().take(4).map(|x| format!("{x:02x}")).collect()
}

struct HkdfLen(usize);
impl hkdf::KeyType for HkdfLen {
    fn len(&self) -> usize {
        self.0
    }
}

fn hkdf_expand(prk: &hkdf::Prk, info: &[u8], out: &mut [u8]) -> Result<()> {
    let info = [info];
    prk.expand(&info, HkdfLen(out.len()))
        .and_then(|okm| okm.fill(out))
        .map_err(|_| DnsError::Odoh("hkdf expand"))
}

impl OdohConfig {
    /// Build a config for an X25519 public key (target side / tests).
    pub fn from_public_key(public_key: &[u8]) -> Result<Self> {
        let mut contents = Vec::with_capacity(8 + public_key.len());
        contents.extend_from_slice(&KEM_X25519_HKDF_SHA256.to_be_bytes());
        contents.extend_from_slice(&KDF_HKDF_SHA256.to_be_bytes());
        contents.extend_from_slice(&AEAD_AES_128_GCM.to_be_bytes());
        let pk_len =
            u16::try_from(public_key.len()).map_err(|_| DnsError::Odoh("public key too long"))?;
        contents.extend_from_slice(&pk_len.to_be_bytes());
        contents.extend_from_slice(public_key);
        Self::from_contents(contents, public_key.to_vec())
    }

    fn from_contents(contents: Vec<u8>, public_key: Vec<u8>) -> Result<Self> {
        // key_id = Expand(Extract("", config_contents), "odoh key id", Nh)
        let prk = hkdf::Salt::new(hkdf::HKDF_SHA256, &[]).extract(&contents);
        let mut key_id = [0u8; NH];
        hkdf_expand(&prk, b"odoh key id", &mut key_id)?;
        Ok(Self {
            contents,
            public_key,
            key_id,
        })
    }

    pub fn key_id(&self) -> &[u8; NH] {
        &self.key_id
    }

    pub fn public_key(&self) -> &[u8] {
        &self.public_key
    }

    /// Serialized `ObliviousDoHConfig` (version, length, contents).
    pub fn encode(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(4 + self.contents.len());
        v.extend_from_slice(&ODOH_VERSION.to_be_bytes());
        v.extend_from_slice(&(self.contents.len() as u16).to_be_bytes());
        v.extend_from_slice(&self.contents);
        v
    }
}

/// Serialize an `ObliviousDoHConfigs` list.
pub fn encode_configs(configs: &[OdohConfig]) -> Vec<u8> {
    let body: Vec<u8> = configs.iter().flat_map(|c| c.encode()).collect();
    let mut v = (body.len() as u16).to_be_bytes().to_vec();
    v.extend_from_slice(&body);
    v
}

struct Reader<'a> {
    b: &'a [u8],
}

impl<'a> Reader<'a> {
    fn u8(&mut self) -> Result<u8> {
        let (&x, rest) = self.b.split_first().ok_or(DnsError::Odoh("truncated"))?;
        self.b = rest;
        Ok(x)
    }
    fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_be_bytes([self.u8()?, self.u8()?]))
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        if self.b.len() < n {
            return Err(DnsError::Odoh("truncated"));
        }
        let (x, rest) = self.b.split_at(n);
        self.b = rest;
        Ok(x)
    }
    fn vec16(&mut self) -> Result<&'a [u8]> {
        let n = self.u16()? as usize;
        self.take(n)
    }
}

/// Parse `ObliviousDoHConfigs`, returning the configs we support
/// (version 1, X25519 / HKDF-SHA256 / AES-128-GCM) in server order.
/// Unknown versions and suites are skipped as RFC 9230 §6.1 requires.
pub fn parse_configs(bytes: &[u8]) -> Result<Vec<OdohConfig>> {
    let mut r = Reader { b: bytes };
    let list = r.vec16()?;
    let mut r = Reader { b: list };
    let mut out = Vec::new();
    while !r.b.is_empty() {
        let version = r.u16()?;
        let contents = r.vec16()?;
        if version != ODOH_VERSION {
            continue;
        }
        let mut c = Reader { b: contents };
        let (kem, kdf, aead_id) = (c.u16()?, c.u16()?, c.u16()?);
        let pk = c.vec16()?;
        if kem != KEM_X25519_HKDF_SHA256
            || kdf != KDF_HKDF_SHA256
            || aead_id != AEAD_AES_128_GCM
            || !c.b.is_empty()
            || <Kem as hpke::Kem>::PublicKey::from_bytes(pk).is_err()
        {
            continue;
        }
        out.push(OdohConfig::from_contents(contents.to_vec(), pk.to_vec())?);
    }
    if out.is_empty() {
        return Err(DnsError::Odoh("target offers no supported config"));
    }
    Ok(out)
}

/// `ObliviousDoHMessage`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OdohMessage {
    pub message_type: u8,
    pub key_id: Vec<u8>,
    pub encrypted_message: Vec<u8>,
}

impl OdohMessage {
    pub fn encode(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(5 + self.key_id.len() + self.encrypted_message.len());
        v.push(self.message_type);
        v.extend_from_slice(&(self.key_id.len() as u16).to_be_bytes());
        v.extend_from_slice(&self.key_id);
        v.extend_from_slice(&(self.encrypted_message.len() as u16).to_be_bytes());
        v.extend_from_slice(&self.encrypted_message);
        v
    }

    pub fn decode(b: &[u8]) -> Result<Self> {
        let mut r = Reader { b };
        let message_type = r.u8()?;
        let key_id = r.vec16()?.to_vec();
        let encrypted_message = r.vec16()?.to_vec();
        if !r.b.is_empty() {
            return Err(DnsError::Odoh("trailing bytes"));
        }
        Ok(Self {
            message_type,
            key_id,
            encrypted_message,
        })
    }
}

/// `aad = type || len(key_id) || key_id`
pub fn aad(message_type: u8, key_id: &[u8]) -> Vec<u8> {
    let mut a = Vec::with_capacity(3 + key_id.len());
    a.push(message_type);
    a.extend_from_slice(&(key_id.len() as u16).to_be_bytes());
    a.extend_from_slice(key_id);
    a
}

/// `ObliviousDoHMessagePlaintext` with zero padding to `block` bytes of DNS payload.
pub fn encode_plaintext(dns: &[u8], block: usize) -> Result<Vec<u8>> {
    let dns_len = u16::try_from(dns.len()).map_err(|_| DnsError::Odoh("message too long"))?;
    let padded = if block > 1 {
        dns.len().div_ceil(block) * block
    } else {
        dns.len()
    };
    let pad = padded - dns.len();
    let mut v = Zeroizing::new(Vec::with_capacity(4 + padded));
    v.extend_from_slice(&dns_len.to_be_bytes());
    v.extend_from_slice(dns);
    v.extend_from_slice(&(pad as u16).to_be_bytes());
    let new_len = v.len() + pad;
    v.resize(new_len, 0);
    Ok(v.to_vec())
}

/// Extract the DNS message from a plaintext, checking that padding is zero.
pub fn decode_plaintext(p: &[u8]) -> Result<Vec<u8>> {
    let mut r = Reader { b: p };
    let dns = r.vec16()?;
    let pad = r.vec16()?;
    if !r.b.is_empty() || pad.iter().any(|b| *b != 0) || dns.is_empty() {
        return Err(DnsError::Odoh("bad plaintext"));
    }
    Ok(dns.to_vec())
}

/// Derive the response AEAD key and nonce (RFC 9230 §6.4).
///
/// `salt = Q_plain || len(resp_nonce) || resp_nonce`,
/// `prk = Extract(salt, secret)`, `key = Expand(prk, "odoh key", Nk)`,
/// `nonce = Expand(prk, "odoh nonce", Nn)`.
pub fn derive_response_secrets(
    secret: &[u8],
    q_plain: &[u8],
    response_nonce: &[u8],
) -> Result<(Secret<NK>, [u8; NN])> {
    let mut salt = Zeroizing::new(Vec::with_capacity(q_plain.len() + 2 + response_nonce.len()));
    salt.extend_from_slice(q_plain);
    salt.extend_from_slice(&(response_nonce.len() as u16).to_be_bytes());
    salt.extend_from_slice(response_nonce);
    let prk = hkdf::Salt::new(hkdf::HKDF_SHA256, &salt).extract(secret);
    let mut key = [0u8; NK];
    let mut nonce = [0u8; NN];
    hkdf_expand(&prk, b"odoh key", &mut key)?;
    hkdf_expand(&prk, b"odoh nonce", &mut nonce)?;
    let k = Secret::new(key);
    zeroize::Zeroize::zeroize(&mut key);
    Ok((k, nonce))
}

/// AES-128-GCM seal (`ct || tag`).
pub fn aes_seal(key: &[u8], nonce: [u8; NN], aad: &[u8], pt: &[u8]) -> Result<Vec<u8>> {
    let k = aead::LessSafeKey::new(
        aead::UnboundKey::new(&aead::AES_128_GCM, key).map_err(|_| DnsError::Odoh("aead key"))?,
    );
    let mut buf = pt.to_vec();
    k.seal_in_place_append_tag(
        aead::Nonce::assume_unique_for_key(nonce),
        aead::Aad::from(aad),
        &mut buf,
    )
    .map_err(|_| DnsError::Odoh("seal"))?;
    Ok(buf)
}

/// AES-128-GCM open.
pub fn aes_open(key: &[u8], nonce: [u8; NN], aad: &[u8], ct: &[u8]) -> Result<Vec<u8>> {
    let k = aead::LessSafeKey::new(
        aead::UnboundKey::new(&aead::AES_128_GCM, key).map_err(|_| DnsError::Odoh("aead key"))?,
    );
    let mut buf = ct.to_vec();
    let pt = k
        .open_in_place(
            aead::Nonce::assume_unique_for_key(nonce),
            aead::Aad::from(aad),
            &mut buf,
        )
        .map_err(|_| DnsError::Odoh("response decryption failed"))?;
    Ok(pt.to_vec())
}

/// Client-side state needed to open the response to one query.
pub struct QueryContext {
    secret: Secret<NK>,
    q_plain: Zeroizing<Vec<u8>>,
}

impl std::fmt::Debug for QueryContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("QueryContext(<redacted>)")
    }
}

/// Seal a DNS query for `config` (RFC 9230 §6.3). Returns the encoded
/// `ObliviousDoHMessage` and the context to decrypt the answer.
pub fn encrypt_query(config: &OdohConfig, dns_query: &[u8]) -> Result<(Vec<u8>, QueryContext)> {
    let pk = <Kem as hpke::Kem>::PublicKey::from_bytes(&config.public_key)
        .map_err(|_| DnsError::Odoh("invalid target key"))?;
    let q_plain = Zeroizing::new(encode_plaintext(dns_query, QUERY_PAD_BLOCK)?);
    let (enc, mut ctx) =
        hpke::setup_sender::<AesGcm128, HkdfSha256, Kem>(&OpModeS::Base, &pk, b"odoh query")
            .map_err(|_| DnsError::Odoh("hpke encapsulation"))?;
    let a = aad(MSG_QUERY, &config.key_id);
    let ct = ctx
        .seal(&q_plain, &a)
        .map_err(|_| DnsError::Odoh("hpke seal"))?;
    let mut secret = [0u8; NK];
    ctx.export(b"odoh response", &mut secret)
        .map_err(|_| DnsError::Odoh("hpke export"))?;
    let enc = enc.to_bytes();
    let mut encrypted_message = Vec::with_capacity(enc.len() + ct.len());
    encrypted_message.extend_from_slice(&enc);
    encrypted_message.extend_from_slice(&ct);
    let msg = OdohMessage {
        message_type: MSG_QUERY,
        key_id: config.key_id.to_vec(),
        encrypted_message,
    };
    let qc = QueryContext {
        secret: Secret::new(secret),
        q_plain,
    };
    zeroize::Zeroize::zeroize(&mut secret);
    Ok((msg.encode(), qc))
}

impl QueryContext {
    /// Open an encoded response `ObliviousDoHMessage` (RFC 9230 §6.5).
    pub fn decrypt_response(&self, body: &[u8]) -> Result<Vec<u8>> {
        let m = OdohMessage::decode(body)?;
        if m.message_type != MSG_RESPONSE {
            return Err(DnsError::Odoh("not a response message"));
        }
        let nonce_len = NK.max(NN);
        if m.key_id.len() != nonce_len {
            return Err(DnsError::Odoh("bad response nonce length"));
        }
        let (key, nonce) = derive_response_secrets(self.secret.expose(), &self.q_plain, &m.key_id)?;
        let pt = Zeroizing::new(aes_open(
            key.expose(),
            nonce,
            &aad(MSG_RESPONSE, &m.key_id),
            &m.encrypted_message,
        )?);
        decode_plaintext(&pt)
    }
}

/// RFC 9230 client: seals queries to the target, relays them via the proxy.
pub struct OdohUpstream {
    client: reqwest::Client,
    proxy: reqwest::Url,
    config_url: reqwest::Url,
    config: Mutex<Option<(Arc<OdohConfig>, Instant)>>,
}

impl std::fmt::Debug for OdohUpstream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OdohUpstream").finish_non_exhaustive()
    }
}

impl OdohUpstream {
    /// Production client (Mozilla roots, built-in bootstrap).
    pub fn new(proxy_url: &str, target_host: &str, target_path: &str) -> Result<Self> {
        Self::with_options(
            proxy_url,
            target_host,
            target_path,
            &UpstreamOptions::production()?,
        )
    }

    /// `target_host` may carry a port (`odoh.example:8443`).
    pub fn with_options(
        proxy_url: &str,
        target_host: &str,
        target_path: &str,
        opts: &UpstreamOptions,
    ) -> Result<Self> {
        let mut proxy = reqwest::Url::parse(proxy_url)
            .map_err(|_| DnsError::Config("invalid ODoH proxy url".into()))?;
        if proxy.scheme() != "https" {
            return Err(DnsError::Config("ODoH proxy url must be https".into()));
        }
        if target_host.is_empty() || target_host.contains('/') || !target_path.starts_with('/') {
            return Err(DnsError::Config("invalid ODoH target".into()));
        }
        proxy
            .query_pairs_mut()
            .append_pair("targethost", target_host)
            .append_pair("targetpath", target_path);
        let config_url = reqwest::Url::parse(&format!("https://{target_host}{CONFIG_PATH}"))
            .map_err(|_| DnsError::Config("invalid ODoH target host".into()))?;
        Ok(Self {
            client: http2_client(opts)?,
            proxy,
            config_url,
            config: Mutex::new(None),
        })
    }

    /// Fetch and cache the target's config.
    pub async fn refresh_config(&self) -> Result<Arc<OdohConfig>> {
        let mut resp = self
            .client
            .get(self.config_url.clone())
            .send()
            .await
            .map_err(|e| DnsError::http(NAME, e))?;
        if !resp.status().is_success() {
            return Err(DnsError::upstream(
                NAME,
                format!("config fetch status {}", resp.status()),
            ));
        }
        let mut body = Vec::new();
        while let Some(c) = resp.chunk().await.map_err(|e| DnsError::http(NAME, e))? {
            if body.len() + c.len() > 16 * 1024 {
                return Err(DnsError::Odoh("config too large"));
            }
            body.extend_from_slice(&c);
        }
        let cfg = Arc::new(
            parse_configs(&body)?
                .into_iter()
                .next()
                .ok_or(DnsError::Odoh("no config"))?,
        );
        if let Ok(mut g) = self.config.lock() {
            *g = Some((cfg.clone(), Instant::now()));
        }
        tracing::debug!(key_id = %hex_prefix(cfg.key_id()), "odoh target config refreshed");
        Ok(cfg)
    }

    async fn current_config(&self) -> Result<Arc<OdohConfig>> {
        let cached = self.config.lock().ok().and_then(|g| g.clone());
        match cached {
            Some((c, at)) if at.elapsed() < CONFIG_TTL => Ok(c),
            _ => self.refresh_config().await,
        }
    }

    fn invalidate(&self) {
        if let Ok(mut g) = self.config.lock() {
            *g = None;
        }
    }

    async fn attempt(
        &self,
        cfg: &OdohConfig,
        dns: &[u8],
    ) -> Result<std::result::Result<Vec<u8>, DnsError>> {
        let (body, ctx) = encrypt_query(cfg, dns)?;
        let (status, resp) =
            post(&self.client, NAME, self.proxy.clone(), ODOH_MESSAGE, body).await?;
        if status == reqwest::StatusCode::BAD_REQUEST || status == reqwest::StatusCode::UNAUTHORIZED
        {
            // Target could not decrypt: most likely a rotated key.
            return Ok(Err(DnsError::Odoh("target rejected query")));
        }
        if !status.is_success() {
            return Err(DnsError::upstream(NAME, format!("http status {status}")));
        }
        Ok(ctx.decrypt_response(&resp))
    }
}

#[async_trait]
impl Upstream for OdohUpstream {
    async fn query(&self, wire: &[u8]) -> Result<Vec<u8>> {
        if wire.len() < 12 {
            return Err(DnsError::Malformed("short query"));
        }
        let id = [wire[0], wire[1]];
        // id 0 inside the sealed query, like DoH.
        let dns = super::with_id(wire, [0, 0]);
        let cfg = self.current_config().await?;
        let resp = match self.attempt(&cfg, &dns).await? {
            Ok(r) => r,
            Err(e) => {
                tracing::debug!(error = %e, "odoh: refreshing target config and retrying");
                self.invalidate();
                let cfg = self.refresh_config().await?;
                self.attempt(&cfg, &dns).await??
            }
        };
        check_response(NAME, &[0, 0], &resp)?;
        Ok(super::with_id(&resp, id))
    }

    fn name(&self) -> &'static str {
        NAME
    }
}

#[cfg(test)]
pub(crate) mod target {
    //! Target-side ODoH processing for local test servers.
    use super::*;
    use hpke::{Kem as _, OpModeR};

    pub struct TestTarget {
        pub sk: <Kem as hpke::Kem>::PrivateKey,
        pub config: OdohConfig,
    }

    impl TestTarget {
        pub fn generate() -> Self {
            let (sk, pk) = Kem::gen_keypair();
            let config = OdohConfig::from_public_key(&pk.to_bytes()).unwrap();
            Self { sk, config }
        }

        /// Decrypt a query, answer it with `answer`, seal the response.
        pub fn handle(
            &self,
            body: &[u8],
            answer: impl FnOnce(&[u8]) -> Vec<u8>,
        ) -> Result<Vec<u8>> {
            let m = OdohMessage::decode(body)?;
            if m.message_type != MSG_QUERY || m.key_id != self.config.key_id {
                return Err(DnsError::Odoh("unknown key id"));
            }
            let enc_len = <Kem as hpke::Kem>::EncappedKey::size();
            if m.encrypted_message.len() <= enc_len {
                return Err(DnsError::Odoh("short"));
            }
            let (enc, ct) = m.encrypted_message.split_at(enc_len);
            let enc = <Kem as hpke::Kem>::EncappedKey::from_bytes(enc)
                .map_err(|_| DnsError::Odoh("enc"))?;
            let mut ctx = hpke::setup_receiver::<AesGcm128, HkdfSha256, Kem>(
                &OpModeR::Base,
                &self.sk,
                &enc,
                b"odoh query",
            )
            .map_err(|_| DnsError::Odoh("decap"))?;
            let q_plain = ctx
                .open(ct, &aad(MSG_QUERY, &m.key_id))
                .map_err(|_| DnsError::Odoh("open"))?;
            assert_eq!((q_plain.len() - 4) % QUERY_PAD_BLOCK, 0, "query not padded");
            let dns = decode_plaintext(&q_plain)?;
            let mut secret = [0u8; NK];
            ctx.export(b"odoh response", &mut secret)
                .map_err(|_| DnsError::Odoh("export"))?;
            let mut nonce = [0u8; 16];
            rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut nonce);
            let (key, aead_nonce) = derive_response_secrets(&secret, &q_plain, &nonce)?;
            let r_plain = encode_plaintext(&answer(&dns), 0)?;
            let ct = aes_seal(
                key.expose(),
                aead_nonce,
                &aad(MSG_RESPONSE, &nonce),
                &r_plain,
            )?;
            Ok(OdohMessage {
                message_type: MSG_RESPONSE,
                key_id: nonce.to_vec(),
                encrypted_message: ct,
            }
            .encode())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::target::TestTarget;
    use super::*;

    #[test]
    fn configs_roundtrip_and_skip_unknown() {
        let t = TestTarget::generate();
        let mut list = Vec::new();
        // An unknown version and an unsupported suite before ours.
        list.extend_from_slice(&0x00ffu16.to_be_bytes());
        list.extend_from_slice(&2u16.to_be_bytes());
        list.extend_from_slice(&[0, 0]);
        let mut bad = OdohConfig::from_public_key(t.config.public_key()).unwrap();
        bad.contents[0..2].copy_from_slice(&0x0010u16.to_be_bytes());
        list.extend_from_slice(&bad.encode());
        list.extend_from_slice(&t.config.encode());
        let mut wire = (list.len() as u16).to_be_bytes().to_vec();
        wire.extend_from_slice(&list);
        let parsed = parse_configs(&wire).unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0], t.config);
        assert!(parse_configs(&encode_configs(&[])).is_err());
        assert!(parse_configs(&[0, 5, 1]).is_err());
    }

    #[test]
    fn query_response_roundtrip() {
        let t = TestTarget::generate();
        let q = crate::message::testutil::query(
            "example.com.",
            hickory_proto::rr::RecordType::A,
            0,
            true,
        );
        let (body, ctx) = encrypt_query(&t.config, &q).unwrap();
        let resp = t
            .handle(&body, |dns| {
                assert_eq!(dns, &q[..]);
                b"answer-bytes".to_vec()
            })
            .unwrap();
        assert_eq!(ctx.decrypt_response(&resp).unwrap(), b"answer-bytes");
        // Tampering is detected.
        let mut bad = resp.clone();
        let last = bad.len() - 1;
        bad[last] ^= 1;
        assert!(ctx.decrypt_response(&bad).is_err());
        // Another query's context cannot open it.
        let (_, other) = encrypt_query(&t.config, &q).unwrap();
        assert!(other.decrypt_response(&resp).is_err());
    }

    #[test]
    fn padding_is_block_aligned() {
        let p = encode_plaintext(&[1u8; 30], 128).unwrap();
        assert_eq!(p.len(), 2 + 30 + 2 + 98);
        assert_eq!(decode_plaintext(&p).unwrap(), vec![1u8; 30]);
        let mut bad = p.clone();
        let last = bad.len() - 1;
        bad[last] = 1;
        assert!(decode_plaintext(&bad).is_err());
    }
}
