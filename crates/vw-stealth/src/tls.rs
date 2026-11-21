//! Shared TLS 1.3 helpers: node certificates, certificate pinning, configs.
//!
//! Certificate policy for clients: when `Endpoint.cert_sha256` is set, the
//! server's end-entity certificate must hash (SHA-256 over DER) to exactly
//! that value and must sign the TLS 1.3 handshake; the name and chain are not
//! checked (self-signed node certificates). Otherwise the chain is verified
//! against the bundled Mozilla roots (`webpki-roots`) for the SNI name.

use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{verify_tls12_signature, verify_tls13_signature, CryptoProvider};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, Error as TlsError, SignatureScheme};
use subtle::ConstantTimeEq;
use vw_core::config::Endpoint;
use vw_core::{Result, VwError};
use zeroize::Zeroizing;

use crate::terr;

fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// Lower-case hex SHA-256 of a DER certificate (the pin format).
pub fn cert_sha256_hex(cert_der: &[u8]) -> String {
    hex::encode(ring::digest::digest(&ring::digest::SHA256, cert_der))
}

/// Generate a self-signed node certificate for `sni`.
///
/// Returns `(cert_der, pkcs8_key_der, sha256_hex)`; the pin goes into the
/// node descriptor's `Endpoint.cert_sha256`.
pub fn generate_node_cert(sni: &str) -> Result<(Vec<u8>, Zeroizing<Vec<u8>>, String)> {
    let ck = rcgen::generate_simple_self_signed(vec![sni.to_string()]).map_err(terr)?;
    let cert = ck.cert.der().to_vec();
    let key = Zeroizing::new(ck.signing_key.serialize_der());
    let pin = cert_sha256_hex(&cert);
    Ok((cert, key, pin))
}

/// Parse a hex SHA-256 pin (whitespace and `:` separators allowed).
pub fn parse_pin(pin: &str) -> Result<[u8; 32]> {
    let clean: String = pin
        .chars()
        .filter(|c| !c.is_whitespace() && *c != ':')
        .collect();
    let v = hex::decode(clean).map_err(|_| VwError::Config("certificate pin is not hex".into()))?;
    v.try_into()
        .map_err(|_| VwError::Config("certificate pin must be 32 bytes".into()))
}

/// Accepts exactly one certificate, identified by its SHA-256.
#[derive(Debug)]
struct PinnedVerifier {
    pin: [u8; 32],
    provider: Arc<CryptoProvider>,
}

impl ServerCertVerifier for PinnedVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, TlsError> {
        let got = ring::digest::digest(&ring::digest::SHA256, end_entity.as_ref());
        if bool::from(got.as_ref().ct_eq(&self.pin)) {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(TlsError::InvalidCertificate(
                rustls::CertificateError::ApplicationVerificationFailure,
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, TlsError> {
        verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, TlsError> {
        verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// TLS 1.3 client config: pinned when `pin_hex` is given, web PKI otherwise.
pub fn client_config(pin_hex: Option<&str>, alpn: &[&[u8]]) -> Result<rustls::ClientConfig> {
    let provider = provider();
    let builder = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(terr)?;
    let mut cfg = match pin_hex {
        Some(pin) => builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(PinnedVerifier {
                pin: parse_pin(pin)?,
                provider,
            }))
            .with_no_client_auth(),
        None => {
            let roots = rustls::RootCertStore {
                roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
            };
            builder.with_root_certificates(roots).with_no_client_auth()
        }
    };
    cfg.alpn_protocols = alpn.iter().map(|a| a.to_vec()).collect();
    Ok(cfg)
}

/// TLS 1.3 server config for a node certificate (PKCS#8 key).
pub fn server_config(
    cert_der: &[u8],
    key_der: &[u8],
    alpn: &[&[u8]],
) -> Result<rustls::ServerConfig> {
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_der.to_vec()));
    let mut cfg = rustls::ServerConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(terr)?
        .with_no_client_auth()
        .with_single_cert(vec![CertificateDer::from(cert_der.to_vec())], key)
        .map_err(terr)?;
    cfg.alpn_protocols = alpn.iter().map(|a| a.to_vec()).collect();
    Ok(cfg)
}

/// TLS server name for an endpoint: `sni`, else `host` (IP or DNS name).
pub fn server_name(endpoint: &Endpoint) -> Result<ServerName<'static>> {
    let name = endpoint
        .sni
        .as_deref()
        .unwrap_or(&endpoint.host)
        .trim_start_matches('[')
        .trim_end_matches(']');
    ServerName::try_from(name.to_string())
        .map_err(|_| VwError::Config("invalid TLS server name".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cert_and_pin() {
        let (cert, key, pin) = generate_node_cert("node.example").unwrap();
        assert_eq!(pin.len(), 64);
        assert_eq!(
            parse_pin(&pin).unwrap().to_vec(),
            hex::decode(&pin).unwrap()
        );
        assert!(!key.is_empty());
        server_config(&cert, &key, &[b"h3"]).unwrap();
        client_config(Some(&pin), &[b"h3"]).unwrap();
        client_config(None, &[b"http/1.1"]).unwrap();
        assert!(parse_pin("abcd").is_err());
        assert!(parse_pin("zz").is_err());
        let upper = pin.to_uppercase();
        assert!(parse_pin(&upper).is_ok());
    }
}
