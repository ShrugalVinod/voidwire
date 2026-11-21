//! DNS over HTTPS (RFC 8484): POST `application/dns-message` over HTTP/2.

use async_trait::async_trait;

use super::{check_response, with_id, Upstream, UpstreamOptions, DNS_MESSAGE};
use crate::error::{DnsError, Result};
use crate::message::MAX_MESSAGE;

const NAME: &str = "doh";

/// RFC 8484 client. HTTP/2 only (ALPN `h2`, prior knowledge), no redirects,
/// no proxies, no cookies, no referer, no User-Agent; resolver hostnames are resolved via
/// [`crate::tls::Bootstrap`], never via the OS resolver (which is the vault).
#[derive(Debug, Clone)]
pub struct DohUpstream {
    client: reqwest::Client,
    url: reqwest::Url,
}

impl DohUpstream {
    /// Production client (Mozilla roots, built-in bootstrap).
    pub fn new(url: &str) -> Result<Self> {
        Self::with_options(url, &UpstreamOptions::production()?)
    }

    pub fn with_options(url: &str, opts: &UpstreamOptions) -> Result<Self> {
        let url =
            reqwest::Url::parse(url).map_err(|_| DnsError::Config("invalid DoH url".into()))?;
        if url.scheme() != "https" {
            return Err(DnsError::Config("DoH url must be https".into()));
        }
        let client = http2_client(opts)?;
        Ok(Self { client, url })
    }

    pub fn url(&self) -> &reqwest::Url {
        &self.url
    }
}

/// HTTP/2-only reqwest client shared by DoH and ODoH.
pub(crate) fn http2_client(opts: &UpstreamOptions) -> Result<reqwest::Client> {
    let tls = opts.trust.client_config(&[b"h2"])?;
    reqwest::Client::builder()
        .tls_backend_preconfigured(tls)
        .http2_prior_knowledge()
        .dns_resolver(opts.bootstrap.clone())
        .https_only(true)
        .no_proxy()
        .referer(false)
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(opts.timeout)
        .timeout(opts.timeout)
        .pool_idle_timeout(std::time::Duration::from_secs(90))
        .http2_keep_alive_interval(std::time::Duration::from_secs(30))
        .build()
        .map_err(|e| DnsError::Tls(e.without_url().to_string()))
}

/// POST a body and return the response body, enforcing status, content type
/// and size.
pub(crate) async fn post(
    client: &reqwest::Client,
    upstream: &'static str,
    url: reqwest::Url,
    content_type: &'static str,
    body: Vec<u8>,
) -> Result<(reqwest::StatusCode, Vec<u8>)> {
    let mut resp = client
        .post(url)
        .header(reqwest::header::CONTENT_TYPE, content_type)
        .header(reqwest::header::ACCEPT, content_type)
        .body(body)
        .send()
        .await
        .map_err(|e| DnsError::http(upstream, e))?;
    let status = resp.status();
    if !status.is_success() {
        return Ok((status, Vec::new()));
    }
    let ct_ok = resp
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(|v| {
            v.split(';')
                .next()
                .unwrap_or("")
                .trim()
                .eq_ignore_ascii_case(content_type)
        })
        .unwrap_or(false);
    if !ct_ok {
        return Err(DnsError::upstream(upstream, "unexpected content type"));
    }
    let mut out = Vec::new();
    while let Some(chunk) = resp
        .chunk()
        .await
        .map_err(|e| DnsError::http(upstream, e))?
    {
        if out.len() + chunk.len() > MAX_MESSAGE + 1024 {
            return Err(DnsError::upstream(upstream, "oversized response"));
        }
        out.extend_from_slice(&chunk);
    }
    Ok((status, out))
}

#[async_trait]
impl Upstream for DohUpstream {
    async fn query(&self, wire: &[u8]) -> Result<Vec<u8>> {
        if wire.len() < 12 {
            return Err(DnsError::Malformed("short query"));
        }
        let id = [wire[0], wire[1]];
        // RFC 8484 §4.1: id 0 for HTTP cache friendliness.
        let body = with_id(wire, [0, 0]);
        let (status, resp) = post(&self.client, NAME, self.url.clone(), DNS_MESSAGE, body).await?;
        if !status.is_success() {
            return Err(DnsError::upstream(NAME, format!("http status {status}")));
        }
        check_response(NAME, &[0, 0], &resp)?;
        Ok(with_id(&resp, id))
    }

    fn name(&self) -> &'static str {
        NAME
    }
}
