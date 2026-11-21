//! End-to-end tests against local mock servers: an HTTP/2-only HTTPS server
//! (DoH, ODoH proxy and target, blocklist host) and a DoT server, all with
//! a self-signed certificate. The production clients are used unmodified.

mod support;

mod e2e_intercept;
mod e2e_upstreams;
mod e2e_vault;
