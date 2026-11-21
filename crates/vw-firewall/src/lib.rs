//! `vw-firewall` — VoidWire's fail-closed kill switch.
//!
//! * [`FirewallBackend`] with kernel-persistent executors: nftables + policy
//!   routing (Linux), a pf anchor (macOS) and WFP persistent / boot-time
//!   filters (Windows). [`platform_backend`] picks the one for this OS.
//! * Pure rule rendering for every platform, compiled everywhere and
//!   unit-tested: [`linux::render_nft`], [`linux::render_policy_routing`],
//!   [`macos::render_pf_anchor`], [`windows_spec::render`].
//! * [`stun::StunFilter`] (userspace WebRTC STUN drop), [`sysdns`] (system
//!   resolver → DNS vault), [`linux::netns`] (`voidwire exec` isolation) and
//!   split-route helpers ([`macos::routes`], `windows::routes`).
//!
//! Every `arm` / `update` replaces the whole ruleset atomically (one nft
//! transaction, one pf anchor load, one WFP transaction) and is idempotent.
//! Arming without a tunnel (boot lock) blocks everything except loopback,
//! DHCP and the pinned endpoints.

#![deny(unsafe_op_in_unsafe_fn)]
#![cfg_attr(not(any(target_os = "linux", windows)), forbid(unsafe_code))]

mod cmd;
pub mod linux;
pub mod macos;
mod plan;
pub mod stun;
pub mod sysdns;
#[cfg(windows)]
pub mod windows;
pub mod windows_spec;

pub use cmd::scrub_addresses;
pub use plan::{
    split_default_prefixes, validate_ifname, FirewallStatus, IpCidr, LockdownPlan, PinnedEndpoint,
    Proto, TunnelIface,
};
pub use stun::{is_stun, StunFilter, Verdict};

use vw_core::Result;

/// A kernel firewall backend. Implementations keep no state the kernel does
/// not also hold: a daemon crash leaves the lockdown in place.
pub trait FirewallBackend: Send {
    /// Short backend name (`nftables`, `pf`, `wfp`).
    fn name(&self) -> &'static str;
    /// Install the lockdown for `plan` (atomic, idempotent).
    fn arm(&mut self, plan: &LockdownPlan) -> Result<()>;
    /// Replace the active lockdown with `plan` (atomic, never opens a gap).
    fn update(&mut self, plan: &LockdownPlan) -> Result<()>;
    /// Remove the lockdown. Only called on an explicit user `Disarm`.
    fn disarm(&mut self) -> Result<()>;
    /// Kernel-verified status.
    fn status(&self) -> Result<FirewallStatus>;
    /// Whether the kernel currently enforces our default-deny policy.
    fn is_armed_in_kernel(&self) -> Result<bool>;
}

/// The backend for the running OS.
pub fn platform_backend() -> Box<dyn FirewallBackend> {
    #[cfg(target_os = "linux")]
    {
        Box::new(linux::NftablesBackend::new())
    }
    #[cfg(target_os = "macos")]
    {
        Box::new(macos::PfBackend::default())
    }
    #[cfg(windows)]
    {
        Box::new(windows::WfpBackend::new())
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
    {
        Box::new(UnsupportedBackend)
    }
}

/// Backend for platforms without a firewall integration: refuses to arm so
/// the daemon can never believe it is protected.
#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
pub struct UnsupportedBackend;

#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
impl FirewallBackend for UnsupportedBackend {
    fn name(&self) -> &'static str {
        "unsupported"
    }
    fn arm(&mut self, _plan: &LockdownPlan) -> Result<()> {
        Err(vw_core::VwError::Unsupported("firewall lockdown"))
    }
    fn update(&mut self, _plan: &LockdownPlan) -> Result<()> {
        Err(vw_core::VwError::Unsupported("firewall lockdown"))
    }
    fn disarm(&mut self) -> Result<()> {
        Ok(())
    }
    fn status(&self) -> Result<FirewallStatus> {
        Ok(FirewallStatus::disarmed(self.name()))
    }
    fn is_armed_in_kernel(&self) -> Result<bool> {
        Ok(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn platform_backend_has_expected_name() {
        // Construction only: never touches the host firewall.
        let b = platform_backend();
        let expected = if cfg!(target_os = "linux") {
            "nftables"
        } else if cfg!(target_os = "macos") {
            "pf"
        } else if cfg!(windows) {
            "wfp"
        } else {
            "unsupported"
        };
        assert_eq!(b.name(), expected);
    }
}
