//! Linux: nftables lockdown, policy routing and network-namespace isolation.
//!
//! Rendering (`nft`, `policy`) compiles on every OS; the executor and the
//! `netns` module only on Linux.

pub mod nft;
pub mod policy;

#[cfg(target_os = "linux")]
mod backend;
#[cfg(target_os = "linux")]
pub mod netns;

#[cfg(target_os = "linux")]
pub use backend::NftablesBackend;
pub use nft::{parse_nft_table, render_nft, render_nft_teardown, NftKernelState};
pub use policy::{render_policy_routing, render_policy_teardown, Family};

/// Candidate locations of the tools used on Linux.
pub const NFT_PATHS: [&str; 3] = ["/usr/sbin/nft", "/sbin/nft", "/usr/bin/nft"];
pub const IP_PATHS: [&str; 4] = ["/usr/sbin/ip", "/sbin/ip", "/usr/bin/ip", "/bin/ip"];
