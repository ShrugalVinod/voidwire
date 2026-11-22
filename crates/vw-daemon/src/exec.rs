//! `voidwire exec` isolation (`Request::ExecPrepare`).
//!
//! Linux: an isolated network namespace (`vw_firewall::linux::netns`) whose
//! TUN is attached to the running engine as an extra device, so namespace
//! traffic goes through the same pipeline (gate, STUN, DNS vault, IPv6
//! policy, DAITA) and the same cascade. macOS / Windows: the lockdown is
//! system-wide (pf / WFP default-deny for every process), so no namespace is
//! needed and the ticket says so.

use vw_core::ipc::ExecTicket;
use vw_core::Result;

use crate::platform::Platform;
use crate::tunnel::ActiveTunnel;

/// Namespaces per tunnel.
pub const MAX_EXEC_NAMESPACES: usize = 8;

/// Isolation statement for platforms without per-process namespaces.
pub const SYSTEM_WIDE: &str =
    "system-wide lockdown: the kernel firewall (pf on macOS, WFP on Windows) \
blocks every process's traffic outside the audited tunnel, so the command runs under the same \
fail-closed guarantee without a separate namespace";

pub async fn prepare(platform: &dyn Platform, t: &mut ActiveTunnel) -> Result<ExecTicket> {
    if t.exec.len() >= MAX_EXEC_NAMESPACES {
        let (_, ns) = &t.exec[t.exec.len() - 1];
        return Ok(ExecTicket {
            netns: Some(ns.name.clone()),
            isolation: "isolated network namespace (reused; limit reached)".into(),
        });
    }
    let id = hex::encode(rand::random::<[u8; 4]>());
    match platform
        .exec_namespace(&id, (t.tun_v4.0, 32), t.mtu)
        .await?
    {
        Some(ns) => {
            let slot = t.mux.attach(ns.tun.clone());
            let name = ns.name.clone();
            t.exec.push((slot, ns));
            Ok(ExecTicket {
                netns: Some(name),
                isolation: "isolated network namespace: its only interface is a TUN read by the \
                            VoidWire engine (same pipeline and cascade as the tunnel)"
                    .into(),
            })
        }
        None => Ok(ExecTicket {
            netns: None,
            isolation: SYSTEM_WIDE.into(),
        }),
    }
}
