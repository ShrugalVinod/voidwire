//! macOS split default routes over the utun, plus host routes keeping the
//! pinned endpoints on the original gateway. Rendering and parsing compile
//! everywhere; `SplitRoutes::install` / `restore` run only on macOS.

use std::net::IpAddr;

use serde::{Deserialize, Serialize};

use crate::plan::split_default_prefixes;

/// Result of `route -n get default` (or `route -n get -inet6 default`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DefaultGateway {
    pub gateway: Option<IpAddr>,
    pub interface: Option<String>,
}

/// Parse `route -n get default` output.
pub fn parse_route_get(output: &str) -> DefaultGateway {
    let mut g = DefaultGateway::default();
    for line in output.lines() {
        let Some((k, v)) = line.trim().split_once(':') else {
            continue;
        };
        let v = v.trim();
        match k.trim() {
            "gateway" => {
                // Link-local v6 gateways carry a scope suffix (fe80::1%en0).
                let addr = v.split('%').next().unwrap_or(v);
                g.gateway = addr.parse().ok();
            }
            "interface" if !v.is_empty() => g.interface = Some(v.to_string()),
            _ => {}
        }
    }
    g
}

/// Where a route points.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RouteVia {
    Interface(String),
    Gateway(IpAddr),
}

/// One route added by VoidWire (persistable for crash recovery).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouteSpec {
    pub inet6: bool,
    /// `true` for `-host`, `false` for `-net`.
    pub host: bool,
    /// Destination in `route(8)` syntax (`0.0.0.0/1`, `198.51.100.7`).
    pub dest: String,
    pub via: RouteVia,
}

impl RouteSpec {
    fn args(&self, verb: &str) -> Vec<String> {
        let mut v: Vec<String> = vec!["-q".into(), "-n".into(), verb.into()];
        if self.inet6 {
            v.push("-inet6".into());
        }
        v.push(if self.host { "-host" } else { "-net" }.into());
        v.push(self.dest.clone());
        match &self.via {
            RouteVia::Interface(i) => {
                v.push("-interface".into());
                v.push(i.clone());
            }
            RouteVia::Gateway(g) => v.push(g.to_string()),
        }
        v
    }

    /// Arguments for `route` (`route -q -n add ...`).
    pub fn add_args(&self) -> Vec<String> {
        self.args("add")
    }

    pub fn delete_args(&self) -> Vec<String> {
        self.args("delete")
    }
}

fn via_for(g: &DefaultGateway) -> Option<RouteVia> {
    match (&g.gateway, &g.interface) {
        (Some(gw), _) => Some(RouteVia::Gateway(*gw)),
        (None, Some(i)) => Some(RouteVia::Interface(i.clone())),
        (None, None) => None,
    }
}

/// Routes to install, in order: pinned host routes via the original gateway
/// first (so the endpoint stays reachable), then the split default routes.
pub fn render_split_routes(
    tun: &str,
    pinned: &[IpAddr],
    gw4: &DefaultGateway,
    gw6: Option<&DefaultGateway>,
    include_v6: bool,
) -> Vec<RouteSpec> {
    let mut pins: Vec<IpAddr> = pinned.to_vec();
    pins.sort();
    pins.dedup();
    let mut v = Vec::new();
    for ip in pins {
        let gw = if ip.is_ipv4() { Some(gw4) } else { gw6 };
        if let Some(via) = gw.and_then(via_for) {
            v.push(RouteSpec {
                inet6: ip.is_ipv6(),
                host: true,
                dest: ip.to_string(),
                via,
            });
        }
    }
    for c in split_default_prefixes(include_v6) {
        v.push(RouteSpec {
            inet6: !c.is_ipv4(),
            host: false,
            dest: c.to_string(),
            via: RouteVia::Interface(tun.to_string()),
        });
    }
    v
}

/// Routes VoidWire added; `restore` removes them in reverse order.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SplitRoutes {
    pub added: Vec<RouteSpec>,
}

#[cfg(target_os = "macos")]
const ROUTE: &str = "/sbin/route";

#[cfg(target_os = "macos")]
impl SplitRoutes {
    fn gateway(inet6: bool) -> vw_core::Result<DefaultGateway> {
        let args: &[&str] = if inet6 {
            &["-n", "get", "-inet6", "default"]
        } else {
            &["-n", "get", "default"]
        };
        let out = crate::cmd::run(ROUTE, args, None)?;
        Ok(if out.success {
            parse_route_get(&out.stdout)
        } else {
            DefaultGateway::default()
        })
    }

    /// Discover the original gateways and install split routes over `tun`.
    pub fn install(tun: &str, pinned: &[IpAddr], include_v6: bool) -> vw_core::Result<Self> {
        crate::plan::validate_ifname(tun)?;
        let gw4 = Self::gateway(false)?;
        let gw6 = if include_v6 || pinned.iter().any(IpAddr::is_ipv6) {
            Some(Self::gateway(true)?)
        } else {
            None
        };
        let mut me = Self::default();
        for spec in render_split_routes(tun, pinned, &gw4, gw6.as_ref(), include_v6) {
            // Replace a stale copy left by a crash; absence is fine.
            let del = spec.delete_args();
            let del: Vec<&str> = del.iter().map(String::as_str).collect();
            crate::cmd::run(ROUTE, &del, None)?;
            let add = spec.add_args();
            let add: Vec<&str> = add.iter().map(String::as_str).collect();
            if let Err(e) = crate::cmd::run_ok(ROUTE, &add, None) {
                let _ = me.restore();
                return Err(e);
            }
            me.added.push(spec);
        }
        tracing::debug!(routes = me.added.len(), "split routes installed");
        Ok(me)
    }

    /// Remove every route we added (best effort for routes already gone).
    pub fn restore(&mut self) -> vw_core::Result<()> {
        while let Some(spec) = self.added.pop() {
            let del = spec.delete_args();
            let del: Vec<&str> = del.iter().map(String::as_str).collect();
            crate::cmd::run(ROUTE, &del, None)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_route_get() {
        let out = "   route to: default\ndestination: default\n       mask: default\n    gateway: 192.168.1.1\n  interface: en0\n      flags: <UP,GATEWAY,DONE,STATIC,PRCLONING>\n";
        let g = parse_route_get(out);
        assert_eq!(g.gateway, Some("192.168.1.1".parse().unwrap()));
        assert_eq!(g.interface.as_deref(), Some("en0"));
        let g6 = parse_route_get("    gateway: fe80::1%en0\n  interface: en0\n");
        assert_eq!(g6.gateway, Some("fe80::1".parse().unwrap()));
    }

    #[test]
    fn renders_split_and_host_routes() {
        let gw = DefaultGateway {
            gateway: Some("192.168.1.1".parse().unwrap()),
            interface: Some("en0".into()),
        };
        let r = render_split_routes("utun4", &["198.51.100.7".parse().unwrap()], &gw, None, true);
        let lines: Vec<String> = r.iter().map(|s| s.add_args().join(" ")).collect();
        assert_eq!(
            lines,
            [
                "-q -n add -host 198.51.100.7 192.168.1.1",
                "-q -n add -net 0.0.0.0/1 -interface utun4",
                "-q -n add -net 128.0.0.0/1 -interface utun4",
                "-q -n add -inet6 -net ::/1 -interface utun4",
                "-q -n add -inet6 -net 8000::/1 -interface utun4",
            ]
        );
        assert_eq!(
            r[1].delete_args().join(" "),
            "-q -n delete -net 0.0.0.0/1 -interface utun4"
        );
    }

    #[test]
    fn interface_only_gateway() {
        let gw = DefaultGateway {
            gateway: None,
            interface: Some("ppp0".into()),
        };
        let r = render_split_routes(
            "utun4",
            &["198.51.100.7".parse().unwrap()],
            &gw,
            None,
            false,
        );
        assert_eq!(
            r[0].add_args().join(" "),
            "-q -n add -host 198.51.100.7 -interface ppp0"
        );
        assert_eq!(r.len(), 3);
    }
}
