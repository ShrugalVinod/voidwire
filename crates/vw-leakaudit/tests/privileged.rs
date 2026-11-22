//! Adversarial Leak Gauntlet — privileged Linux part.
//!
//! Builds a two-namespace cyber-range (client ⇄ `eth_isp` ⇄ ISP/observer),
//! applies VoidWire's real nftables ruleset and policy routing inside the
//! client namespace, then attacks it and counts cleartext packets captured on
//! `eth_isp`. Requires root, `ip`, `nft`, `tcpdump` and `bash`; enabled with
//! `--features privileged` and skipped (with a message) when not root.
#![cfg(all(target_os = "linux", feature = "privileged"))]

use std::net::Ipv4Addr;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use vw_core::config::FirewallSettings;
use vw_firewall::linux::policy::{render_policy_routing, Family};
use vw_firewall::{LockdownPlan, PinnedEndpoint, TunnelIface};

const CLIENT: &str = "vwg-client";
const ISP: &str = "vwg-isp";
/// Packets the client itself sends on the subscriber link (IPv4, or IPv6 from
/// its global address), excluding the daemon's pinned tunnel endpoint. ARP and
/// link-local neighbour discovery carry no user data and are not counted.
const CLIENT_EGRESS: &str =
    "((ip and src host 198.51.100.2) or (ip6 and src net 2001:db8:77::/64)) \
     and not (udp port 51820 and host 198.51.100.1)";

fn sh(ns: Option<&str>, cmd: &str) -> bool {
    let status = match ns {
        Some(n) => Command::new("ip")
            .args(["netns", "exec", n, "bash", "-c", cmd])
            .status(),
        None => Command::new("bash").args(["-c", cmd]).status(),
    };
    status.is_ok_and(|s| s.success())
}

fn must(ns: Option<&str>, cmd: &str) {
    assert!(sh(ns, cmd), "command failed: {cmd}");
}

struct Range;

impl Range {
    fn up() -> Self {
        let _ = Self::teardown();
        for cmd in [
            format!("ip netns add {CLIENT}"),
            format!("ip netns add {ISP}"),
            format!("ip link add eth0 netns {CLIENT} type veth peer name eth_isp netns {ISP}"),
        ] {
            must(None, &cmd);
        }
        for cmd in [
            "ip link set lo up",
            "ip link set eth0 up",
            "ip addr add 198.51.100.2/24 dev eth0",
            "ip -6 addr add 2001:db8:77::2/64 dev eth0 nodad",
            "ip route add default via 198.51.100.1",
            "ip -6 route add default via 2001:db8:77::1",
            "ip link add vw0 type dummy && ip link set vw0 up",
            "ip addr add 100.96.0.2/12 dev vw0",
        ] {
            must(Some(CLIENT), cmd);
        }
        for cmd in [
            "ip link set lo up",
            "ip link set eth_isp up",
            "ip addr add 198.51.100.1/24 dev eth_isp",
            "ip -6 addr add 2001:db8:77::1/64 dev eth_isp nodad",
            "ip addr add 203.0.113.99/32 dev lo",
            "ip addr add 8.8.8.8/32 dev lo",
            "ip addr add 1.1.1.1/32 dev lo",
        ] {
            must(Some(ISP), cmd);
        }
        Range
    }

    fn teardown() -> bool {
        sh(
            None,
            &format!("ip netns del {CLIENT} 2>/dev/null; ip netns del {ISP} 2>/dev/null; true"),
        )
    }

    fn plan() -> LockdownPlan {
        let mut plan = LockdownPlan::new(FirewallSettings::default());
        plan.pinned = vec![PinnedEndpoint::udp("198.51.100.1:51820".parse().unwrap())];
        plan.tunnel = Some(TunnelIface {
            name: "vw0".into(),
            luid: None,
            v4: Some((Ipv4Addr::new(100, 96, 0, 2), 12)),
            v6: None,
        });
        plan
    }

    fn arm_script() -> String {
        let plan = Self::plan();
        let mut s = format!(
            "nft -f - <<'NFT'\n{}\nNFT\n",
            vw_firewall::linux::render_nft(&plan)
        );
        for fam in [Family::V4, Family::V6] {
            for args in render_policy_routing(&plan, fam) {
                s.push_str("ip ");
                s.push_str(&args.join(" "));
                s.push_str(" || exit 1\n");
            }
        }
        s
    }

    /// Start a capture on the ISP side of the subscriber link.
    fn capture(filter: &str) -> (Child, String) {
        let file = format!("/tmp/vwg-{}-{}.pcap", std::process::id(), rand_tag());
        let child = Command::new("ip")
            .args([
                "netns", "exec", ISP, "tcpdump", "-i", "eth_isp", "-nn", "-U", "-w", &file, filter,
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("tcpdump");
        std::thread::sleep(Duration::from_millis(800));
        (child, file)
    }

    fn count(cap: (Child, String)) -> usize {
        Self::packets(cap).len()
    }

    /// Stop the capture and return one summary line per captured packet.
    fn packets(mut cap: (Child, String)) -> Vec<String> {
        std::thread::sleep(Duration::from_millis(500));
        let _ = Command::new("kill")
            .args(["-INT", &cap.0.id().to_string()])
            .status();
        let _ = cap.0.wait();
        let out = Command::new("tcpdump")
            .args(["-nn", "-r", &cap.1])
            .stderr(Stdio::null())
            .output()
            .expect("tcpdump -r");
        let _ = std::fs::remove_file(&cap.1);
        String::from_utf8_lossy(&out.stdout)
            .lines()
            .map(str::to_string)
            .collect()
    }
}

impl Drop for Range {
    fn drop(&mut self) {
        Self::teardown();
    }
}

fn rand_tag() -> u32 {
    rand::random()
}

fn is_root() -> bool {
    Command::new("id")
        .arg("-u")
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim() == "0")
        .unwrap_or(false)
}

#[test]
fn leak_gauntlet_netns() {
    if !is_root() {
        eprintln!("skipping privileged gauntlet: not root");
        return;
    }
    let _range = Range::up();
    // Sanity: without the lockdown the observer IS reachable (proves the range works).
    let cap = Range::capture("host 203.0.113.99");
    must(Some(CLIENT), "echo probe > /dev/udp/203.0.113.99/9999");
    assert!(
        Range::count(cap) > 0,
        "range broken: unprotected packet not captured"
    );

    // Test 1: SIGKILL crash race. The armer process installs the rules and is
    // killed with SIGKILL while a flood runs; rules must persist.
    let script = Range::arm_script();
    let mut armer = Command::new("ip")
        .args(["netns", "exec", CLIENT, "bash", "-c"])
        .arg(format!("{script}\nsleep 600"))
        .spawn()
        .expect("armer");
    std::thread::sleep(Duration::from_secs(2));
    let cap = Range::capture(CLIENT_EGRESS);
    let mut flood = Command::new("ip")
        .args(["netns", "exec", CLIENT, "bash", "-c"])
        .arg("end=$((SECONDS+6)); while [ $SECONDS -lt $end ]; do echo x > /dev/udp/203.0.113.99/9999 2>/dev/null; timeout 0.2 bash -c '</dev/tcp/203.0.113.99/80' 2>/dev/null; done")
        .spawn()
        .expect("flood");
    std::thread::sleep(Duration::from_secs(2));
    armer.kill().expect("SIGKILL armer");
    let _ = armer.wait();
    let _ = flood.wait();
    let leaked = Range::packets(cap);
    assert!(
        leaked.is_empty(),
        "Test 1: cleartext escaped around SIGKILL:\n{}",
        leaked.join("\n")
    );
    assert!(
        sh(
            Some(CLIENT),
            "nft list table inet voidwire_lockdown >/dev/null"
        ),
        "lockdown table vanished after SIGKILL"
    );

    // Test 2: Tunnelvision rogue routes onto the physical interface.
    must(
        Some(CLIENT),
        "ip route add 1.0.0.0/8 via 198.51.100.1 dev eth0; ip route add 0.0.0.0/1 via 198.51.100.1 dev eth0; ip route add 203.0.113.0/24 via 198.51.100.1 dev eth0",
    );
    let cap = Range::capture(CLIENT_EGRESS);
    for _ in 0..20 {
        sh(
            Some(CLIENT),
            "echo x > /dev/udp/1.1.1.1/9999; echo x > /dev/udp/203.0.113.99/9999",
        );
    }
    let leaked = Range::packets(cap);
    assert!(
        leaked.is_empty(),
        "Test 2: rogue routes pulled traffic to eth_isp:\n{}",
        leaked.join("\n")
    );

    // Test 3: hardcoded DNS / DoT.
    let cap = Range::capture(
        "((ip and src host 198.51.100.2) or (ip6 and src net 2001:db8:77::/64)) and (port 53 or port 853)",
    );
    for _ in 0..10 {
        sh(
            Some(CLIENT),
            "echo q > /dev/udp/8.8.8.8/53; timeout 0.3 bash -c '</dev/tcp/1.1.1.1/853'",
        );
        sh(Some(CLIENT), "echo q > /dev/udp/2001:db8:77::1/53");
    }
    let leaked = Range::packets(cap);
    assert!(
        leaked.is_empty(),
        "Test 3: DNS left outside the tunnel:\n{}",
        leaked.join("\n")
    );

    // Test 4: kernel accepted the STUN payload expression.
    let table = Command::new("ip")
        .args([
            "netns",
            "exec",
            CLIENT,
            "nft",
            "list",
            "table",
            "inet",
            "voidwire_lockdown",
        ])
        .output()
        .expect("nft list");
    let table = String::from_utf8_lossy(&table.stdout);
    assert!(
        table.contains("0x2112a442"),
        "Test 4: STUN rule missing:\n{table}"
    );

    // Test 5: IPv6 egress on an IPv4-only tunnel.
    let cap = Range::capture("ip6");
    for _ in 0..10 {
        sh(Some(CLIENT), "echo x > /dev/udp/2001:db8:77::1/9999; timeout 0.3 bash -c '</dev/tcp/2001:db8:77::1/443'");
    }
    let leaked: usize = Range::count(cap);
    // Neighbour discovery from the kernel itself is link-local signalling, not
    // user data; the filter `ip6` would include it, so require no packets with
    // our global source address instead.
    let cap = Range::capture("ip6 src 2001:db8:77::2 and not icmp6");
    for _ in 0..10 {
        sh(Some(CLIENT), "echo x > /dev/udp/2001:db8:77::1/9999");
    }
    assert_eq!(
        Range::count(cap),
        0,
        "Test 5: IPv6 user traffic leaked ({leaked} ip6 frames total)"
    );
}
