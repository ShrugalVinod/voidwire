# VoidWire

**A fail-closed, post-quantum, censorship-resistant VPN for macOS and Windows 11.**
Free out of the box (Cloudflare WARP), and free *private* with your own
Oracle Always-Free exit node.

- **Iron Dome kill-switch**: the firewall (macOS `pf`, Windows WFP, Linux `nftables`)
  blocks every non-tunnel packet *before* connecting and stays locked if the app
  crashes or is killed. Nothing flows until a live leak self-audit passes.
- **Post-quantum**: X25519 + ML-KEM-1024 hybrid pre-shared keys rotated every
  120 s on every VoidWire hop (WARP hops are classical WireGuard, and the UI says so).
- **Picks the best route for you**: VoidWire measures every gateway and transport
  (handshake time, RTT, loss, bandwidth, DPI interference) and chooses the fastest
  combination that keeps zero-leak guarantees. It re-checks when your network changes.
- **Gets through censorship**: AmneziaWG (disguised WireGuard), MASQUE over HTTP/3,
  TLS-WebSocket on port 443 with a decoy website, and DAITA traffic padding.
- **Private DNS**: an encrypted local resolver (Oblivious DoH / DoH / DoT) with an
  ad/tracker/malware Shield that also catches CNAME-cloaked trackers.
- **Fingerprint scrubbing**: TTL, TCP MSS and TCP timestamps are normalised.
- **Multi-hop**: entry and exit hops split trust — the entry never sees where you
  go, the exit never sees who you are.

## Install

Download from [Releases](https://github.com/ShrugalVinod/voidwire/releases):

| System | File |
|---|---|
| macOS (Apple Silicon) | `VoidWire_<version>_aarch64.dmg` |
| macOS (Intel) | `VoidWire_<version>_x64.dmg` |
| Windows 11 | `VoidWire_<version>_x64-setup.exe` (or `.msi`) |

**macOS**: open the `.dmg`, drag VoidWire to Applications and open it. Builds
are not notarized yet, so macOS blocks the first launch: open **System Settings →
Privacy & Security**, scroll to "VoidWire was blocked", click **Open Anyway** and
confirm. (On macOS 14 and older, right-click VoidWire → **Open** also works.)
If an older download (before v0.1.5) says *"VoidWire is damaged"*, download the
latest release, or run `xattr -cr /Applications/VoidWire.app` once in Terminal.
Then click **Install VoidWire service** and enter your password once (it installs
the background service that controls the firewall and tunnel).

**Windows 11**: run the installer. SmartScreen may say "Windows protected your PC"
for unsigned builds: **More info → Run anyway**. The installer registers the
VoidWire service and the Wintun driver.

## $0 quickstart

1. Open VoidWire → **Nodes → Get free WARP** (accept Cloudflare's terms).
2. Press **Connect**. Auto mode picks the fastest WARP endpoint and transport.

WARP is fast and has no data cap, but Cloudflare can see your real IP and it is
not post-quantum. For real privacy, add your own exit node:

## Use another VPN provider's servers (choose your country)

VoidWire can use any provider that hands out **WireGuard** configs: Proton VPN
(including the free plan), Mullvad, IVPN, Surfshark, Windscribe and others.
Providers with closed protocols (Hotspot Shield, X-VPN) cannot be used.

1. Download a WireGuard `.conf` from your provider for the country you want.
2. VoidWire → **Nodes → Import WireGuard config**: choose the file, give it a
   name (e.g. `Proton US`) and the country code.
3. Pick it in the gateway menu next to **Connect**. Tick **via WARP** to chain
   WARP → provider, so the provider never sees your real IP.

CLI: `voidwire nodes import-conf proton-us.conf --name "Proton US" --country US`,
then `voidwire up --gateway "Proton US"` (add `--profile multihop` to chain via WARP).
Shell hooks in configs (`PostUp`, etc.) are refused, and the config's DNS line is
ignored: DNS always goes through VoidWire's encrypted vault.

## Your own free exit node (Oracle Always Free)

```bash
voidwire cloud generate --provider oracle-free --out ./my-node
```

Follow `my-node/README.md` (OpenTofu/Terraform, or paste `cloud-init.yaml` into the
Oracle console when creating an Ampere A1 Ubuntu 24.04 instance). After ~3 minutes:

```bash
ssh ubuntu@<server-ip> sudo voidwire-node uri --state /run/voidwire --qr
```

Import the `voidwire://node/...` URI in VoidWire (Nodes → Import). Auto mode now
uses **WARP → your node** as a free two-hop circuit. The node runs RAM-only
(tmpfs state, no swap, no logs) and signs an attestation you can see with
`voidwire status --audit`.

Share your node with friends: `sudo voidwire-node invite --state /run/voidwire --bandwidth-limit 50Mbps --expires 30d`.
Friends import the `voidwire://f2f/...` link; their sessions use blind-signed
tokens, so your node cannot link them to the invite.

Other providers: `gcp-free` (only 1 GB/month free egress), `fly` (paid),
`docker`, `ssh` (any VPS).

## CLI

```bash
voidwire up                 # auto: best gateway + transport
voidwire up --profile stealth
voidwire status --audit     # live canary leak audit with proof table
voidwire panic              # rotate keys + exit, firewall stays locked
voidwire down --keep-lockdown
voidwire disarm             # remove the kill-switch
voidwire exec -- curl https://example.com   # Linux: isolated network namespace
voidwire tui                # terminal dashboard (P = panic)
```

## What "zero leaks" means here

VoidWire is designed so no packet can leave outside the tunnel: the firewall is
armed first, stays armed through crashes and reboots (boot lock), and traffic is
only released after a live audit (firewall state, physical-interface probes, DNS,
WebRTC STUN, IPv6, exit identity) passes. The Leak Gauntlet tests SIGKILL races,
Tunnelvision (CVE-2024-3661) rogue routes, hardcoded DNS, STUN exfiltration,
IPv6 and DPI signatures.

It cannot protect you from a compromised computer, browser fingerprinting and
logins that identify you, or an adversary watching both ends of the circuit.

## Build from source

```bash
cargo test --workspace
cargo build --release -p vw-daemon -p vw-cli -p vw-server
cd apps/desktop && npm ci && npm run sidecars && npm run tauri build
```

Privileged Linux gauntlet: `sudo -E cargo test -p vw-leakaudit --features privileged -- --test-threads=1`.
Docker cyber-range: `deploy/docker-testbed/run-range.sh`.
Architecture, wire formats and threat model: [ARCHITECTURE.md](ARCHITECTURE.md).

Releases: push a tag `vX.Y.Z`; GitHub Actions builds the `.dmg`/`.msi`/`.exe`
installers and the Linux node binaries.

License: AGPL-3.0-or-later.
