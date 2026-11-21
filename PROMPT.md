# PROMPT.md — Source specification for VoidWire

This file preserves the original build specification so work can resume across
context windows. Section A is the user's own adjustments, which take precedence
over the original spec where they conflict. Section B is the original spec.

## A. User adjustments (take precedence)

1. **Primary targets are macOS (Apple Silicon + Intel) and Windows 11 (x64).**
   Linux stays supported (server node, Leak Gauntlet netns range), but client
   UX, firewall backends, packaging and CI focus on macOS `pf`/`utun` and
   Windows WFP/Wintun.
2. **Downloadable app from GitHub**: pushing a tag must produce installable
   artifacts (macOS `.dmg`, Windows `.msi`/NSIS `.exe`) via GitHub Actions
   Releases, bundling the GUI, the `voidwired` daemon and the `voidwire` CLI.
3. **All features of the original spec are kept**; they are executed as one
   continuous build rather than gated phases (PROGRESS.md still tracks
   milestones).
4. **Auto-optimisation, not location picking**: VoidWire must measure available
   gateways (WARP anycast endpoints, user nodes, F2F exits) and transports
   (Native UDP, AmneziaWG, MASQUE/QUIC, TLS-WS) with real probes (RTT, loss,
   handshake success, DPI interference, throughput) and automatically pick the
   fastest configuration that keeps the zero-leak guarantees, re-evaluating
   while connected. `--country` remains an optional override, not the default.
5. Product name: **VoidWire**.
6. Goal: zero leaks (fail-closed), no unnecessary data caps (use free backends
   without artificial limits), best settings chosen per user and network.

## B. Original specification (summary of the pasted Grand Unified Specification)

### 0. Prime directives
1. No placeholders/stubs (`todo!()`, `unimplemented!()`, `// TODO`, fake sleeps,
   mocked returns) in production crates.
2. Gate: `cargo fmt --check`, `cargo clippy --workspace --all-targets -- -D warnings`,
   `cargo test --workspace` clean.
3. Secrets implement `Zeroize` + `ZeroizeOnDrop`; never log IPs, DNS queries,
   SNI or key material at info/warn/error.
4. Fail-closed: on panic, SIGKILL, network loss or failed rotation the firewall
   stays locked (drop all non-tunnel egress) until the user disarms it.
5. Persistent agent memory: `CLAUDE.md`, `ARCHITECTURE.md`, `PROGRESS.md`.
6. Use subagents for orthogonal crates, integrate + verify in main thread.

### 1. Workspace topology (edition 2021, resolver 2)
```
voidwire/
├── CLAUDE.md  ARCHITECTURE.md  PROGRESS.md  Cargo.toml
├── crates/
│   ├── vw-core/       shared types, config schemas, errors, IPC protocol, state machine
│   ├── vw-crypto/     X25519 + ML-KEM-1024 hybrid PQ, ChaCha20Poly1305, Ed25519, blind tokens
│   ├── vw-wg/         userspace WireGuard + nested multi-hop + MSS/Timestamp/TTL scrubber
│   ├── vw-stealth/    Native UDP, AmneziaWG morpher, MASQUE (QUIC), TLS-WS, DAITA chaff
│   ├── vw-firewall/   fail-closed kill-switch (Linux nftables+netns, macOS pf, Windows WFP) + STUN filter
│   ├── vw-dns/        loopback encrypted stub resolver (DoH, DoT, ODoH RFC 9230), CNAME-uncloaking shield
│   ├── vw-freecloud/  WARP registrar, F2F invite mesh, Arti bridge, free-VPS cloud-init generator
│   ├── vw-leakaudit/  canary self-verifier + netns Adversarial Leak Gauntlet
│   ├── vw-daemon/     privileged service `voidwired`, authenticated Unix/NamedPipe RPC
│   ├── vw-server/     RAM-only zero-log exit/relay `voidwire-node` with attestation
│   ├── vw-cli/        `voidwire` CLI incl. `voidwire exec <cmd>`
│   └── vw-tui/        ratatui dashboard (`voidwire tui`)
├── apps/desktop/      Tauri v2 + React + TS + Tailwind
└── deploy/
    ├── free-tier/       Oracle Always-Free / GCP / Fly.io RAM-only deployment + cloud-init
    └── docker-testbed/  simulated ISP + rogue DHCP (CVE-2024-3661) + DPI lab
```

### 2. Subsystems
**2.1 Crypto & WG**: userspace WireGuard (Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s)
over tun devices and in-memory `VirtualTunChannel`. Hybrid PQ sidecar handshake
X25519 + ML-KEM-1024 (FIPS 203); `psk = HKDF-BLAKE3(x25519_ss || mlkem_ss || transcript_hash)`,
rotated every 120 s. Userspace multi-hop: outer session to Hop 1, inner session
over the outer's decrypted stream to Hop 2. Packet sanitizer: MSS clamp (1280
baseline for nested+stealth), TCP timestamp option (kind 8) → NOPs with checksum
fix, TTL/Hop Limit normalised to 64.

**2.2 Iron Dome firewall**: FSM `Disarmed → ArmingBootLock → Handshaking →
CanaryAuditing → TunnelActive → KeyRotating → FailsafeLockdown → Disarming`.
No app traffic before CanaryAuditing succeeds. Linux: `table inet voidwire_lockdown`,
priority filter-10, policy drop on output/forward, allow lo, vw0, and
`meta mark 0x564f4944` only to the pinned entry endpoint ip:port; drop non-tunnel
IPv6, RA (strict), mDNS/LLMNR 5353/5355, NetBIOS 137/138. Tunnelvision defence:
`ip rule pref 50` non-marked → table 51820 (`default dev vw0`) + `suppress_prefixlength 0`.
`voidwire exec` isolated netns `vw-ns-<id>`. macOS pf anchor `com.voidwire.lockdown`
with transactions. Windows WFP (`FwpmEngineOpen0`, persistent/boot-time filters,
own sublayer) behind `cfg(windows)`. STUN filter: magic cookie `0x2112A442`
(userspace + nft `@th,96,32 == 0x2112a442`), `block_webrtc_stun = true` default.

**2.3 Stealth**: async `StealthTransport` trait. NativeUdp with SO_MARK; AmneziaWG
(Jc/Jmin/Jmax junk, S1/S2 padding, H1..H4 type remap); MASQUE CONNECT-UDP
(RFC 9298) over quinn + rustls, ALPN h3, QUIC datagrams (RFC 9221), migration;
TLS-WS on TCP 443 (tokio-tungstenite + rustls) with realistic headers and SNI;
DAITA wrapper: size buckets {128,256,512,1024,1280} + Poisson chaff.

**2.4 DNS vault**: bind 100.64.0.1:53 and [fd00:564f:4944::1]:53; redirect all
port-53 in tunnel. Upstreams DoH, DoT, ODoH (RFC 9230, HPKE) via the tunnel.
Aho-Corasick/trie blocker with wildcard + CNAME uncloaking (synthesize 0.0.0.0/::
or NXDOMAIN). Category counters only, no persistent history.

**2.5 FreeCloud**: WARP anonymous registration (`/v0a2158/reg`), store keypair,
addresses, endpoint; WARP `reserved` 3-byte client id handling in vw-wg.
WARP entry → self-hosted/friend exit 2-hop. `voidwire cloud init/generate` for
Oracle Always Free (A1), GCP e2-micro, Fly.io: cloud-init, OpenTofu, SSH bootstrap,
RAM-only (tmpfs, swapoff, journald Storage=none, BBR), all listeners, outputs
`voidwire://node/...` URI + QR. F2F invites: `voidwire-node invite --bandwidth-limit
50Mbps --expires 30d` → Ed25519-signed blinded capability token `voidwire://f2f/...`.
Optional arti Tor exit (feature flag).

**2.6 Server `voidwire-node`**: static binary < 15 MB, multi-listener (UDP WG/AWG/
MASQUE, TCP 443 TLS-WS with decoy website), in-memory NAT44/NAT66, signed runtime
attestation (swap off, logging off, binary BLAKE3, uptime).

**2.7 UX**: CLI `up [--profile warp|multihop|stealth|f2f] [--country CC]`,
`down [--keep-lockdown]`, `status --audit`, `panic` (< 100 ms rotation, firewall
stays locked), `exec -- <cmd>`, `cloud generate --provider oracle-free|gcp-free|fly`.
TUI (ratatui+crossterm): route map, Rx/Tx sparklines, crypto suite, firewall
matrix (IPv4, IPv6, DNS, STUN, CVE-2024-3661), shield counter, `P` = panic.
Desktop (Tauri v2): #07090E bg, #00F0FF accent, #10B981 verified, #EF4444 lockdown;
SVG topology map with RTT; modes Instant Free (WARP), Ghost Multi-Hop, Chameleon
Stealth, Max Anonymity; live leak self-auditor; Ctrl/Cmd+Shift+X panic.

### 3. Leak Gauntlet
Mocked pipeline tests (no root) + privileged netns/Docker range:
1. SIGKILL crash race — 0 cleartext packets to 203.0.113.99 on eth_isp.
2. Tunnelvision rogue routes (/1, /8 via rogue gw) — 0 packets to rogue gw.
3. Hardcoded DNS (8.8.8.8:53, 1.1.1.1:853, [2001:4860:4860::8888]:53) blocked/intercepted.
4. STUN Binding Request dropped + counter incremented.
5. IPv6 egress on IPv4-only exit dropped, zero leakage.
6. Wire capture under AmneziaWG/MASQUE has no 0x01000000 signature; inner SYN
   MSS clamped and timestamps scrubbed.

### 4. Phases (now executed as one continuous build)
1 Foundation · 2 PQ crypto + WG · 3 Stealth + DAITA · 4 Firewall + DNS ·
5 FreeCloud + server · 6 Daemon/CLI/TUI · 7 Tauri desktop · 8 Gauntlet,
docker range, zero warnings, README.
