# PROGRESS.md

Update after every milestone. `[x]` = done and verified (fmt + clippy + tests).

## Foundation
- [x] Rust toolchain (stable 1.100) + windows/x64-darwin targets
- [x] PROMPT.md, CLAUDE.md, ARCHITECTURE.md
- [x] Workspace scaffold (12 crates)
- [x] vw-core: consts, errors, secrets, configs, URIs, Iron Dome FSM, packet parsing, IPC, transport trait, telemetry

## Crypto & WireGuard
- [x] vw-crypto (39 tests): HKDF-BLAKE3, hybrid X25519+ML-KEM-1024, Ed25519 identities, VWCP, blind RSA tokens
- [x] vw-wg (57 tests incl. 7 boringtun interop): Noise_IKpsk2 engine, timers, cookies, reserved bytes, VirtualTunChannel, OS TUN, cascade, sanitizer, DAITA padding, boringtun interop test

## Stealth
- [x] vw-stealth (34 tests): NativeUdp, AmneziaWG, MASQUE/QUIC, TLS-WS, DAITA wrapper, anti-signature tests

## Firewall & DNS
- [x] vw-firewall (48 tests; macOS/Windows/Linux clippy clean; kernel execution untested until gauntlet): trait, nftables + policy routing + netns, pf anchor, WFP, STUN filter
- [ ] vw-dns: vault, DoH, DoT, ODoH, Shield + CNAME uncloaking, interception

## FreeCloud & Server
- [x] vw-freecloud: WARP registrar, HTTPS mark/pin client, cloud-init/OpenTofu (Oracle, GCP, Fly, Docker, SSH)
- [ ] vw-freecloud: F2F invite redemption client, arti Tor feature
- [ ] vw-server: voidwire-node listeners, admission, NAT, decoy, attestation, invite CLI

## Daemon, CLI, TUI
- [ ] vw-daemon: IPC server, FSM driver, pipeline, optimizer, launchd / Windows service
- [ ] vw-cli: up/down/status --audit/panic/exec/cloud/tui
- [x] vw-tui: dashboard panels + panic hotkey (23 tests, Windows clippy clean)

## Desktop
- [ ] apps/desktop: Tauri v2 + React + Tailwind UI, IPC bridge, map, auditor, global shortcut, daemon installer

## Gauntlet & release
- [ ] vw-leakaudit: canary verifier, mocked gauntlet (tests 1–6), privileged netns gauntlet
- [ ] deploy/docker-testbed, deploy/free-tier
- [ ] GitHub Actions: CI (mac, windows, linux + privileged gauntlet), release (dmg, msi/nsis)
- [ ] README.md
- [ ] Workspace fmt + clippy -D warnings + tests green
