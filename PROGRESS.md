# PROGRESS.md

Update after every milestone. `[x]` = done and verified (fmt + clippy + tests).

## Foundation
- [x] Rust toolchain (stable 1.100) + windows/x64-darwin targets
- [x] PROMPT.md, CLAUDE.md, ARCHITECTURE.md
- [ ] Workspace scaffold (12 crates)
- [ ] vw-core: consts, errors, secrets, configs, URIs, Iron Dome FSM, packet parsing, IPC, transport trait, telemetry

## Crypto & WireGuard
- [ ] vw-crypto: HKDF-BLAKE3, hybrid X25519+ML-KEM-1024, Ed25519 identities, VWCP, blind RSA tokens
- [ ] vw-wg: Noise_IKpsk2 engine, timers, cookies, reserved bytes, VirtualTunChannel, OS TUN, cascade, sanitizer, DAITA padding, boringtun interop test

## Stealth
- [ ] vw-stealth: NativeUdp, AmneziaWG, MASQUE/QUIC, TLS-WS, DAITA wrapper, anti-signature tests

## Firewall & DNS
- [ ] vw-firewall: trait, nftables + policy routing + netns, pf anchor, WFP, STUN filter
- [ ] vw-dns: vault, DoH, DoT, ODoH, Shield + CNAME uncloaking, interception

## FreeCloud & Server
- [ ] vw-freecloud: WARP registrar, F2F invites, cloud-init/OpenTofu (Oracle, GCP, Fly), arti feature
- [ ] vw-server: voidwire-node listeners, admission, NAT, decoy, attestation, invite CLI

## Daemon, CLI, TUI
- [ ] vw-daemon: IPC server, FSM driver, pipeline, optimizer, launchd / Windows service
- [ ] vw-cli: up/down/status --audit/panic/exec/cloud/tui
- [ ] vw-tui: dashboard panels + panic hotkey

## Desktop
- [ ] apps/desktop: Tauri v2 + React + Tailwind UI, IPC bridge, map, auditor, global shortcut, daemon installer

## Gauntlet & release
- [ ] vw-leakaudit: canary verifier, mocked gauntlet (tests 1–6), privileged netns gauntlet
- [ ] deploy/docker-testbed, deploy/free-tier
- [ ] GitHub Actions: CI (mac, windows, linux + privileged gauntlet), release (dmg, msi/nsis)
- [ ] README.md
- [ ] Workspace fmt + clippy -D warnings + tests green
