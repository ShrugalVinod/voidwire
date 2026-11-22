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
- [x] vw-dns (42 tests): vault, DoH, DoT, ODoH, Shield + CNAME uncloaking, interception

## FreeCloud & Server
- [x] vw-freecloud: WARP registrar, HTTPS mark/pin client, cloud-init/OpenTofu (Oracle, GCP, Fly, Docker, SSH)
- [x] vw-freecloud: F2F invite redemption client, arti Tor feature
- [x] vw-server: voidwire-node listeners, admission, NAT, decoy, attestation, invite CLI

## Daemon, CLI, TUI
- [x] vw-daemon: IPC server, FSM driver, pipeline, optimizer, launchd / Windows service
- [x] vw-cli: up/down/status --audit/panic/exec/cloud/tui
- [x] vw-tui: dashboard panels + panic hotkey (23 tests, Windows clippy clean)

## Desktop
- [x] apps/desktop (bundle verified with stand-in sidecars; needs real daemon): Tauri v2 + React + Tailwind UI, IPC bridge, map, auditor, global shortcut, daemon installer

## Gauntlet & release
- [x] vw-leakaudit: canary verifier, mocked gauntlet (tests 1–6), privileged netns gauntlet
- [x] deploy/docker-testbed, deploy/free-tier
- [x] GitHub Actions: CI (mac, windows, linux + privileged gauntlet), release (dmg, msi/nsis)
- [x] README.md
- [x] Workspace fmt + clippy -D warnings + tests green

## Verification (2026-11-22)
- macOS: fmt clean, clippy -D warnings clean (workspace, all targets), 384 tests pass.
- Linux target: vw-leakaudit privileged gauntlet type-checks; runs as root in CI.
- Not yet run for real: OS firewall/route/DNS/TUN paths (need root), Windows build (CI), arti Tor bridge (not implemented).
