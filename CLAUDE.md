# CLAUDE.md — VoidWire workspace guide

VoidWire is a fail-closed, post-quantum, censorship-resistant VPN suite in Rust
(client daemon, CLI, TUI, Tauri v2 desktop app, and a RAM-only exit node).
Primary client targets: **macOS (arm64 + x64) and Windows 11 (x64)**. Linux is
supported for the server node and for the privileged Leak Gauntlet.

Read `PROMPT.md` (spec), `ARCHITECTURE.md` (contracts and wire formats) and
`PROGRESS.md` (what is done) before changing anything.

## Build & verify

```bash
source "$HOME/.cargo/env"
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
# Windows type-check from macOS (crates without C build deps):
cargo clippy -p vw-core -p vw-firewall --target x86_64-pc-windows-msvc -- -D warnings
# Desktop app
cd apps/desktop && npm ci && npm run build && npm run tauri build
```

Privileged gauntlet (Linux root only, runs in CI): `sudo -E cargo test -p vw-leakaudit --features privileged -- --test-threads=1`.

## Crate map (dependency direction is strictly downward)

| crate | role | internal deps |
|---|---|---|
| vw-core | types, configs, secrets, IPC, Iron Dome FSM, packet parsing, `StealthTransport` trait | — |
| vw-crypto | hybrid X25519+ML-KEM-1024, HKDF-BLAKE3, Ed25519 identities, blind tokens, VWCP handshake | core |
| vw-wg | Noise_IKpsk2 WireGuard engine, VirtualTunChannel, cascade, sanitizer, DAITA padding | core, crypto |
| vw-stealth | NativeUdp, AmneziaWG, MASQUE/QUIC, TLS-WS transports, DAITA chaff wrapper | core |
| vw-firewall | `FirewallBackend` (nftables / pf / WFP), policy routing, netns, STUN filter | core |
| vw-dns | DNS vault, DoH/DoT/ODoH, Shield + CNAME uncloaking, packet interception | core |
| vw-freecloud | WARP registrar, F2F tokens, cloud-init/OpenTofu generators, optional arti | core, crypto |
| vw-server | `voidwire-node` exit/relay daemon | core, crypto, wg, stealth, freecloud |
| vw-daemon | `voidwired` privileged service, packet pipeline, optimizer, IPC server | all client crates |
| vw-leakaudit | canary verifier + Leak Gauntlet | core, wg, firewall, dns, stealth |
| vw-tui | ratatui dashboard | core |
| vw-cli | `voidwire` binary | core, freecloud, tui |
| apps/desktop | Tauri v2 + React shell over the IPC protocol | core (via src-tauri) |

## Invariants (never violate)

1. **No stubs in production code**: no `todo!()`, `unimplemented!()`, `// TODO`,
   fake sleeps or mocked returns. Platform code for other OSes lives behind
   `#[cfg(target_os = ...)]` and is real.
2. **Secrets**: every private key, PSK, token secret and session key is held in
   `vw_core::secret::{Secret, SecretVec}` or a type deriving `Zeroize` +
   `ZeroizeOnDrop`. `Debug` must redact.
3. **Logging**: never log IP addresses, ports of remote peers, DNS names, SNI or
   key material at `info`/`warn`/`error`. Use `debug`/`trace` only, and prefer
   `vw_core::redact` helpers.
4. **Fail-closed**: firewall state is kernel-persistent (nftables table, pf
   anchor, WFP persistent filters). A daemon crash must leave egress blocked.
   Only an explicit `Disarm` IPC request removes the lockdown.
5. **No user traffic before `CanaryAuditing` passes** (see FSM in ARCHITECTURE.md).
6. `unsafe` only for FFI (WFP, ioctl) and each block carries a `// SAFETY:` note.
7. Clippy `-D warnings` clean on every target we ship.
8. Do not edit another crate's public API without updating ARCHITECTURE.md.

## Conventions

- Edition 2021, MSRV = current stable. Errors: `thiserror` in libraries,
  `anyhow` only in binaries.
- Async runtime: tokio. Dynamic transports use `async_trait`.
- Constants (`FW_MARK`, addresses, ports) come from `vw_core::consts`; never
  hard-code them elsewhere.
- Tests that need root are behind the `privileged` feature and `#[ignore]`-free;
  they must skip cleanly (return early with a message) when not root.
