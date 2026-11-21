# VoidWire desktop app

Tauri v2 + React 19 + TypeScript (strict) + Tailwind CSS 4. The app is an
**unprivileged remote control**: the tunnel, the Iron Dome firewall and the DNS
vault all run in the privileged `voidwired` service. The app talks to it over
VWIPC (`vw_core::ipc::IpcClient`, ARCHITECTURE.md §5). When the service cannot
be reached the UI says so and offers **Install VoidWire service**. It never
shows a connected state it did not get from the daemon.

```
apps/desktop/
├── src/                     React UI
│   ├── ipc/types.ts         TS mirror of vw-core's serde output
│   ├── ipc/client.ts        typed invoke() wrappers + event listeners
│   ├── hooks/store.tsx      app state fed by commands and daemon events
│   ├── components/          header, modes, map, panels, settings…
│   └── lib/landmask.ts      generated 120×60 land mask (scripts/gen-landmask.py)
├── src-tauri/
│   ├── src/bridge.rs        per-call authenticated IPC with timeouts
│   ├── src/commands.rs      one Tauri command per IPC request
│   ├── src/events.rs        Subscribe → `voidwire://event` with reconnect backoff
│   ├── src/tray.rs          tray menu + state tooltip
│   ├── src/service.rs       daemon detection + elevated `voidwired install`
│   ├── binaries/            sidecars (not committed, see below)
│   ├── resources/           wintun.dll on Windows (not committed)
│   ├── windows/hooks.nsh    NSIS post-install / pre-uninstall hooks
│   ├── windows/service-fragment.wxs  same for the MSI
│   └── tauri.{,windows.,linux.}conf.json
└── scripts/                 prepare-sidecars.mjs, gen-landmask.py
```

## Development

```bash
cd apps/desktop
npm ci
npm run sidecars            # builds voidwired + voidwire and places them (see below)
npm run tauri dev           # Vite on :1420 + the Tauri shell
npm run build               # tsc --noEmit + vite build
cd src-tauri && cargo fmt -- --check && cargo clippy --all-targets -- -D warnings
```

`src-tauri` is excluded from the root workspace and has its own `Cargo.lock`.
It depends on `vw-core` by path.

For the app to do anything useful, `voidwired` must be installed and running.
Use the in-app button, or run `sudo ./voidwired install` (macOS) /
`voidwired.exe install` from an elevated prompt (Windows). The IPC token at
`<state_dir>/ipc.token` is readable by administrators only, so run the app as
an admin user.

## Sidecars

`bundle.externalBin` lists `binaries/voidwired` and `binaries/voidwire`.
Tauri expects one file per target triple:

```
src-tauri/binaries/voidwired-aarch64-apple-darwin
src-tauri/binaries/voidwire-aarch64-apple-darwin
src-tauri/binaries/voidwired-x86_64-apple-darwin
src-tauri/binaries/voidwired-x86_64-pc-windows-msvc.exe
src-tauri/binaries/voidwire-x86_64-pc-windows-msvc.exe
```

`npm run sidecars [-- --target <triple>]` builds `vw-daemon` and `vw-cli` from
the workspace and copies them there. **`cargo build`, `cargo clippy` and
`tauri build` fail if the file for the current triple is missing**, because
`tauri-build` checks it. In bundles the triple suffix is stripped: on macOS
they land in `VoidWire.app/Contents/MacOS/`, on Windows in the install dir next
to `VoidWire.exe`. `service.rs` looks for them there.

## wintun.dll (Windows only)

`tauri.windows.conf.json` bundles `src-tauri/resources/wintun.dll` into the
install directory, next to `voidwired.exe`. It is not committed. Release CI
downloads the signed Wintun zip from <https://www.wintun.net>, checks its
SHA-256, and copies `wintun/bin/amd64/wintun.dll` there. macOS and Linux builds
don't need it, because only the Windows config references it.

## Service install contract

`voidwired install` is run elevated in three ways: by the in-app button (macOS
uses `osascript … with administrator privileges`, Windows uses
`ShellExecuteExW` with the `runas` verb, Linux uses `pkexec`), by the NSIS
post-install hook, and by the MSI deferred custom action. It must be
idempotent and must do all of the following:

- copy itself (and `wintun.dll`) to a stable location;
- register and start the launchd daemon or Windows service;
- create the state dir and IPC token;
- exit 0, or non-zero with a message on stderr.

`voidwired uninstall` reverses this and is run before files are removed.

## Bundling and releases

```bash
npm run tauri build                       # macOS: .app + .dmg
npm run tauri build -- --target x86_64-apple-darwin
npm run tauri build                       # on Windows: .msi + NSIS .exe
```

Bundle identifier `com.voidwire.desktop`, product name `VoidWire`. NSIS
installs per machine (elevated), so its hooks can register the service.
WebView2 uses `embedBootstrapper` (silent). Windows 11 already ships the
runtime, and the embedded bootstrapper avoids a separate download step.

### Unsigned builds

- **macOS Gatekeeper**: the first launch of an unsigned app is blocked.
  Right-click `VoidWire.app` → **Open** → **Open**, or run
  `xattr -dr com.apple.quarantine /Applications/VoidWire.app`.
- **Windows SmartScreen**: click **More info** → **Run anyway**.

### Signing

- macOS: set `APPLE_CERTIFICATE` (base64 .p12), `APPLE_CERTIFICATE_PASSWORD`,
  `APPLE_SIGNING_IDENTITY` and, for notarization, `APPLE_ID`, `APPLE_PASSWORD`
  (app-specific) and `APPLE_TEAM_ID`. `tauri build` signs the app and its
  sidecars, then notarizes. Sidecars need the hardened runtime, which Tauri
  applies by default.
- Windows: set `bundle.windows.certificateThumbprint` (plus `digestAlgorithm`
  and `timestampUrl`) for a certificate in the store, or a `signCommand` for
  cloud HSMs such as Azure Trusted Signing. Sign `voidwired.exe` and
  `voidwire.exe` before bundling, because the service binary runs as
  LocalSystem.

## Memory

The UI deliberately uses no map, chart or state libraries. The world map and
sparklines are hand-written SVG, and the land mask is 1.8 kB of hex. The Rust
side allocates very little: per-call IPC connections, one event-stream task,
and a tray icon.

The host process is still larger than our code. On an M-series Mac, a release
build at idle measured a **~31 MB physical footprint** for `voidwire-desktop`.
Most of that is AppKit and WebKit's UI-process side, not VoidWire code. The
system WebView adds its own processes:

- `WebKit.WebContent`: ~45 MB RSS.
- `GPU`: ~28 MB.
- `Networking`: ~11 MB.

On Windows, WebView2 (Edge) typically adds 80–150 MB across its processes.
The < 15 MB budget is met by our own allocations, not by the whole process
tree.

## Behaviour notes

- Closing the window hides it. The tray icon and the global panic shortcut
  (⌘⇧X / Ctrl+Shift+X) stay active. Use **Quit** in the tray to exit. Quitting
  the app never changes the firewall; the daemon owns it.
- The client position on the map is never geolocated. "You" is drawn at a
  fixed neutral spot. Hop positions come from `HopInfo.coords`, supplied by
  the daemon.
- The live DNS inspector is off by default. Its entries are held in memory
  only and are cleared as soon as it is turned off.
