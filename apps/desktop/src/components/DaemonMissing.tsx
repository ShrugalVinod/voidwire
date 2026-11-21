import { useStore } from "../hooks/store";
import { Spinner } from "./ui";

export function DaemonMissing() {
  const { s, act } = useStore();
  const p = s.presence;
  const installing = !!s.busy.install;

  let title = "VoidWire service is not reachable";
  let body =
    "The desktop app is only a remote control. The tunnel, the firewall lockdown and the DNS vault run in the privileged voidwired service, which this app cannot reach right now. Nothing is protected by this window.";
  if (p && !p.token_present) {
    title = "VoidWire service is not installed";
    body =
      "VoidWire needs its privileged service (voidwired) to create the tunnel and lock the firewall. Installing it asks for your administrator password once.";
  } else if (p && p.token_present && !p.token_readable) {
    title = "No permission to talk to the VoidWire service";
    body =
      "The service is installed, but this user cannot read its access token. Only administrators may control the tunnel. Re-running the installer repairs the token permissions.";
  } else if (p && p.token_present) {
    title = "VoidWire service is installed but not running";
    body =
      "The service did not answer. It may have stopped or still be starting. Re-running the installer re-registers and starts it; your firewall lockdown (if any) stays in place.";
  }

  return (
    <div className="flex flex-1 items-center justify-center p-8">
      <div className="glass anim-in w-full max-w-[560px] p-7">
        <div className="mb-4 flex items-center gap-3">
          <span className="grid h-10 w-10 place-items-center rounded-full border border-crimson/50 bg-crimson/10 text-crimson" aria-hidden>
            <svg width="18" height="18" viewBox="0 0 24 24">
              <path d="M12 8v5M12 16.5v.5M10.3 3.9 2.4 18a2 2 0 0 0 1.7 3h15.8a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0Z" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" />
            </svg>
          </span>
          <h1 className="text-[18px] font-semibold">{title}</h1>
        </div>
        <p className="mb-5 text-[13px] leading-relaxed text-mute">{body}</p>

        <div className="mb-5 flex gap-2">
          <button type="button" className="btn btn-cyan !h-10 !px-5" disabled={installing || !p?.sidecar} onClick={() => void act.installService()}>
            {installing && <Spinner />} {installing ? "Waiting for administrator approval…" : "Install VoidWire service"}
          </button>
          <button type="button" className="btn !h-10" disabled={installing} onClick={() => void act.checkPresence()}>
            Check again
          </button>
        </div>
        {p && !p.sidecar && (
          <p className="mb-4 rounded-lg border border-amber/40 bg-amber/[0.07] px-3 py-2 text-[12px] text-[#ffdca0]">
            The bundled voidwired binary was not found next to the app. Reinstall VoidWire from the official GitHub release,
            or (developers) place the sidecar in src-tauri/binaries as described in apps/desktop/README.md.
          </p>
        )}

        <details className="text-[11.5px] text-dim">
          <summary className="cursor-pointer text-mute">Diagnostics</summary>
          <dl className="num selectable mt-2 grid grid-cols-[120px_1fr] gap-x-3 gap-y-1">
            <dt>Endpoint</dt>
            <dd className="break-all">{p?.endpoint ?? "—"}</dd>
            <dt>Token</dt>
            <dd className="break-all">
              {p ? `${p.token_path} (${p.token_present ? (p.token_readable ? "readable" : "no permission") : "missing"})` : "—"}
            </dd>
            <dt>Bundled daemon</dt>
            <dd className="break-all">{p?.sidecar ?? "not found"}</dd>
            <dt>Last error</dt>
            <dd className="break-all">{p?.error ?? s.link?.error ?? "—"}</dd>
          </dl>
        </details>
      </div>
    </div>
  );
}
