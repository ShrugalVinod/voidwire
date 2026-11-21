import { useStore } from "../hooks/store";
import type { Profile } from "../ipc/types";
import { ACTIVE_STATES, PROFILE_META, STATE_META, TONE_COLOR, formatDuration } from "../lib/format";
import { ConfirmButton, Spinner } from "./ui";

export function Header({ profile, country }: { profile: Profile; country: string }) {
  const { s, act } = useStore();
  const isMac = s.appInfo?.os === "macos";
  const online = s.link?.connected === true;
  const state = online ? (s.status?.state ?? s.link?.state ?? null) : null;
  const meta = state ? STATE_META[state] : null;
  const color = meta ? TONE_COLOR[meta.tone] : "#5a6577";
  const active = state ? ACTIVE_STATES.includes(state) : false;
  const lockdown = state === "FailsafeLockdown";
  const shortcut = s.appInfo?.panic_shortcut ?? "Ctrl+Shift+X";
  const anim = meta && meta.tone !== "idle";

  return (
    <header
      data-tauri-drag-region
      className="relative z-10 flex h-[76px] shrink-0 items-center gap-5 border-b border-line pr-5"
      style={{ paddingLeft: isMac ? 92 : 20 }}
    >
      {/* State orb */}
      <div data-tauri-drag-region className="relative grid h-11 w-11 place-items-center">
        {anim && (
          <span
            className="anim-ring absolute inset-0 rounded-full"
            style={{ border: `1.5px solid ${color}` }}
            aria-hidden
          />
        )}
        <span
          className={`relative h-5 w-5 rounded-full ${meta?.tone === "work" ? "anim-pulse" : ""}`}
          style={{ background: color, boxShadow: `0 0 24px ${color}, 0 0 4px ${color}` }}
          aria-hidden
        />
      </div>

      <div data-tauri-drag-region className="min-w-0 flex-1">
        <div data-tauri-drag-region className="flex items-baseline gap-3">
          <span
            data-tauri-drag-region
            className="text-[24px] leading-none font-bold tracking-[0.06em]"
            style={{ color: meta ? color : "#8a96a8", textShadow: meta?.tone === "cyan" ? `0 0 18px ${color}66` : undefined }}
            aria-live="polite"
          >
            {meta ? meta.label : online ? "…" : "OFFLINE"}
          </span>
          {online && s.status && (state === "TunnelActive" || state === "KeyRotating") && (
            <span className="num text-mute">up {formatDuration(s.status.uptime_secs)}</span>
          )}
        </div>
        <div data-tauri-drag-region className="mt-1.5 truncate text-[12px] text-mute">
          {meta
            ? meta.detail
            : online
              ? "Reading state from voidwired"
              : "voidwired is not reachable: the tunnel cannot be controlled from here"}
          {online && s.status?.profile && active && (
            <span className="text-dim"> · {PROFILE_META[s.status.profile].title}</span>
          )}
        </div>
      </div>

      {online && (
        <div className="flex items-center gap-2">
          {lockdown ? (
            <>
              <button
                type="button"
                className="btn btn-cyan"
                disabled={!!s.busy.connect}
                onClick={() => void act.connect(profile, country || null, null)}
              >
                {s.busy.connect && <Spinner />} Retry tunnel
              </button>
              <ConfirmButton
                className="btn btn-crimson"
                confirmLabel="Remove lockdown: traffic will flow unprotected"
                onConfirm={() => void act.disarm()}
                disabled={!!s.busy.disarm}
              >
                Disarm
              </ConfirmButton>
            </>
          ) : active ? (
            <>
              <button
                type="button"
                className="btn"
                disabled={!!s.busy.disconnect}
                onClick={() => void act.disconnect(false)}
                title="Tear down the tunnel and release the firewall"
              >
                {s.busy.disconnect && <Spinner />} Disconnect
              </button>
              <button
                type="button"
                className="btn btn-sm"
                disabled={!!s.busy.disconnect}
                onClick={() => void act.disconnect(true)}
                title="Tear down the tunnel but keep all traffic blocked"
              >
                Keep lockdown
              </button>
            </>
          ) : (
            <button
              type="button"
              className="btn btn-cyan !h-9 !px-5"
              disabled={!!s.busy.connect || state === "Disarming"}
              onClick={() => void act.connect(profile, country || null, null)}
            >
              {s.busy.connect && <Spinner />} Connect · {PROFILE_META[profile].title}
            </button>
          )}
          <button
            type="button"
            className="btn btn-crimson !h-9"
            disabled={!!s.busy.panic}
            onClick={() => void act.panic()}
            title={`Rotate all keys, flush DNS and switch exit; firewall stays locked (${shortcut})`}
          >
            {s.busy.panic ? <Spinner /> : <PanicIcon />}
            Panic
            <kbd className="num rounded border border-crimson/40 px-1 text-[10px] text-crimson/90">{shortcut}</kbd>
          </button>
        </div>
      )}
    </header>
  );
}

function PanicIcon() {
  return (
    <svg width="13" height="13" viewBox="0 0 24 24" aria-hidden>
      <path d="M12 2 3 6v6c0 5 3.8 9.4 9 10 5.2-.6 9-5 9-10V6l-9-4Z" fill="none" stroke="currentColor" strokeWidth="2" />
      <path d="M12 8v5M12 16.5v.5" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" />
    </svg>
  );
}
