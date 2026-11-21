import { useStore } from "../hooks/store";
import { SHIELD_CATEGORIES } from "../ipc/types";
import { SHIELD_LABEL, formatCount } from "../lib/format";
import { Empty, Panel, Switch } from "./ui";

const CAT_COLOR = {
  ads: "#00f0ff",
  trackers: "#7c9cff",
  telemetry: "#f5b544",
  malware: "#ef4444",
  custom: "#10b981",
} as const;

export function ShieldCounters() {
  const { s } = useStore();
  const sh = (s.telemetry ?? s.status?.telemetry ?? null)?.shield ?? null;
  const total = sh ? sh.ads + sh.trackers + sh.telemetry + sh.malware + sh.custom : 0;
  const max = sh ? Math.max(1, ...SHIELD_CATEGORIES.map((c) => sh[c])) : 1;
  const enabled = s.settings?.dns.shield.enabled;
  return (
    <Panel
      title="Shield"
      right={enabled === false ? <span className="chip chip-amber">DISABLED</span> : enabled ? <span className="chip chip-emerald">ACTIVE</span> : null}
    >
      {!sh ? (
        <Empty>Service offline</Empty>
      ) : (
        <div className="grid gap-4">
          <div className="flex items-end gap-6">
            <div>
              <div className="label !text-[9.5px]">Blocked this session</div>
              <div className="num text-[34px] leading-none text-cyan">{formatCount(total)}</div>
            </div>
            <div>
              <div className="label !text-[9.5px]">CNAME cloaks uncovered</div>
              <div className="num text-[20px] leading-none">{formatCount(sh.cname_uncloaked)}</div>
            </div>
          </div>
          <ul className="grid gap-2">
            {SHIELD_CATEGORIES.map((c) => (
              <li key={c} className="grid grid-cols-[84px_1fr_64px] items-center gap-3 text-[12px]">
                <span className="text-mute">{SHIELD_LABEL[c]}</span>
                <div className="h-2 overflow-hidden rounded-full bg-white/5">
                  <div
                    className="h-full rounded-full transition-[width] duration-500"
                    style={{ width: `${(sh[c] / max) * 100}%`, background: CAT_COLOR[c], boxShadow: `0 0 10px ${CAT_COLOR[c]}88` }}
                  />
                </div>
                <span className="num text-right">{formatCount(sh[c])}</span>
              </li>
            ))}
          </ul>
          <p className="text-[11px] text-dim">Category counters only. VoidWire keeps no query history.</p>
        </div>
      )}
    </Panel>
  );
}

export function DnsInspector() {
  const { s, act } = useStore();
  const on = s.settings?.live_inspector ?? false;
  return (
    <Panel
      title="Live DNS inspector"
      className="min-h-0"
      bodyClass="flex min-h-0 flex-col"
      right={
        <label className="flex items-center gap-2 text-[11.5px] text-mute">
          {on ? "Streaming" : "Off"}
          <Switch
            label="Live DNS inspector"
            checked={on}
            disabled={!s.settings || !!s.busy.inspector}
            onChange={(v) => void act.setLiveInspector(v)}
          />
        </label>
      }
    >
      {!on ? (
        <Empty>
          Off by default. When on, voidwired streams each lookup to this window only: entries live in memory and are
          wiped when you turn it off.
        </Empty>
      ) : s.dns.length === 0 ? (
        <Empty>Waiting for DNS queries…</Empty>
      ) : (
        <ul className="scroll-y num selectable min-h-0 flex-1 px-4 py-2 text-[11.5px]">
          {s.dns.map((d) => (
            <li key={d.id} className="anim-in grid grid-cols-[84px_1fr_auto] items-center whitespace-nowrap gap-2 border-b border-white/[0.03] py-1">
              <span className="text-dim">{new Date(d.at).toLocaleTimeString()}</span>
              <span className={`truncate ${d.blocked ? "text-crimson line-through decoration-crimson/40" : "text-ink"}`}>{d.name}</span>
              <span className={`chip ${d.blocked ? "chip-crimson" : ""}`}>
                {d.blocked ? `BLOCKED${d.category ? ` · ${SHIELD_LABEL[d.category]}` : ""}` : "resolved"}
              </span>
            </li>
          ))}
        </ul>
      )}
    </Panel>
  );
}
