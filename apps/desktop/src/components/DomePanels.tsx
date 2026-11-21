import { useStore } from "../hooks/store";
import type { FirewallMatrix } from "../ipc/types";
import { formatCount, shortHash } from "../lib/format";
import { Empty, Panel, Spinner } from "./ui";

const ROWS: { key: keyof Omit<FirewallMatrix, "backend">; label: string; hint: string }[] = [
  { key: "ipv4_locked", label: "IPv4 lockdown", hint: "Default-deny egress except the pinned tunnel endpoints" },
  { key: "ipv6_locked", label: "IPv6 lockdown", hint: "Non-tunnel IPv6 dropped" },
  { key: "dns_vault", label: "DNS vault", hint: "All port-53 traffic answered by the encrypted local resolver" },
  { key: "stun_filter", label: "WebRTC STUN filter", hint: "STUN binding requests (cookie 0x2112A442) dropped" },
  { key: "tunnelvision_guard", label: "Tunnelvision guard", hint: "CVE-2024-3661: rogue DHCP routes cannot bypass the tunnel" },
  { key: "boot_lock", label: "Boot lock", hint: "Lockdown re-armed at boot until you disarm" },
];

export function DomeMatrix() {
  const { s } = useStore();
  const fw = s.status?.firewall;
  const locked = s.status ? s.status.state !== "Disarmed" : false;
  return (
    <Panel
      title="Iron Dome verification matrix"
      right={fw && <span className="chip num">{fw.backend}</span>}
    >
      {!fw ? (
        <Empty>Service offline</Empty>
      ) : (
        <ul className="grid gap-1.5">
          {ROWS.map((r) => {
            const on = fw[r.key];
            // A guard that is off while the dome is armed is an alert.
            const cls = on ? "chip-emerald" : locked ? "chip-crimson" : "";
            return (
              <li key={r.key} className="flex items-center justify-between gap-3 rounded-lg border border-line bg-black/20 px-3 py-2">
                <div className="min-w-0">
                  <div className="text-[12.5px] font-semibold">{r.label}</div>
                  <div className="truncate text-[11px] text-dim">{r.hint}</div>
                </div>
                <span className={`chip ${cls}`}>{on ? "ENFORCED" : locked ? "NOT ENFORCED" : "OFF"}</span>
              </li>
            );
          })}
        </ul>
      )}
    </Panel>
  );
}

export function EnforcementCounters() {
  const { s } = useStore();
  const t = s.telemetry ?? s.status?.telemetry ?? null;
  const items: [string, number | undefined][] = [
    ["Pre-canary packets dropped", t?.pre_canary_dropped],
    ["STUN requests blocked", t?.stun_blocked],
    ["IPv6 packets dropped", t?.ipv6_dropped],
    ["DNS queries intercepted", t?.dns_intercepted],
    ["Foreign DoT blocked", t?.dot_blocked],
    ["TCP timestamps scrubbed", t?.ts_scrubbed],
    ["MSS clamped", t?.mss_clamped],
    ["TTL normalised", t?.ttl_normalized],
  ];
  return (
    <Panel title="Enforcement counters">
      <div className="grid grid-cols-2 gap-x-5 gap-y-1.5 text-[11.5px]">
        {items.map(([k, v]) => (
          <div key={k} className="flex justify-between gap-2">
            <span className="truncate text-mute">{k}</span>
            <span className="num">{v == null ? "—" : formatCount(v)}</span>
          </div>
        ))}
      </div>
    </Panel>
  );
}

export function AuditPanel() {
  const { s, act } = useStore();
  const r = s.audit;
  const running = !!s.busy.audit;
  return (
    <Panel
      title="Live leak self-auditor"
      className="min-h-0"
      bodyClass="flex min-h-0 flex-col p-4"
      right={
        <button type="button" className="btn btn-sm btn-cyan" disabled={running || !s.link?.connected} onClick={() => void act.audit()}>
          {running && <Spinner />} {running ? "Auditing…" : "Run leak audit"}
        </button>
      }
    >
      {!r ? (
        <Empty>
          {running
            ? "voidwired is sending canary probes outside and inside the tunnel…"
            : "Run the audit to prove, with canary probes, that nothing leaves outside the tunnel."}
        </Empty>
      ) : (
        <>
          <div
            className={`mb-3 flex items-center justify-between rounded-lg border px-3 py-2 ${
              r.passed ? "border-emerald/50 bg-emerald/[0.08] text-[#b7f5dc]" : "border-crimson/50 bg-crimson/[0.08] text-[#ffc9c9]"
            }`}
          >
            <span className="font-semibold tracking-wide">
              {r.passed ? "VERIFIED ZERO-LEAK" : "LEAK DETECTED"} · {r.checks.filter((c) => c.passed).length}/{r.checks.length} checks
            </span>
            <span className="num text-[11px] opacity-80">{new Date(r.unix_time * 1000).toLocaleTimeString()}</span>
          </div>
          <ul className="scroll-y grid min-h-0 flex-1 content-start gap-1.5">
            {r.checks.map((c) => (
              <li key={c.name} className="anim-in rounded-lg border border-line bg-black/20 px-3 py-2">
                <div className="flex items-center justify-between gap-2">
                  <span className="flex items-center gap-2 font-semibold">
                    <span style={{ color: c.passed ? "#10b981" : "#ef4444" }} aria-hidden>
                      {c.passed ? "✓" : "✕"}
                    </span>
                    {c.name}
                  </span>
                  <span className={`chip ${c.passed ? "chip-emerald" : "chip-crimson"}`}>{c.passed ? "PASS" : "FAIL"}</span>
                </div>
                <div className="selectable mt-0.5 text-[11.5px] text-mute">{c.detail}</div>
                <div className="num selectable mt-1 truncate text-[10.5px] text-dim" title={c.proof}>
                  proof blake3:{shortHash(c.proof, 16)}
                </div>
              </li>
            ))}
          </ul>
        </>
      )}
    </Panel>
  );
}

export function LogPanel() {
  const { s } = useStore();
  return (
    <Panel title="Daemon log" className="min-h-0" bodyClass="scroll-y min-h-0 px-4 py-2">
      {s.logs.length === 0 ? (
        <Empty>No log lines received this session.</Empty>
      ) : (
        <ul className="num selectable grid gap-0.5 text-[11px]">
          {s.logs.map((l) => (
            <li key={l.id} className="flex gap-2">
              <span className="text-dim">{new Date(l.at).toLocaleTimeString()}</span>
              <span className={l.level === "error" ? "text-crimson" : l.level === "warn" ? "text-amber" : "text-mute"}>
                {l.level.toUpperCase().padEnd(5)}
              </span>
              <span className="text-ink/90">{l.message}</span>
            </li>
          ))}
        </ul>
      )}
    </Panel>
  );
}
