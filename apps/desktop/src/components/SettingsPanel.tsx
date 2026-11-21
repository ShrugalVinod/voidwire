import { useEffect, useState, type ReactNode } from "react";
import { useStore } from "../hooks/store";
import {
  PROFILES,
  SHIELD_CATEGORIES,
  TRANSPORT_KINDS,
  type DnsUpstream,
  type FirewallSettings,
  type SanitizerSettings,
  type Settings,
  type TransportKind,
} from "../ipc/types";
import { PROFILE_META, SHIELD_LABEL, TRANSPORT_LABEL } from "../lib/format";
import { Empty, Panel, Spinner, Switch } from "./ui";

const FW: { key: keyof FirewallSettings; label: string; hint: string }[] = [
  { key: "block_webrtc_stun", label: "Block WebRTC STUN", hint: "Stops browsers revealing your real IP via STUN" },
  { key: "strict_ipv6", label: "Strict IPv6", hint: "Drop all IPv6 that cannot go through the tunnel" },
  { key: "block_router_adverts", label: "Block router adverts", hint: "Ignore rogue IPv6 RAs on the LAN" },
  { key: "block_mdns_netbios", label: "Block mDNS / LLMNR / NetBIOS", hint: "No local name broadcasts" },
  { key: "block_foreign_dot", label: "Block foreign DNS-over-TLS", hint: "Port 853 only to the DNS vault" },
  { key: "boot_lock", label: "Boot lock", hint: "Re-arm the lockdown at boot until you disarm" },
  { key: "allow_lan", label: "Allow LAN access", hint: "Printers, NAS etc. outside the tunnel (weaker)" },
];

const SAN: { key: keyof SanitizerSettings; label: string }[] = [
  { key: "normalize_ttl", label: "Normalise TTL / hop limit to 64" },
  { key: "clamp_mss", label: "Clamp TCP MSS to tunnel MTU" },
  { key: "scrub_tcp_timestamps", label: "Scrub TCP timestamps" },
];

function Row({ label, hint, children }: { label: string; hint?: string; children: ReactNode }) {
  return (
    <div className="flex items-center justify-between gap-4 border-b border-white/[0.04] py-2 last:border-0">
      <div className="min-w-0">
        <div className="text-[12.5px]">{label}</div>
        {hint && <div className="text-[11px] text-dim">{hint}</div>}
      </div>
      <div className="shrink-0">{children}</div>
    </div>
  );
}

function upstreamLabel(u: DnsUpstream): [string, string] {
  switch (u.protocol) {
    case "odoh":
      return ["ODoH", `${u.target_host}${u.target_path} via ${u.proxy_url}`];
    case "doh":
      return ["DoH", u.url];
    case "dot":
      return ["DoT", `${u.host} (${u.addr}:${u.port})`];
  }
}

function AddUpstream({ onAdd }: { onAdd: (u: DnsUpstream) => void }) {
  const [proto, setProto] = useState<DnsUpstream["protocol"]>("doh");
  const [a, setA] = useState("");
  const [b, setB] = useState("");
  const [c, setC] = useState("");
  const valid =
    proto === "doh"
      ? a.startsWith("https://")
      : proto === "odoh"
        ? a.startsWith("https://") && b.length > 0 && c.startsWith("/")
        : a.length > 0 && b.length > 0 && /^\d+$/.test(c) && Number(c) > 0 && Number(c) < 65536;
  const add = () => {
    if (!valid) return;
    if (proto === "doh") onAdd({ protocol: "doh", url: a.trim() });
    else if (proto === "odoh") onAdd({ protocol: "odoh", proxy_url: a.trim(), target_host: b.trim(), target_path: c.trim() });
    else onAdd({ protocol: "dot", host: a.trim(), addr: b.trim(), port: Number(c) });
    setA("");
    setB("");
    setC("");
  };
  const ph =
    proto === "doh"
      ? ["https://resolver/dns-query"]
      : proto === "odoh"
        ? ["https://relay/proxy", "target host", "/dns-query"]
        : ["tls name", "IP address", "853"];
  return (
    <div className="mt-2 flex items-center gap-2">
      <select
        className="field !w-[84px]"
        value={proto}
        onChange={(e) => {
          const p = e.target.value as DnsUpstream["protocol"];
          setProto(p);
          setC(p === "dot" ? "853" : p === "odoh" ? "/dns-query" : "");
        }}
        aria-label="Upstream protocol"
      >
        <option value="doh">DoH</option>
        <option value="dot">DoT</option>
        <option value="odoh">ODoH</option>
      </select>
      <input className="field" placeholder={ph[0]} value={a} onChange={(e) => setA(e.target.value)} aria-label={ph[0]} />
      {proto !== "doh" && <input className="field" placeholder={ph[1]} value={b} onChange={(e) => setB(e.target.value)} aria-label={ph[1]} />}
      {proto !== "doh" && (
        <input className="field !w-[110px]" placeholder={ph[2]} value={c} onChange={(e) => setC(e.target.value)} aria-label={ph[2]} />
      )}
      <button type="button" className="btn btn-sm" disabled={!valid} onClick={add}>
        Add
      </button>
    </div>
  );
}

const lines = (v: string[]) => v.join("\n");
const unlines = (v: string) =>
  v
    .split(/\r?\n/)
    .map((l) => l.trim())
    .filter(Boolean);

export function SettingsPanel() {
  const { s, act } = useStore();
  const [draft, setDraft] = useState<Settings | null>(s.settings);
  const [customText, setCustomText] = useState("");
  const [allowText, setAllowText] = useState("");

  // Reset the draft whenever the daemon's copy changes.
  useEffect(() => {
    setDraft(s.settings);
    setCustomText(s.settings ? lines(s.settings.dns.shield.custom_block) : "");
    setAllowText(s.settings ? lines(s.settings.dns.shield.allow) : "");
  }, [s.settings]);

  if (!draft || !s.settings) return <Empty>Settings are read from voidwired; the service is not reachable.</Empty>;

  const withLists = (d: Settings): Settings => ({
    ...d,
    dns: { ...d.dns, shield: { ...d.dns.shield, custom_block: unlines(customText), allow: unlines(allowText) } },
  });
  const dirty = JSON.stringify(withLists(draft)) !== JSON.stringify(s.settings);
  const up = (f: (d: Settings) => Settings) => setDraft((d) => (d ? f(d) : d));
  const ups = draft.dns.upstreams;
  const moveUp = (i: number, dir: -1 | 1) =>
    up((d) => {
      const u = [...d.dns.upstreams];
      const j = i + dir;
      if (j < 0 || j >= u.length) return d;
      [u[i], u[j]] = [u[j] as DnsUpstream, u[i] as DnsUpstream];
      return { ...d, dns: { ...d.dns, upstreams: u } };
    });

  return (
    <div className="flex min-h-0 flex-1 flex-col gap-3">
      <div className="scroll-y grid min-h-0 flex-1 auto-rows-max grid-cols-2 content-start gap-3 pr-1">
        <Panel title="Iron Dome firewall">
          {FW.map((r) => (
            <Row key={r.key} label={r.label} hint={r.hint}>
              <Switch
                label={r.label}
                checked={draft.firewall[r.key]}
                onChange={(v) => up((d) => ({ ...d, firewall: { ...d.firewall, [r.key]: v } }))}
              />
            </Row>
          ))}
        </Panel>

        <div className="flex flex-col gap-3">
          <Panel title="Connection">
            <Row label="Default mode">
              <select
                className="field !w-[190px]"
                value={draft.default_profile}
                onChange={(e) => up((d) => ({ ...d, default_profile: e.target.value as Settings["default_profile"] }))}
              >
                {PROFILES.map((p) => (
                  <option key={p} value={p}>
                    {PROFILE_META[p].title}
                  </option>
                ))}
              </select>
            </Row>
            <Row label="Transport" hint="Auto lets the optimizer pick per network">
              <select
                className="field !w-[190px]"
                value={draft.transport_preference ?? "auto"}
                onChange={(e) =>
                  up((d) => ({
                    ...d,
                    transport_preference: e.target.value === "auto" ? null : (e.target.value as TransportKind),
                  }))
                }
              >
                <option value="auto">Auto (recommended)</option>
                {TRANSPORT_KINDS.map((t) => (
                  <option key={t} value={t}>
                    {TRANSPORT_LABEL[t]}
                  </option>
                ))}
              </select>
            </Row>
            <Row label="Auto-optimise" hint="Re-measure on network change and every 30 min">
              <Switch label="Auto-optimise" checked={draft.auto_optimize} onChange={(v) => up((d) => ({ ...d, auto_optimize: v }))} />
            </Row>
            <Row label="PQ key rotation" hint="Seconds between ML-KEM re-keys">
              <input
                type="number"
                min={30}
                max={3600}
                className="field num !w-[90px]"
                value={draft.pq_rotate_secs}
                onChange={(e) => up((d) => ({ ...d, pq_rotate_secs: Math.max(30, Math.min(3600, Number(e.target.value) || 120)) }))}
              />
            </Row>
          </Panel>

          <Panel title="DAITA traffic-analysis defence">
            <Row label="DAITA" hint="Size buckets + Poisson chaff">
              <Switch label="DAITA" checked={draft.daita.enabled} onChange={(v) => up((d) => ({ ...d, daita: { ...d.daita, enabled: v } }))} />
            </Row>
            <Row label="Chaff rate" hint="Mean packets per second">
              <input
                type="number"
                step="0.5"
                min={0}
                max={200}
                className="field num !w-[90px]"
                value={draft.daita.chaff_rate_hz}
                onChange={(e) => up((d) => ({ ...d, daita: { ...d.daita, chaff_rate_hz: Math.max(0, Number(e.target.value) || 0) } }))}
              />
            </Row>
            <Row label="Max overhead" hint="Chaff cap, % of real traffic">
              <input
                type="number"
                min={0}
                max={100}
                className="field num !w-[90px]"
                value={draft.daita.max_overhead_pct}
                onChange={(e) =>
                  up((d) => ({ ...d, daita: { ...d.daita, max_overhead_pct: Math.max(0, Math.min(100, Math.round(Number(e.target.value) || 0))) } }))
                }
              />
            </Row>
          </Panel>
        </div>

        <Panel title="DNS vault upstreams (first healthy wins)" className="col-span-2">
          {ups.length === 0 && <div className="py-2 text-crimson">At least one upstream is required.</div>}
          <ul className="grid gap-1.5">
            {ups.map((u, i) => {
              const [proto, desc] = upstreamLabel(u);
              return (
                <li key={`${proto}-${desc}-${i}`} className="flex items-center gap-2 rounded-lg border border-line bg-black/20 px-2.5 py-1.5">
                  <span className="num w-5 text-dim">{i + 1}</span>
                  <span className="chip chip-cyan">{proto}</span>
                  <span className="num selectable min-w-0 flex-1 truncate text-[11.5px]">{desc}</span>
                  <button type="button" className="btn btn-sm" disabled={i === 0} onClick={() => moveUp(i, -1)} aria-label="Move up">
                    ↑
                  </button>
                  <button type="button" className="btn btn-sm" disabled={i === ups.length - 1} onClick={() => moveUp(i, 1)} aria-label="Move down">
                    ↓
                  </button>
                  <button
                    type="button"
                    className="btn btn-sm"
                    onClick={() => up((d) => ({ ...d, dns: { ...d.dns, upstreams: d.dns.upstreams.filter((_, j) => j !== i) } }))}
                  >
                    Remove
                  </button>
                </li>
              );
            })}
          </ul>
          <AddUpstream onAdd={(u) => up((d) => ({ ...d, dns: { ...d.dns, upstreams: [...d.dns.upstreams, u] } }))} />
        </Panel>

        <Panel title="Shield">
          <Row label="Shield enabled">
            <Switch
              label="Shield enabled"
              checked={draft.dns.shield.enabled}
              onChange={(v) => up((d) => ({ ...d, dns: { ...d.dns, shield: { ...d.dns.shield, enabled: v } } }))}
            />
          </Row>
          <Row label="CNAME uncloaking" hint="Catch trackers hiding behind first-party CNAMEs">
            <Switch
              label="CNAME uncloaking"
              checked={draft.dns.shield.cname_uncloak}
              onChange={(v) => up((d) => ({ ...d, dns: { ...d.dns, shield: { ...d.dns.shield, cname_uncloak: v } } }))}
            />
          </Row>
          <Row label="Block mode">
            <select
              className="field !w-[150px]"
              value={draft.dns.shield.block_mode}
              onChange={(e) =>
                up((d) => ({
                  ...d,
                  dns: { ...d.dns, shield: { ...d.dns.shield, block_mode: e.target.value as Settings["dns"]["shield"]["block_mode"] } },
                }))
              }
            >
              <option value="zero-ip">0.0.0.0 / ::</option>
              <option value="nxdomain">NXDOMAIN</option>
            </select>
          </Row>
          <div className="flex flex-wrap gap-1.5 pt-2">
            {SHIELD_CATEGORIES.map((c) => {
              const on = draft.dns.shield.categories.includes(c);
              return (
                <button
                  key={c}
                  type="button"
                  aria-pressed={on}
                  className={`chip focus-ring cursor-pointer ${on ? "chip-cyan" : ""}`}
                  onClick={() =>
                    up((d) => {
                      const cats = on ? d.dns.shield.categories.filter((x) => x !== c) : [...d.dns.shield.categories, c];
                      return { ...d, dns: { ...d.dns, shield: { ...d.dns.shield, categories: cats } } };
                    })
                  }
                >
                  {on ? "✓ " : ""}
                  {SHIELD_LABEL[c]}
                </button>
              );
            })}
          </div>
        </Panel>

        <Panel title="Custom lists & sanitiser">
          <div className="grid grid-cols-2 gap-2">
            <label className="grid gap-1">
              <span className="label !text-[9.5px]">Custom block (one per line)</span>
              <textarea className="field !text-[11px]" rows={4} value={customText} spellCheck={false} onChange={(e) => setCustomText(e.target.value)} />
            </label>
            <label className="grid gap-1">
              <span className="label !text-[9.5px]">Always allow</span>
              <textarea className="field !text-[11px]" rows={4} value={allowText} spellCheck={false} onChange={(e) => setAllowText(e.target.value)} />
            </label>
          </div>
          <div className="pt-1">
            {SAN.map((r) => (
              <Row key={r.key} label={r.label}>
                <Switch
                  label={r.label}
                  checked={draft.sanitizer[r.key]}
                  onChange={(v) => up((d) => ({ ...d, sanitizer: { ...d.sanitizer, [r.key]: v } }))}
                />
              </Row>
            ))}
          </div>
        </Panel>
      </div>

      <div className="glass flex shrink-0 items-center justify-between !rounded-xl px-4 py-2.5">
        <span className="text-[12px] text-mute">{dirty ? "Unsaved changes" : "In sync with voidwired"}</span>
        <div className="flex gap-2">
          <button
            type="button"
            className="btn btn-sm"
            disabled={!dirty}
            onClick={() => {
              setDraft(s.settings);
              setCustomText(s.settings ? lines(s.settings.dns.shield.custom_block) : "");
              setAllowText(s.settings ? lines(s.settings.dns.shield.allow) : "");
            }}
          >
            Revert
          </button>
          <button
            type="button"
            className="btn btn-sm btn-cyan"
            disabled={!dirty || ups.length === 0 || !!s.busy.settings}
            onClick={() => void act.saveSettings(withLists(draft))}
          >
            {s.busy.settings && <Spinner />} Apply
          </button>
        </div>
      </div>
    </div>
  );
}
