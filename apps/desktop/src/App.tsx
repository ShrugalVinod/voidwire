import { useEffect, useRef, useState } from "react";
import { StoreProvider, useStore } from "./hooks/store";
import type { Profile } from "./ipc/types";
import { Header } from "./components/Header";
import { ModeSelector } from "./components/ModeSelector";
import { OptimizerPanel } from "./components/OptimizerPanel";
import { TopologyMap } from "./components/TopologyMap";
import { TrafficPanel } from "./components/TrafficPanel";
import { CryptoPanel } from "./components/CryptoPanel";
import { AuditPanel, DomeMatrix, EnforcementCounters, LogPanel } from "./components/DomePanels";
import { DnsInspector, ShieldCounters } from "./components/ShieldPanel";
import { NodesPanel } from "./components/NodesPanel";
import { SettingsPanel } from "./components/SettingsPanel";
import { DaemonMissing } from "./components/DaemonMissing";

type Tab = "overview" | "dome" | "shield" | "nodes" | "settings";

const TABS: { id: Tab; label: string; icon: string }[] = [
  { id: "overview", label: "Overview", icon: "M3 12h4l3-8 4 16 3-8h4" },
  { id: "dome", label: "Iron Dome", icon: "M12 3 4 7v5c0 4.4 3.4 8.4 8 9 4.6-.6 8-4.6 8-9V7l-8-4Zm-3 9 2 2 4-4" },
  { id: "shield", label: "Shield", icon: "M4 6h16M4 12h10M4 18h6M17 15l4 4m0-4-4 4" },
  { id: "nodes", label: "Nodes", icon: "M6 18a2 2 0 1 0 0-4 2 2 0 0 0 0 4Zm12-8a2 2 0 1 0 0-4 2 2 0 0 0 0 4ZM6 8a2 2 0 1 0 0-4 2 2 0 0 0 0 4Zm2 8 8-6M6 8v6" },
  { id: "settings", label: "Settings", icon: "M12 15a3 3 0 1 0 0-6 3 3 0 0 0 0 6Zm7.4-3a7.4 7.4 0 0 0-.1-1.2l2-1.6-2-3.4-2.4 1a7 7 0 0 0-2-1.2L14.5 3h-5l-.4 2.6a7 7 0 0 0-2 1.2l-2.4-1-2 3.4 2 1.6a7.4 7.4 0 0 0 0 2.4l-2 1.6 2 3.4 2.4-1a7 7 0 0 0 2 1.2l.4 2.6h5l.4-2.6a7 7 0 0 0 2-1.2l2.4 1 2-3.4-2-1.6c.1-.4.1-.8.1-1.2Z" },
];

function Rail({ tab, setTab }: { tab: Tab; setTab: (t: Tab) => void }) {
  const { s } = useStore();
  return (
    <nav className="flex w-[76px] shrink-0 flex-col items-center gap-1 border-r border-line py-3" aria-label="Sections">
      {TABS.map((t) => {
        const sel = t.id === tab;
        return (
          <button
            key={t.id}
            type="button"
            onClick={() => setTab(t.id)}
            aria-current={sel ? "page" : undefined}
            className={`focus-ring flex w-[64px] flex-col items-center gap-1 rounded-xl py-2 text-[10.5px] transition-colors ${
              sel ? "bg-cyan/[0.09] text-[#c9fbff]" : "text-mute hover:bg-white/[0.04] hover:text-ink"
            }`}
          >
            <svg width="20" height="20" viewBox="0 0 24 24" aria-hidden>
              <path d={t.icon} fill="none" stroke={sel ? "#00f0ff" : "currentColor"} strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round" />
            </svg>
            {t.label}
          </button>
        );
      })}
      <div className="mt-auto px-1 text-center text-[9.5px] leading-tight text-dim">
        <div className="num">app {s.appInfo?.version ?? "—"}</div>
        <div className="num">{s.link?.daemon_version ? `svc ${s.link.daemon_version}` : "svc offline"}</div>
      </div>
    </nav>
  );
}

function Toasts() {
  const { s, act } = useStore();
  useEffect(() => {
    if (!s.toasts.length) return;
    const timers = s.toasts.map((t) => window.setTimeout(() => act.dismiss(t.id), t.level === "error" ? 9000 : 5000));
    return () => timers.forEach((id) => window.clearTimeout(id));
  }, [s.toasts, act]);
  return (
    <div className="pointer-events-none fixed right-4 bottom-4 z-50 flex w-[360px] flex-col gap-2" aria-live="polite">
      {s.toasts.map((t) => (
        <div
          key={t.id}
          role={t.level === "error" ? "alert" : "status"}
          className={`glass anim-in pointer-events-auto flex items-start gap-3 !rounded-xl px-3.5 py-2.5 text-[12.5px] ${
            t.level === "error" ? "!border-crimson/50" : t.level === "warn" ? "!border-amber/50" : "!border-cyan/40"
          }`}
          style={{ background: "var(--glass-strong)" }}
        >
          <span className="selectable flex-1 leading-snug break-words">{t.message}</span>
          <button type="button" className="text-dim hover:text-ink" onClick={() => act.dismiss(t.id)} aria-label="Dismiss">
            ✕
          </button>
        </div>
      ))}
    </div>
  );
}

function PanicFlash() {
  const { s } = useStore();
  if (!s.panicFlash) return null;
  return (
    <div key={s.panicFlash} className="panic-flash" aria-hidden>
      <div className="absolute inset-0 grid place-items-center">
        <span className="num text-[13px] tracking-[0.4em] text-cyan">ROTATING KEYS</span>
      </div>
    </div>
  );
}

function Shell() {
  const { s } = useStore();
  const [tab, setTab] = useState<Tab>("overview");
  const [profile, setProfile] = useState<Profile>("auto");
  const [country, setCountry] = useState("");
  const seeded = useRef(false);

  // Start from the user's default mode (or the running one) once known.
  useEffect(() => {
    if (seeded.current) return;
    const p = s.status?.profile ?? s.settings?.default_profile;
    if (p) {
      setProfile(p);
      seeded.current = true;
    }
  }, [s.status?.profile, s.settings?.default_profile]);

  const online = s.link?.connected === true;

  return (
    <div className="relative z-[1] flex h-full flex-col">
      <Header profile={profile} country={country} />
      {s.appInfo?.shortcut_error && (
        <div className="border-b border-amber/30 bg-amber/[0.07] px-5 py-1 text-[11.5px] text-[#ffdca0]">
          Global panic shortcut unavailable ({s.appInfo.shortcut_error}). The Panic button and tray menu still work.
        </div>
      )}
      <div className="flex min-h-0 flex-1">
        <Rail tab={tab} setTab={setTab} />
        <main className="flex min-h-0 min-w-0 flex-1 flex-col gap-3 p-3">
          {s.link === null ? null : !online ? (
            <DaemonMissing />
          ) : tab === "overview" ? (
            <>
              <ModeSelector profile={profile} setProfile={setProfile} country={country} setCountry={setCountry} />
              <div className="grid min-h-0 flex-[1.25] grid-cols-[1fr_280px] gap-3">
                <TopologyMap />
                <div className="scroll-y flex min-h-0 flex-col gap-3">
                  <TrafficPanel />
                  <CryptoPanel />
                </div>
              </div>
              <div className="flex min-h-[170px] flex-1">
                <OptimizerPanel />
              </div>
            </>
          ) : tab === "dome" ? (
            <div className="grid min-h-0 flex-1 grid-cols-2 gap-3">
              <div className="scroll-y flex min-h-0 flex-col gap-3">
                <DomeMatrix />
                <EnforcementCounters />
              </div>
              <div className="flex min-h-0 flex-col gap-3">
                <div className="flex min-h-0 flex-[1.4]">
                  <AuditPanel />
                </div>
                <div className="flex min-h-0 flex-1">
                  <LogPanel />
                </div>
              </div>
            </div>
          ) : tab === "shield" ? (
            <div className="grid min-h-0 flex-1 grid-cols-[360px_1fr] gap-3">
              <ShieldCounters />
              <DnsInspector />
            </div>
          ) : tab === "nodes" ? (
            <NodesPanel />
          ) : (
            <SettingsPanel />
          )}
        </main>
      </div>
      <PanicFlash />
      <Toasts />
    </div>
  );
}

export function App() {
  return (
    <StoreProvider>
      <div className="vw-backdrop" aria-hidden />
      <Shell />
    </StoreProvider>
  );
}
