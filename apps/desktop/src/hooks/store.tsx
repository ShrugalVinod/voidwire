// App-wide state: everything here is fed by real Tauri commands and the
// `voidwire://*` events the Rust bridge re-emits from voidwired.

import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useReducer,
  useRef,
  type ReactNode,
} from "react";
import {
  api,
  errorText,
  onDaemonEvent,
  onLink,
  onNotice,
  onPanic,
} from "../ipc/client";
import type {
  AppInfo,
  AuditReport,
  DaemonPresence,
  LinkStatus,
  NodeSummary,
  OptimizerDecision,
  Profile,
  Settings,
  ShieldCategory,
  StatusReport,
  TelemetrySnapshot,
  TransportKind,
} from "../ipc/types";

export interface RatePoint {
  t: number;
  rx: number;
  tx: number;
}
export interface DnsEntry {
  id: number;
  at: number;
  name: string;
  category: ShieldCategory | null;
  blocked: boolean;
}
export interface LogEntry {
  id: number;
  at: number;
  level: string;
  message: string;
}
export interface Toast {
  id: number;
  level: "info" | "warn" | "error";
  message: string;
}

const RATE_POINTS = 90;
const DNS_CAP = 200;
const LOG_CAP = 120;

interface State {
  appInfo: AppInfo | null;
  link: LinkStatus | null;
  presence: DaemonPresence | null;
  status: StatusReport | null;
  statusAt: number;
  telemetry: TelemetrySnapshot | null;
  telemetryAt: number;
  rates: RatePoint[];
  decision: OptimizerDecision | null;
  audit: AuditReport | null;
  settings: Settings | null;
  nodes: NodeSummary[] | null;
  dns: DnsEntry[];
  logs: LogEntry[];
  panicFlash: number;
  toasts: Toast[];
  busy: Record<string, boolean>;
}

const initial: State = {
  appInfo: null,
  link: null,
  presence: null,
  status: null,
  statusAt: 0,
  telemetry: null,
  telemetryAt: 0,
  rates: [],
  decision: null,
  audit: null,
  settings: null,
  nodes: null,
  dns: [],
  logs: [],
  panicFlash: 0,
  toasts: [],
  busy: {},
};

type Action =
  | { t: "appInfo"; v: AppInfo }
  | { t: "link"; v: LinkStatus }
  | { t: "presence"; v: DaemonPresence }
  | { t: "status"; v: StatusReport }
  | { t: "telemetry"; v: TelemetrySnapshot }
  | { t: "decision"; v: OptimizerDecision }
  | { t: "audit"; v: AuditReport }
  | { t: "settings"; v: Settings }
  | { t: "nodes"; v: NodeSummary[] }
  | { t: "dns"; v: Omit<DnsEntry, "id" | "at"> }
  | { t: "dnsClear" }
  | { t: "log"; v: { level: string; message: string } }
  | { t: "panicFlash" }
  | { t: "toast"; v: Omit<Toast, "id"> }
  | { t: "dismiss"; id: number }
  | { t: "busy"; key: string; on: boolean };

let seq = 0;

function withTelemetry(s: State, v: TelemetrySnapshot): State {
  const now = performance.now();
  let rates = s.rates;
  if (s.telemetry && s.telemetryAt > 0) {
    const dt = (now - s.telemetryAt) / 1000;
    if (dt > 0.2) {
      const rx = Math.max(0, (v.rx_bytes - s.telemetry.rx_bytes) / dt);
      const tx = Math.max(0, (v.tx_bytes - s.telemetry.tx_bytes) / dt);
      rates = [...s.rates, { t: now, rx, tx }].slice(-RATE_POINTS);
    } else {
      return { ...s, telemetry: v };
    }
  }
  return { ...s, telemetry: v, telemetryAt: now, rates };
}

function reducer(s: State, a: Action): State {
  switch (a.t) {
    case "appInfo":
      return { ...s, appInfo: a.v };
    case "link": {
      // Drop daemon-derived state when the link goes away so nothing stale
      // is shown as if it were live.
      if (!a.v.connected) {
        return { ...s, link: a.v, status: null, telemetry: null, telemetryAt: 0, rates: [] };
      }
      return { ...s, link: a.v };
    }
    case "presence":
      return { ...s, presence: a.v };
    case "status": {
      const next = { ...s, status: a.v, statusAt: Date.now() };
      return a.v.decision ? { ...next, decision: a.v.decision } : next;
    }
    case "telemetry":
      return withTelemetry(s, a.v);
    case "decision":
      return { ...s, decision: a.v };
    case "audit":
      return { ...s, audit: a.v };
    case "settings": {
      const dns = a.v.live_inspector ? s.dns : [];
      return { ...s, settings: a.v, dns };
    }
    case "nodes":
      return { ...s, nodes: a.v };
    case "dns": {
      if (!s.settings?.live_inspector) return s;
      const entry = { ...a.v, id: ++seq, at: Date.now() };
      return { ...s, dns: [entry, ...s.dns].slice(0, DNS_CAP) };
    }
    case "dnsClear":
      return { ...s, dns: [] };
    case "log": {
      const entry = { ...a.v, id: ++seq, at: Date.now() };
      return { ...s, logs: [entry, ...s.logs].slice(0, LOG_CAP) };
    }
    case "panicFlash":
      return { ...s, panicFlash: s.panicFlash + 1 };
    case "toast":
      return { ...s, toasts: [...s.toasts, { ...a.v, id: ++seq }].slice(-4) };
    case "dismiss":
      return { ...s, toasts: s.toasts.filter((t) => t.id !== a.id) };
    case "busy":
      return { ...s, busy: { ...s.busy, [a.key]: a.on } };
  }
}

export interface Actions {
  refreshStatus: () => Promise<void>;
  refreshSettings: () => Promise<void>;
  refreshNodes: () => Promise<void>;
  checkPresence: () => Promise<void>;
  connect: (profile: Profile, country: string | null, transport: TransportKind | null) => Promise<void>;
  disconnect: (keepLockdown: boolean) => Promise<void>;
  disarm: () => Promise<void>;
  panic: () => Promise<void>;
  audit: () => Promise<void>;
  optimize: () => Promise<void>;
  saveSettings: (s: Settings) => Promise<boolean>;
  setLiveInspector: (on: boolean) => Promise<void>;
  importUri: (uri: string) => Promise<boolean>;
  removeNode: (name: string) => Promise<void>;
  registerWarp: () => Promise<void>;
  installService: () => Promise<void>;
  toast: (level: Toast["level"], message: string) => void;
  dismiss: (id: number) => void;
}

interface Ctx {
  s: State;
  act: Actions;
}

const StoreCtx = createContext<Ctx | null>(null);

export function useStore(): Ctx {
  const c = useContext(StoreCtx);
  if (!c) throw new Error("StoreProvider missing");
  return c;
}

export function StoreProvider({ children }: { children: ReactNode }) {
  const [s, dispatch] = useReducer(reducer, initial);
  const stateRef = useRef(s);
  stateRef.current = s;

  const toast = useCallback((level: Toast["level"], message: string) => {
    dispatch({ t: "toast", v: { level, message } });
  }, []);

  /** Run an action with a busy flag; errors become toasts. */
  const run = useCallback(
    async <T,>(key: string, fn: () => Promise<T>): Promise<T | undefined> => {
      dispatch({ t: "busy", key, on: true });
      try {
        return await fn();
      } catch (e) {
        toast("error", errorText(e));
        return undefined;
      } finally {
        dispatch({ t: "busy", key, on: false });
      }
    },
    [toast],
  );

  const refreshStatus = useCallback(async () => {
    try {
      dispatch({ t: "status", v: await api.status() });
    } catch {
      // Link state drives the offline UI; a failed poll is not user-facing.
    }
  }, []);
  const refreshSettings = useCallback(async () => {
    try {
      dispatch({ t: "settings", v: await api.getSettings() });
    } catch (e) {
      toast("warn", `Settings unavailable: ${errorText(e)}`);
    }
  }, [toast]);
  const refreshNodes = useCallback(async () => {
    try {
      dispatch({ t: "nodes", v: await api.listNodes() });
    } catch (e) {
      toast("warn", `Node list unavailable: ${errorText(e)}`);
    }
  }, [toast]);
  const checkPresence = useCallback(async () => {
    try {
      dispatch({ t: "presence", v: await api.daemonInstalled() });
    } catch (e) {
      toast("error", errorText(e));
    }
  }, [toast]);

  const act = useMemo<Actions>(
    () => ({
      refreshStatus,
      refreshSettings,
      refreshNodes,
      checkPresence,
      toast,
      dismiss: (id) => dispatch({ t: "dismiss", id }),
      connect: async (profile, country, transport) => {
        await run("connect", () => api.up(profile, country, transport));
        await refreshStatus();
      },
      disconnect: async (keep) => {
        await run("disconnect", () => api.down(keep));
        await refreshStatus();
      },
      disarm: async () => {
        await run("disarm", () => api.disarm());
        await refreshStatus();
      },
      // Flash + result toasts come from the `voidwire://panic` event so the
      // shortcut, tray and button behave identically.
      panic: async () => {
        dispatch({ t: "busy", key: "panic", on: true });
        try {
          await api.panic();
        } catch {
          // reported via the panic event
        } finally {
          dispatch({ t: "busy", key: "panic", on: false });
        }
        await refreshStatus();
      },
      audit: async () => {
        const r = await run("audit", () => api.audit());
        if (r) dispatch({ t: "audit", v: r });
      },
      optimize: async () => {
        const d = await run("optimize", () => api.optimize());
        if (d) dispatch({ t: "decision", v: d });
      },
      saveSettings: async (next) => {
        const r = await run("settings", () => api.setSettings(next));
        if (r === undefined) return false;
        await refreshSettings();
        toast("info", "Settings applied by voidwired");
        return true;
      },
      setLiveInspector: async (on) => {
        const cur = stateRef.current.settings;
        if (!cur) return;
        if (!on) dispatch({ t: "dnsClear" });
        const r = await run("inspector", () => api.setSettings({ ...cur, live_inspector: on }));
        if (r !== undefined) await refreshSettings();
      },
      importUri: async (raw) => {
        const uri = raw.trim();
        let r;
        if (uri.startsWith("voidwire://node/")) {
          r = await run("import", () => api.importNode(uri));
        } else if (uri.startsWith("voidwire://f2f/")) {
          r = await run("import", () => api.redeemInvite(uri));
        } else {
          toast("error", "Paste a voidwire://node/… or voidwire://f2f/… URI");
          return false;
        }
        if (r === undefined) return false;
        toast("info", uri.startsWith("voidwire://f2f/") ? "Invite redeemed" : "Node imported");
        await refreshNodes();
        return true;
      },
      removeNode: async (name) => {
        const r = await run(`remove:${name}`, () => api.removeNode(name));
        if (r !== undefined) await refreshNodes();
      },
      registerWarp: async () => {
        const r = await run("warp", () => api.registerWarp());
        if (r === undefined) return;
        toast("info", "Cloudflare WARP device registered");
        await refreshNodes();
      },
      installService: async () => {
        const msg = await run("install", () => api.installService());
        if (msg !== undefined) toast("info", msg);
        await checkPresence();
      },
    }),
    [run, toast, refreshStatus, refreshSettings, refreshNodes, checkPresence],
  );

  // Subscriptions to the Rust bridge.
  useEffect(() => {
    const subs = [
      onLink((l) => dispatch({ t: "link", v: l })),
      onDaemonEvent((e) => {
        switch (e.type) {
          case "StateChanged":
            void refreshStatus();
            break;
          case "Telemetry":
            dispatch({ t: "telemetry", v: e.data });
            break;
          case "Audit":
            dispatch({ t: "audit", v: e.data });
            break;
          case "Decision":
            dispatch({ t: "decision", v: e.data });
            break;
          case "Log":
            dispatch({ t: "log", v: e.data });
            break;
          case "DnsInspect":
            dispatch({ t: "dns", v: e.data });
            break;
        }
      }),
      onPanic((p) => {
        if (p.stage === "requested") dispatch({ t: "panicFlash" });
        else if (p.stage === "done")
          toast("info", "Panic complete: keys rotated, DNS flushed, exit switched. Firewall stayed locked.");
        else if (p.error && /not available while (Disarmed|ArmingBootLock|Handshaking|CanaryAuditing|Disarming)/.test(p.error))
          toast("info", "Panic only works while VoidWire is connected (or locked down). Press Connect first.");
        else toast("error", `Panic failed: ${p.error ?? "unknown error"}`);
      }),
      onNotice((n) => toast(n.level, n.message)),
    ];
    void api.appInfo().then((v) => dispatch({ t: "appInfo", v }));
    void api.linkStatus().then((v) => dispatch({ t: "link", v }));
    void checkPresence();
    return () => {
      for (const p of subs) void p.then((un) => un());
    };
  }, [refreshStatus, toast, checkPresence]);

  const connected = s.link?.connected === true;

  // On (re)connect, load everything once.
  useEffect(() => {
    if (!connected) return;
    void refreshStatus();
    void refreshSettings();
    void refreshNodes();
    void checkPresence();
  }, [connected, refreshStatus, refreshSettings, refreshNodes, checkPresence]);

  // While connected: status every 5 s; telemetry polled only when the
  // daemon has not pushed a Telemetry event in the last 1.5 s.
  useEffect(() => {
    if (!connected) return;
    const st = window.setInterval(() => void refreshStatus(), 5000);
    const tl = window.setInterval(() => {
      if (performance.now() - stateRef.current.telemetryAt < 1500) return;
      api
        .telemetry()
        .then((v) => dispatch({ t: "telemetry", v }))
        .catch(() => undefined);
    }, 1000);
    return () => {
      window.clearInterval(st);
      window.clearInterval(tl);
    };
  }, [connected, refreshStatus]);

  // While disconnected: re-check installation state every 5 s.
  useEffect(() => {
    if (connected || s.link === null) return;
    void checkPresence();
    const id = window.setInterval(() => void checkPresence(), 5000);
    return () => window.clearInterval(id);
  }, [connected, s.link, checkPresence]);

  const value = useMemo(() => ({ s, act }), [s, act]);
  return <StoreCtx.Provider value={value}>{children}</StoreCtx.Provider>;
}
