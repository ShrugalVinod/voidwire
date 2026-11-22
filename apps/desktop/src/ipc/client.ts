// Typed wrappers around the Tauri commands in src-tauri/src/commands.rs.
// Every call reaches voidwired over VWIPC; nothing here is simulated.

import { invoke } from "@tauri-apps/api/core";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";
import type {
  AppInfo,
  AuditReport,
  DaemonEvent,
  DaemonPresence,
  LinkStatus,
  NodeSummary,
  Notice,
  OptimizerDecision,
  PanicNotice,
  Profile,
  Response,
  Settings,
  StatusReport,
  TelemetrySnapshot,
  TransportKind,
} from "./types";

export const EVENT_DAEMON = "voidwire://event";
export const EVENT_LINK = "voidwire://link";
export const EVENT_PANIC = "voidwire://panic";
export const EVENT_NOTICE = "voidwire://notice";

/** Commands reject with a plain string; normalise anything else. */
export function errorText(e: unknown): string {
  if (typeof e === "string") return e;
  if (e instanceof Error) return e.message;
  try {
    return JSON.stringify(e);
  } catch {
    return String(e);
  }
}

export const api = {
  status: () => invoke<StatusReport>("status"),
  up: (profile: Profile, country: string | null, transport: TransportKind | null, gateway: string | null) =>
    invoke<Response>("up", { profile, country, transport, gateway }),
  down: (keepLockdown: boolean) => invoke<Response>("down", { keep_lockdown: keepLockdown }),
  disarm: () => invoke<Response>("disarm"),
  panic: () => invoke<null>("panic"),
  audit: () => invoke<AuditReport>("audit"),
  optimize: () => invoke<OptimizerDecision>("optimize"),
  getSettings: () => invoke<Settings>("get_settings"),
  setSettings: (settings: Settings) => invoke<Response>("set_settings", { settings }),
  listNodes: () => invoke<NodeSummary[]>("list_nodes"),
  importNode: (uri: string) => invoke<Response>("import_node", { uri }),
  importWireGuard: (name: string, config: string, country: string | null) =>
    invoke<Response>("import_wireguard", { name, config, country }),
  removeNode: (name: string) => invoke<Response>("remove_node", { name }),
  redeemInvite: (uri: string) => invoke<Response>("redeem_invite", { uri }),
  registerWarp: () => invoke<Response>("register_warp"),
  telemetry: () => invoke<TelemetrySnapshot>("telemetry"),
  daemonInstalled: () => invoke<DaemonPresence>("daemon_installed"),
  installService: () => invoke<string>("install_service"),
  linkStatus: () => invoke<LinkStatus>("link_status"),
  appInfo: () => invoke<AppInfo>("app_info"),
};

export function onDaemonEvent(cb: (e: DaemonEvent) => void): Promise<UnlistenFn> {
  return listen<DaemonEvent>(EVENT_DAEMON, (e) => cb(e.payload));
}
export function onLink(cb: (l: LinkStatus) => void): Promise<UnlistenFn> {
  return listen<LinkStatus>(EVENT_LINK, (e) => cb(e.payload));
}
export function onPanic(cb: (p: PanicNotice) => void): Promise<UnlistenFn> {
  return listen<PanicNotice>(EVENT_PANIC, (e) => cb(e.payload));
}
export function onNotice(cb: (n: Notice) => void): Promise<UnlistenFn> {
  return listen<Notice>(EVENT_NOTICE, (e) => cb(e.payload));
}
