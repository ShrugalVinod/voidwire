import type { DomeState, NodeKind, Profile, ShieldCategory, TransportKind } from "../ipc/types";

export function formatBytes(n: number): string {
  if (!Number.isFinite(n) || n < 0) return "0 B";
  const units = ["B", "KiB", "MiB", "GiB", "TiB"];
  let v = n;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i++;
  }
  return `${v >= 100 || i === 0 ? v.toFixed(0) : v.toFixed(1)} ${units[i]}`;
}

/** Bytes per second → bit rate string. */
export function formatRate(bytesPerSec: number): string {
  const bits = Math.max(0, bytesPerSec) * 8;
  if (bits >= 1e9) return `${(bits / 1e9).toFixed(2)} Gb/s`;
  if (bits >= 1e6) return `${(bits / 1e6).toFixed(1)} Mb/s`;
  if (bits >= 1e3) return `${(bits / 1e3).toFixed(0)} kb/s`;
  return `${bits.toFixed(0)} b/s`;
}

export function formatCount(n: number): string {
  return new Intl.NumberFormat("en-US").format(n);
}

export function formatDuration(secs: number): string {
  const s = Math.max(0, Math.floor(secs));
  const h = Math.floor(s / 3600);
  const m = Math.floor((s % 3600) / 60);
  const r = s % 60;
  if (h > 0) return `${h}h ${String(m).padStart(2, "0")}m`;
  if (m > 0) return `${m}m ${String(r).padStart(2, "0")}s`;
  return `${r}s`;
}

export function formatMs(v: number | null | undefined, digits = 0): string {
  return v == null || !Number.isFinite(v) ? "—" : `${v.toFixed(digits)} ms`;
}

export type Tone = "idle" | "work" | "cyan" | "crimson";

export interface StateMeta {
  label: string;
  detail: string;
  tone: Tone;
}

export const STATE_META: Record<DomeState, StateMeta> = {
  Disarmed: { label: "Disarmed", detail: "Firewall open, no tunnel", tone: "idle" },
  ArmingBootLock: { label: "Arming", detail: "Engaging kernel lockdown", tone: "work" },
  Handshaking: { label: "Handshaking", detail: "WireGuard + ML-KEM key exchange", tone: "work" },
  CanaryAuditing: { label: "Canary audit", detail: "Verifying zero leaks before traffic", tone: "work" },
  TunnelActive: { label: "PROTECTED", detail: "Tunnel active, egress locked to tunnel", tone: "cyan" },
  KeyRotating: { label: "Rotating", detail: "Post-quantum key rotation in progress", tone: "cyan" },
  FailsafeLockdown: { label: "LOCKDOWN", detail: "All traffic blocked until you retry or disarm", tone: "crimson" },
  Disarming: { label: "Disarming", detail: "Releasing the firewall lockdown", tone: "work" },
};

export const TONE_COLOR: Record<Tone, string> = {
  idle: "#8a96a8",
  work: "#f5b544",
  cyan: "#00f0ff",
  crimson: "#ef4444",
};

export const ACTIVE_STATES: readonly DomeState[] = [
  "ArmingBootLock",
  "Handshaking",
  "CanaryAuditing",
  "TunnelActive",
  "KeyRotating",
];

export interface ProfileMeta {
  title: string;
  blurb: string;
}

export const PROFILE_META: Record<Profile, ProfileMeta> = {
  auto: { title: "Auto", blurb: "Fastest zero-leak path, measured live" },
  warp: { title: "Instant Free", blurb: "Cloudflare WARP, single hop" },
  multihop: { title: "Ghost Multi-Hop", blurb: "Split-trust entry + exit" },
  stealth: { title: "Chameleon Stealth", blurb: "Anti-DPI transports only" },
  "max-anonymity": { title: "Max Anonymity", blurb: "3 hops, DAITA, stealth" },
  f2f: { title: "Friend Exit", blurb: "Exit via a friend's node" },
};

export const TRANSPORT_LABEL: Record<TransportKind, string> = {
  "native-udp": "WireGuard UDP",
  "amnezia-wg": "AmneziaWG",
  "masque-quic": "MASQUE HTTP/3",
  "tls-websocket": "TLS-WebSocket",
};

export const NODE_KIND_LABEL: Record<NodeKind, string> = {
  voidwire: "VoidWire node",
  warp: "Cloudflare WARP",
  generic: "WireGuard server",
};

export const SHIELD_LABEL: Record<ShieldCategory, string> = {
  ads: "Ads",
  trackers: "Trackers",
  telemetry: "Telemetry",
  malware: "Malware",
  custom: "Custom",
};

export function shortHash(h: string, n = 10): string {
  return h.length > n * 2 + 1 ? `${h.slice(0, n)}…${h.slice(-n)}` : h;
}
