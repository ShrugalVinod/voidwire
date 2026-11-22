// TypeScript mirror of vw-core's serde output (crates/vw-core/src/{ipc,config,probe,state,telemetry}.rs).
//
// Serde rules reflected here:
//  * Adjacently tagged enums (`#[serde(tag = "type", content = "data")]`):
//    unit variants serialize as `{ "type": "X" }`, newtype/struct variants as
//    `{ "type": "X", "data": ... }`. `Box<T>` is transparent.
//  * `#[serde(rename_all = "kebab-case")]` unit enums serialize as strings,
//    e.g. `AmneziaWg` → "amnezia-wg", `MaxAnonymity` → "max-anonymity".
//  * `DnsUpstream` is internally tagged on "protocol".
//  * `Option<T>` without `skip_serializing_if` is always present (`T | null`).
//  * Tuples serialize as arrays; u64 counters arrive as JSON numbers.

// ───────────────────────────── config.rs ─────────────────────────────

export type TransportKind = "native-udp" | "amnezia-wg" | "masque-quic" | "tls-websocket";
export const TRANSPORT_KINDS: readonly TransportKind[] = [
  "native-udp",
  "amnezia-wg",
  "masque-quic",
  "tls-websocket",
];

export type NodeKind = "voidwire" | "warp" | "generic";
export type NodeRole = "entry" | "exit" | "both";

export type Profile = "auto" | "warp" | "multihop" | "stealth" | "f2f" | "max-anonymity";
export const PROFILES: readonly Profile[] = [
  "auto",
  "warp",
  "multihop",
  "stealth",
  "f2f",
  "max-anonymity",
];

export type BlockMode = "zero-ip" | "nxdomain";

export type ShieldCategory = "ads" | "trackers" | "telemetry" | "malware" | "custom";
export const SHIELD_CATEGORIES: readonly ShieldCategory[] = [
  "ads",
  "trackers",
  "telemetry",
  "malware",
  "custom",
];

export type DnsUpstream =
  | { protocol: "odoh"; proxy_url: string; target_host: string; target_path: string }
  | { protocol: "doh"; url: string }
  | { protocol: "dot"; host: string; addr: string; port: number };

export interface ShieldSettings {
  enabled: boolean;
  categories: ShieldCategory[];
  cname_uncloak: boolean;
  block_mode: BlockMode;
  custom_block: string[];
  allow: string[];
}

export interface DnsSettings {
  upstreams: DnsUpstream[];
  shield: ShieldSettings;
  max_cache_ttl: number;
}

export interface FirewallSettings {
  block_webrtc_stun: boolean;
  strict_ipv6: boolean;
  block_router_adverts: boolean;
  block_mdns_netbios: boolean;
  block_foreign_dot: boolean;
  allow_lan: boolean;
  boot_lock: boolean;
}

export interface DaitaParams {
  enabled: boolean;
  buckets: number[];
  chaff_rate_hz: number;
  max_overhead_pct: number;
}

export interface SanitizerSettings {
  normalize_ttl: boolean;
  clamp_mss: boolean;
  scrub_tcp_timestamps: boolean;
}

export interface Settings {
  firewall: FirewallSettings;
  dns: DnsSettings;
  daita: DaitaParams;
  sanitizer: SanitizerSettings;
  auto_optimize: boolean;
  transport_preference: TransportKind | null;
  pq_rotate_secs: number;
  default_profile: Profile;
  live_inspector: boolean;
}

// ───────────────────────────── state.rs ──────────────────────────────

export type DomeState =
  | "Disarmed"
  | "ArmingBootLock"
  | "Handshaking"
  | "CanaryAuditing"
  | "TunnelActive"
  | "KeyRotating"
  | "FailsafeLockdown"
  | "Disarming";

// ─────────────────────────── telemetry.rs ────────────────────────────

export interface ShieldCounts {
  ads: number;
  trackers: number;
  telemetry: number;
  malware: number;
  custom: number;
  cname_uncloaked: number;
}

export interface TelemetrySnapshot {
  tx_bytes: number;
  rx_bytes: number;
  tx_packets: number;
  rx_packets: number;
  stun_blocked: number;
  ipv6_dropped: number;
  dns_intercepted: number;
  dot_blocked: number;
  pre_canary_dropped: number;
  ts_scrubbed: number;
  mss_clamped: number;
  ttl_normalized: number;
  chaff_sent: number;
  handshakes: number;
  pq_rotations: number;
  shield: ShieldCounts;
}

// ───────────────────────────── probe.rs ──────────────────────────────

export interface ProbeResult {
  node_name: string;
  transport: TransportKind;
  reachable: boolean;
  handshake_ms: number | null;
  rtt_ms: number | null;
  jitter_ms: number | null;
  /** 0.0 ..= 1.0 */
  loss: number;
  throughput_mbps: number | null;
  post_quantum: boolean;
  score: number;
}

export interface NetworkVerdict {
  udp_hostile: boolean;
  quic_blocked: boolean;
  wg_signature_filtered: boolean;
}

export interface OptimizerDecision {
  hops: string[];
  transport: TransportKind;
  mtu: number;
  mss_v4: number;
  daita: boolean;
  verdict: NetworkVerdict;
  candidates: ProbeResult[];
  reason: string;
}

// ────────────────────────────── ipc.rs ───────────────────────────────

export interface HopInfo {
  name: string;
  kind: NodeKind;
  role: NodeRole;
  country: string | null;
  transport: TransportKind;
  post_quantum: boolean;
  rtt_ms: number | null;
  /** Approximate (lat, lon) for the route map. */
  coords: [number, number] | null;
}

export interface FirewallMatrix {
  ipv4_locked: boolean;
  ipv6_locked: boolean;
  dns_vault: boolean;
  stun_filter: boolean;
  tunnelvision_guard: boolean;
  boot_lock: boolean;
  backend: string;
}

export interface StatusReport {
  state: DomeState;
  profile: Profile | null;
  hops: HopInfo[];
  transport: TransportKind | null;
  crypto_suite: string;
  uptime_secs: number;
  mtu: number | null;
  daita: boolean;
  firewall: FirewallMatrix;
  last_rotation_secs_ago: number | null;
  telemetry: TelemetrySnapshot;
  decision: OptimizerDecision | null;
  platform: string;
  daemon_version: string;
}

export interface AuditCheck {
  name: string;
  passed: boolean;
  detail: string;
  /** BLAKE3 digest of the probe transcript / counter deltas. */
  proof: string;
}

export interface AuditReport {
  passed: boolean;
  checks: AuditCheck[];
  unix_time: number;
}

export interface NodeSummary {
  name: string;
  kind: NodeKind;
  role: NodeRole;
  country: string | null;
  transports: TransportKind[];
  post_quantum: boolean;
}

export interface ExecTicket {
  netns: string | null;
  isolation: string;
}

export type Handshake =
  | { type: "ClientHello"; data: { version: number } }
  | { type: "Challenge"; data: { nonce: string } }
  | { type: "Auth"; data: { mac: string } }
  | { type: "AuthOk"; data: { daemon_version: string } }
  | { type: "AuthFail" };

export type Request =
  | { type: "Status" }
  | {
      type: "Up";
      data: { profile: Profile; country: string | null; transport: TransportKind | null; gateway?: string | null };
    }
  | { type: "Down"; data: { keep_lockdown: boolean } }
  | { type: "Disarm" }
  | { type: "Panic" }
  | { type: "Audit" }
  | { type: "Optimize" }
  | { type: "GetSettings" }
  | { type: "SetSettings"; data: Settings }
  | { type: "ListNodes" }
  | { type: "ImportNode"; data: { uri: string } }
  | { type: "RemoveNode"; data: { name: string } }
  | { type: "RedeemInvite"; data: { uri: string } }
  | { type: "ImportWireGuard"; data: { name: string; config: string; country?: string | null } }
  | { type: "RegisterWarp" }
  | { type: "Telemetry" }
  | { type: "Subscribe" }
  | { type: "ExecPrepare" };

export type DaemonEvent =
  | { type: "StateChanged"; data: { from: DomeState; to: DomeState } }
  | { type: "Telemetry"; data: TelemetrySnapshot }
  | { type: "Audit"; data: AuditReport }
  | { type: "Decision"; data: OptimizerDecision }
  | { type: "Log"; data: { level: string; message: string } }
  | {
      type: "DnsInspect";
      data: { name: string; category: ShieldCategory | null; blocked: boolean };
    };

export type Response =
  | { type: "Ok" }
  | { type: "Error"; data: { message: string } }
  | { type: "Status"; data: StatusReport }
  | { type: "Audit"; data: AuditReport }
  | { type: "Optimized"; data: OptimizerDecision }
  | { type: "Settings"; data: Settings }
  | { type: "Nodes"; data: NodeSummary[] }
  | { type: "Telemetry"; data: TelemetrySnapshot }
  | { type: "Exec"; data: ExecTicket }
  | { type: "Event"; data: DaemonEvent };

// ─────────────────── desktop shell (src-tauri) types ─────────────────

/** `events::LinkStatus`: is the event stream to voidwired up. */
export interface LinkStatus {
  connected: boolean;
  daemon_version: string | null;
  error: string | null;
  state: DomeState | null;
}

/** `service::DaemonPresence`. */
export interface DaemonPresence {
  token_present: boolean;
  token_readable: boolean;
  token_path: string;
  endpoint: string;
  reachable: boolean;
  daemon_version: string | null;
  sidecar: string | null;
  error: string | null;
}

/** `events::PanicNotice`. */
export interface PanicNotice {
  stage: "requested" | "done" | "failed";
  source: "shortcut" | "tray" | "ui";
  error: string | null;
}

/** `events::Notice`. */
export interface Notice {
  level: "info" | "warn" | "error";
  message: string;
}

/** `commands::AppInfo`. */
export interface AppInfo {
  os: string;
  arch: string;
  version: string;
  panic_shortcut: string;
  shortcut_error: string | null;
}
