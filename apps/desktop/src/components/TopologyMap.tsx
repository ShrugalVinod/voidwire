import { useMemo, useState } from "react";
import { useStore } from "../hooks/store";
import type { HopInfo } from "../ipc/types";
import { LAND_MASK, MASK_COLS } from "../lib/landmask";
import { NODE_KIND_LABEL, TRANSPORT_LABEL, formatMs } from "../lib/format";
import { Panel, PqBadge } from "./ui";

// Equirectangular projection over the land mask (3° cells). Rows 1..48 cover
// 87°N..57°S; Antarctica is cropped.
const S = 8;
const ROW0 = 1;
const ROWS = 48;
const MARGIN = 84; // room on the left for the "You" marker
const W = MASK_COLS * S;
const H = ROWS * S;
const VB = `${-MARGIN} 0 ${W + MARGIN} ${H}`;

function project(lat: number, lon: number): [number, number] {
  const x = ((lon + 180) / 3) * S;
  const y = ((90 - lat) / 3 - ROW0) * S;
  return [Math.min(W, Math.max(0, x)), Math.min(H - 4, Math.max(4, y))];
}

function landPath(): string {
  let d = "";
  for (let r = ROW0; r < ROW0 + ROWS; r++) {
    const row = LAND_MASK[r] ?? "";
    for (let i = 0; i < row.length; i++) {
      const nib = parseInt(row[i] ?? "0", 16);
      for (let b = 0; b < 4; b++) {
        if (nib & (8 >> b)) {
          const c = i * 4 + b;
          d += `M${c * S + S / 2} ${(r - ROW0) * S + S / 2}h0`;
        }
      }
    }
  }
  return d;
}

/** The client is never geolocated: it sits at a fixed neutral spot. */
const YOU: [number, number] = [-MARGIN / 2, H * 0.62];

interface Placed {
  hop: HopInfo;
  x: number;
  y: number;
  located: boolean;
}

function arcPath(a: [number, number], b: [number, number]): string {
  const [x1, y1] = a;
  const [x2, y2] = b;
  const mx = (x1 + x2) / 2;
  const my = (y1 + y2) / 2;
  const dist = Math.hypot(x2 - x1, y2 - y1);
  const lift = Math.min(120, dist * 0.32);
  return `M${x1} ${y1} Q${mx} ${my - lift} ${x2} ${y2}`;
}

export function TopologyMap() {
  const { s } = useStore();
  const dots = useMemo(landPath, []);
  const [hover, setHover] = useState<number | null>(null);
  const status = s.status;
  const hops = status?.hops ?? [];
  const state = status?.state;

  const placed: Placed[] = useMemo(() => {
    let lane = 0;
    return hops.map((hop) => {
      if (hop.coords) {
        const [x, y] = project(hop.coords[0], hop.coords[1]);
        return { hop, x, y, located: true };
      }
      // Unknown position: park on a top lane, clearly labelled.
      lane++;
      return { hop, x: W * 0.3 + lane * 150, y: 18, located: false };
    });
  }, [hops]);

  const lockdown = state === "FailsafeLockdown";
  const live = state === "TunnelActive" || state === "KeyRotating";
  const arcColor = lockdown ? "#ef4444" : live ? "#00f0ff" : "#f5b544";
  const points: [number, number][] = [YOU, ...placed.map((p) => [p.x, p.y] as [number, number])];
  const hovered = hover != null ? placed[hover] : undefined;

  return (
    <Panel
      title="Circuit topology"
      bodyClass="relative p-0"
      className="min-h-0"
      right={
        <span className="text-[11px] text-dim">
          {hops.length ? `${hops.length} hop${hops.length > 1 ? "s" : ""}` : "no circuit"} · positions approximate
        </span>
      }
    >
      <div className="relative h-full w-full">
        <svg viewBox={VB} preserveAspectRatio="xMidYMid meet" className="block h-full w-full" role="img" aria-label="World map with the current VoidWire circuit">
          <defs>
            <radialGradient id="hopGlow">
              <stop offset="0" stopColor={arcColor} stopOpacity="0.55" />
              <stop offset="1" stopColor={arcColor} stopOpacity="0" />
            </radialGradient>
          </defs>
          <path d={dots} stroke="#3a4a60" strokeOpacity="0.55" strokeWidth={3.1} strokeLinecap="round" />

          {/* You */}
          <g>
            <circle cx={YOU[0]} cy={YOU[1]} r={16} fill="none" stroke="#8a96a8" strokeOpacity="0.35" strokeDasharray="2 4" />
            <circle cx={YOU[0]} cy={YOU[1]} r={6} fill="#e6edf5" />
            <text x={YOU[0]} y={YOU[1] + 32} textAnchor="middle" fontSize="13" fill="#e6edf5" fontWeight="600">
              You
            </text>
            <text x={YOU[0]} y={YOU[1] + 47} textAnchor="middle" fontSize="9.5" fill="#5a6577">
              not geolocated
            </text>
          </g>

          {/* Arcs */}
          {points.slice(1).map((p, i) => {
            const from = points[i] as [number, number];
            const d = arcPath(from, p);
            const hop = placed[i]?.hop;
            const [x1, y1] = from;
            const mx = (x1 + p[0]) / 2;
            const my = (y1 + p[1]) / 2 - Math.min(120, Math.hypot(p[0] - x1, p[1] - y1) * 0.32) / 2;
            return (
              <g key={`arc-${i}`}>
                <path d={d} fill="none" stroke={arcColor} strokeOpacity="0.18" strokeWidth={6} />
                <path
                  d={d}
                  fill="none"
                  stroke={arcColor}
                  strokeWidth={1.8}
                  strokeDasharray="4 16"
                  strokeLinecap="round"
                  className={live ? "anim-dash" : undefined}
                />
                {hop?.rtt_ms != null && (
                  <g>
                    <rect x={mx - 30} y={my - 11} width={60} height={20} rx={6} fill="#07090e" fillOpacity="0.85" stroke={arcColor} strokeOpacity="0.4" />
                    <text x={mx} y={my + 3.5} textAnchor="middle" fontSize="11" fill={arcColor} fontFamily="ui-monospace, monospace">
                      {formatMs(hop.rtt_ms, 0)}
                    </text>
                  </g>
                )}
              </g>
            );
          })}

          {/* Hops */}
          {placed.map((p, i) => (
            <g
              key={`hop-${i}`}
              tabIndex={0}
              role="button"
              aria-label={`Hop ${i + 1}: ${p.hop.name}`}
              onMouseEnter={() => setHover(i)}
              onMouseLeave={() => setHover(null)}
              onFocus={() => setHover(i)}
              onBlur={() => setHover(null)}
              style={{ cursor: "default", outline: "none" }}
            >
              <circle cx={p.x} cy={p.y} r={26} fill="url(#hopGlow)" />
              <circle cx={p.x} cy={p.y} r={7} fill="#07090e" stroke={arcColor} strokeWidth={2.5} />
              <circle cx={p.x} cy={p.y} r={2.6} fill={arcColor} />
              <text x={p.x} y={i % 2 === 0 ? p.y - 14 : p.y + 24} textAnchor="middle" fontSize="11.5" fill="#e6edf5" fontWeight="600">
                {i + 1}. {p.hop.name}
              </text>
              {!p.located && (
                <text x={p.x} y={i % 2 === 0 ? p.y + 22 : p.y + 37} textAnchor="middle" fontSize="9.5" fill="#5a6577">
                  position n/a
                </text>
              )}
            </g>
          ))}
        </svg>

        {hovered && (
          <div
            className="glass pointer-events-none absolute z-10 w-56 !rounded-lg p-3 text-[12px]"
            style={{
              left: `${((hovered.x + MARGIN) / (W + MARGIN)) * 100}%`,
              top: `${(hovered.y / H) * 100}%`,
              transform: `translate(${hovered.x > W * 0.7 ? "-105%" : "12px"}, 12px)`,
              background: "var(--glass-strong)",
            }}
          >
            <div className="mb-1 flex items-center justify-between gap-2">
              <span className="truncate font-semibold">{hovered.hop.name}</span>
              <PqBadge pq={hovered.hop.post_quantum} />
            </div>
            <dl className="grid grid-cols-[auto_1fr] gap-x-3 gap-y-0.5 text-mute">
              <dt>Kind</dt>
              <dd className="text-ink">{NODE_KIND_LABEL[hovered.hop.kind]}</dd>
              <dt>Role</dt>
              <dd className="text-ink">{hovered.hop.role}</dd>
              <dt>Transport</dt>
              <dd className="text-ink">{TRANSPORT_LABEL[hovered.hop.transport]}</dd>
              <dt>RTT</dt>
              <dd className="num text-ink">{formatMs(hovered.hop.rtt_ms, 1)}</dd>
              <dt>Country</dt>
              <dd className="text-ink">{hovered.hop.country ?? "—"}</dd>
            </dl>
          </div>
        )}

        {!hops.length && (
          <div className="pointer-events-none absolute inset-x-0 bottom-3 text-center text-[11.5px] text-dim">
            {s.link?.connected ? "No active circuit. Connect to draw the route." : "Service offline"}
          </div>
        )}
      </div>
    </Panel>
  );
}
