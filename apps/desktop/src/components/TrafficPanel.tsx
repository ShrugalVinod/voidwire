import { useStore, type RatePoint } from "../hooks/store";
import { formatBytes, formatCount, formatRate } from "../lib/format";
import { Panel } from "./ui";

const SW = 240;
const SH = 46;

function Sparkline({ points, pick, color, label }: { points: RatePoint[]; pick: (p: RatePoint) => number; color: string; label: string }) {
  const vals = points.map(pick);
  const max = Math.max(1, ...vals);
  const n = vals.length;
  const step = n > 1 ? SW / (n - 1) : SW;
  const coords = vals.map((v, i) => [i * step, SH - 2 - (v / max) * (SH - 6)] as const);
  const line = coords.map(([x, y], i) => `${i ? "L" : "M"}${x.toFixed(1)} ${y.toFixed(1)}`).join("");
  const area = n > 1 ? `${line}L${SW} ${SH}L0 ${SH}Z` : "";
  const last = vals[n - 1] ?? 0;
  const id = `sg-${label}`;
  return (
    <div>
      <div className="flex items-baseline justify-between">
        <span className="label !text-[9.5px]">{label}</span>
        <span className="num text-[15px]" style={{ color }}>
          {n ? formatRate(last) : "—"}
        </span>
      </div>
      <svg viewBox={`0 0 ${SW} ${SH}`} preserveAspectRatio="none" className="mt-1 block h-[46px] w-full" aria-hidden>
        <defs>
          <linearGradient id={id} x1="0" y1="0" x2="0" y2="1">
            <stop offset="0" stopColor={color} stopOpacity="0.35" />
            <stop offset="1" stopColor={color} stopOpacity="0" />
          </linearGradient>
        </defs>
        <path d={`M0 ${SH - 0.5}H${SW}`} stroke="#ffffff" strokeOpacity="0.06" />
        {n > 1 && <path d={area} fill={`url(#${id})`} />}
        {n > 1 && <path d={line} fill="none" stroke={color} strokeWidth="1.6" vectorEffect="non-scaling-stroke" />}
      </svg>
    </div>
  );
}

export function TrafficPanel() {
  const { s } = useStore();
  const t = s.telemetry;
  return (
    <Panel title="Throughput" className="shrink-0" right={<span className="text-[11px] text-dim">{s.rates.length ? `live · ${s.rates.length} samples` : "waiting for samples"}</span>}>
      <div className="grid gap-3">
        <Sparkline points={s.rates} pick={(p) => p.rx} color="#00f0ff" label="Download" />
        <Sparkline points={s.rates} pick={(p) => p.tx} color="#10b981" label="Upload" />
        <div className="grid grid-cols-2 gap-x-4 gap-y-1 border-t border-line pt-2.5 text-[11.5px]">
          <span className="text-mute">Received</span>
          <span className="num text-right">{t ? formatBytes(t.rx_bytes) : "—"}</span>
          <span className="text-mute">Sent</span>
          <span className="num text-right">{t ? formatBytes(t.tx_bytes) : "—"}</span>
          <span className="text-mute">Packets rx / tx</span>
          <span className="num text-right">{t ? `${formatCount(t.rx_packets)} / ${formatCount(t.tx_packets)}` : "—"}</span>
          <span className="text-mute">DAITA chaff sent</span>
          <span className="num text-right">{t ? formatCount(t.chaff_sent) : "—"}</span>
        </div>
      </div>
    </Panel>
  );
}
