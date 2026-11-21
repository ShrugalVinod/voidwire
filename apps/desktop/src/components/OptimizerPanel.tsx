import { useStore } from "../hooks/store";
import { TRANSPORT_LABEL, formatMs } from "../lib/format";
import { Empty, Panel, PqBadge, Spinner, Stat } from "./ui";

export function OptimizerPanel() {
  const { s, act } = useStore();
  const d = s.decision;
  const candidates = d ? [...d.candidates].sort((a, b) => b.score - a.score) : [];
  const best = candidates[0]?.score ?? 0;

  return (
    <Panel
      title="Optimizer decision"
      className="min-h-0"
      bodyClass="flex min-h-0 flex-col"
      right={
        <button type="button" className="btn btn-sm" disabled={!!s.busy.optimize} onClick={() => void act.optimize()}>
          {s.busy.optimize && <Spinner />} {s.busy.optimize ? "Measuring…" : "Re-measure"}
        </button>
      }
    >
      {!d ? (
        <Empty>
          No measurement yet. The optimizer probes every gateway and transport (RTT, loss, handshake, DPI,
          throughput) when you connect or press Re-measure.
        </Empty>
      ) : (
        <>
          <div className="grid grid-cols-[1.6fr_1fr_0.6fr_0.6fr_0.6fr] gap-4 px-4 pt-3">
            <Stat label="Circuit" value={d.hops.length ? d.hops.join(" → ") : "—"} tone="#00f0ff" />
            <Stat label="Transport" value={TRANSPORT_LABEL[d.transport]} />
            <Stat label="MTU" value={d.mtu} />
            <Stat label="MSS v4" value={d.mss_v4} />
            <Stat label="DAITA" value={d.daita ? "on" : "off"} tone={d.daita ? "#10b981" : undefined} />
          </div>
          <div className="flex flex-wrap items-center gap-1.5 px-4 pt-2.5">
            {d.verdict.udp_hostile && <span className="chip chip-amber">UDP hostile network</span>}
            {d.verdict.quic_blocked && <span className="chip chip-amber">QUIC blocked</span>}
            {d.verdict.wg_signature_filtered && <span className="chip chip-amber">WireGuard signature filtered</span>}
            {!d.verdict.udp_hostile && !d.verdict.quic_blocked && !d.verdict.wg_signature_filtered && (
              <span className="chip chip-emerald">No DPI interference detected</span>
            )}
            <span className="selectable text-[11.5px] text-mute">{d.reason}</span>
          </div>
          <div className="scroll-y mt-2 min-h-0 flex-1 px-2 pb-2">
            <table className="w-full border-separate border-spacing-0 text-[11.5px]">
              <thead className="sticky top-0 bg-[#0d121b]">
                <tr className="text-left text-dim">
                  {["Gateway", "Transport", "Handshake", "RTT", "Jitter", "Loss", "Mb/s", "", "Score"].map((h) => (
                    <th key={h} className="px-2 py-1.5 font-semibold">
                      {h}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {candidates.map((c) => {
                  const chosen = d.hops.includes(c.node_name) && c.transport === d.transport;
                  return (
                    <tr
                      key={`${c.node_name}/${c.transport}`}
                      className={chosen ? "bg-cyan/[0.07] text-[#c9fbff]" : c.reachable ? "" : "text-dim"}
                    >
                      <td className="truncate px-2 py-1">
                        {chosen && <span className="mr-1 text-cyan">▸</span>}
                        {c.node_name}
                      </td>
                      <td className="px-2 py-1">{TRANSPORT_LABEL[c.transport]}</td>
                      <td className="num px-2 py-1">{c.reachable ? formatMs(c.handshake_ms) : "unreachable"}</td>
                      <td className="num px-2 py-1">{formatMs(c.rtt_ms, 1)}</td>
                      <td className="num px-2 py-1">{formatMs(c.jitter_ms, 1)}</td>
                      <td className="num px-2 py-1">{(c.loss * 100).toFixed(1)}%</td>
                      <td className="num px-2 py-1">{c.throughput_mbps == null ? "—" : c.throughput_mbps.toFixed(0)}</td>
                      <td className="px-2 py-1">
                        <PqBadge pq={c.post_quantum} />
                      </td>
                      <td className="px-2 py-1">
                        <div className="flex items-center gap-2">
                          <div className="h-1.5 w-14 overflow-hidden rounded bg-white/5">
                            <div
                              className="h-full rounded"
                              style={{
                                width: `${best > 0 ? Math.max(2, (c.score / best) * 100) : 0}%`,
                                background: chosen ? "#00f0ff" : "#5a6577",
                              }}
                            />
                          </div>
                          <span className="num">{c.score.toFixed(1)}</span>
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </>
      )}
    </Panel>
  );
}
