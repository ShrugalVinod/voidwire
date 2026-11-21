import { useStore } from "../hooks/store";
import { formatCount, formatDuration } from "../lib/format";
import { Panel, PqBadge } from "./ui";

export function CryptoPanel() {
  const { s } = useStore();
  const st = s.status;
  const hops = st?.hops ?? [];
  const classical = hops.filter((h) => !h.post_quantum);
  const allClassical = hops.length > 0 && classical.length === hops.length;
  const rotate = s.settings?.pq_rotate_secs;

  return (
    <Panel title="Crypto suite" className="shrink-0">
      {!st ? (
        <div className="text-mute">—</div>
      ) : (
        <div className="grid gap-2.5">
          <div className="num selectable rounded-lg border border-line bg-black/30 px-2.5 py-2 text-[11.5px] leading-relaxed break-words text-[#c9fbff]">
            {st.crypto_suite || "no session"}
          </div>
          {hops.length > 0 && (
            <ul className="grid gap-1">
              {hops.map((h, i) => (
                <li key={`${h.name}-${i}`} className="flex items-center justify-between gap-2 text-[12px]">
                  <span className="truncate">
                    <span className="num text-dim">{i + 1}.</span> {h.name}
                  </span>
                  <PqBadge pq={h.post_quantum} />
                </li>
              ))}
            </ul>
          )}
          {classical.length > 0 && (
            <div className="rounded-lg border border-amber/40 bg-amber/[0.07] px-2.5 py-2 text-[11.5px] leading-snug text-[#ffdca0]">
              {allClassical
                ? "This circuit is classical WireGuard only: no post-quantum protection. Traffic recorded today could be decrypted by a future quantum computer."
                : `Classical WireGuard on ${classical.map((h) => h.name).join(", ")} (no VWCP, e.g. Cloudflare WARP). Post-quantum protection applies on the VoidWire hops only.`}
            </div>
          )}
          <div className="grid grid-cols-2 gap-x-4 gap-y-1 text-[11.5px]">
            <span className="text-mute">Last PQ rotation</span>
            <span className="num text-right">
              {st.last_rotation_secs_ago == null ? "—" : `${formatDuration(st.last_rotation_secs_ago)} ago`}
            </span>
            <span className="text-mute">Rotation interval</span>
            <span className="num text-right">{rotate ? `${rotate}s` : "—"}</span>
            <span className="text-mute">PQ rotations / handshakes</span>
            <span className="num text-right">
              {formatCount(st.telemetry.pq_rotations)} / {formatCount(st.telemetry.handshakes)}
            </span>
          </div>
        </div>
      )}
    </Panel>
  );
}
