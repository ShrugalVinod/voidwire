import { useState } from "react";
import { useStore } from "../hooks/store";
import { NODE_KIND_LABEL, TRANSPORT_LABEL } from "../lib/format";
import { ConfirmButton, Empty, Panel, PqBadge, Spinner } from "./ui";

export function NodesPanel() {
  const { s, act } = useStore();
  const [uri, setUri] = useState("");
  const [confName, setConfName] = useState("");
  const [confCountry, setConfCountry] = useState("");
  const [conf, setConf] = useState("");
  const nodes = s.nodes;
  const hasWarp = nodes?.some((n) => n.kind === "warp") ?? false;
  const trimmed = uri.trim();
  const kind = trimmed.startsWith("voidwire://f2f/") ? "f2f" : trimmed.startsWith("voidwire://node/") ? "node" : null;

  return (
    <div className="grid min-h-0 flex-1 grid-cols-[1fr_340px] gap-3">
      <Panel
        title="Gateways"
        className="min-h-0"
        bodyClass="scroll-y min-h-0 p-3"
        right={
          <button type="button" className="btn btn-sm" disabled={!!s.busy.nodes} onClick={() => void act.refreshNodes()}>
            Refresh
          </button>
        }
      >
        {nodes === null ? (
          <Empty>Loading node list from voidwired…</Empty>
        ) : nodes.length === 0 ? (
          <Empty>No gateways yet. Register free Cloudflare WARP or import a node / friend invite.</Empty>
        ) : (
          <ul className="grid gap-2">
            {nodes.map((n) => (
              <li key={n.name} className="flex items-center gap-3 rounded-xl border border-line bg-black/20 px-3 py-2.5">
                <div className="min-w-0 flex-1">
                  <div className="flex items-center gap-2">
                    <span className="truncate font-semibold">{n.name}</span>
                    <PqBadge pq={n.post_quantum} />
                    {n.country && <span className="chip num">{n.country}</span>}
                  </div>
                  <div className="mt-0.5 flex flex-wrap items-center gap-1.5 text-[11px] text-mute">
                    <span>{NODE_KIND_LABEL[n.kind]}</span>
                    <span className="text-dim">·</span>
                    <span>role {n.role}</span>
                    <span className="text-dim">·</span>
                    {n.transports.map((t) => (
                      <span key={t} className="chip !h-[18px]">
                        {TRANSPORT_LABEL[t]}
                      </span>
                    ))}
                  </div>
                </div>
                <ConfirmButton
                  confirmLabel={`Remove ${n.name}`}
                  disabled={!!s.busy[`remove:${n.name}`]}
                  onConfirm={() => void act.removeNode(n.name)}
                >
                  {s.busy[`remove:${n.name}`] ? <Spinner /> : "Remove"}
                </ConfirmButton>
              </li>
            ))}
          </ul>
        )}
      </Panel>

      <div className="flex min-h-0 flex-col gap-3">
        <Panel title="Instant free">
          <p className="mb-3 text-[12px] text-mute">
            Registers an anonymous Cloudflare WARP device (no account, no e-mail). WARP hops are classical WireGuard; use
            them as an entry in front of a VoidWire exit for post-quantum protection.
          </p>
          <button type="button" className="btn btn-cyan w-full" disabled={!!s.busy.warp} onClick={() => void act.registerWarp()}>
            {s.busy.warp && <Spinner />} {hasWarp ? "Re-register WARP device" : "Get free WARP"}
          </button>
        </Panel>
        <Panel title="Import WireGuard config">
          <form
            className="grid gap-2"
            onSubmit={(e) => {
              e.preventDefault();
              void act.importWireGuard(confName.trim(), conf, confCountry.trim() || null).then((ok) => {
                if (ok) {
                  setConf("");
                  setConfName("");
                  setConfCountry("");
                }
              });
            }}
          >
            <p className="text-[11px] text-mute">
              Any provider that gives WireGuard configs (Proton VPN, Mullvad, IVPN, Surfshark…). Your DNS still goes through
              VoidWire’s encrypted vault.
            </p>
            <div className="grid grid-cols-[1fr_64px] gap-2">
              <input className="field" placeholder="Name, e.g. Proton US" value={confName} onChange={(e) => setConfName(e.target.value)} aria-label="Gateway name" />
              <input className="field uppercase" placeholder="US" maxLength={2} value={confCountry} onChange={(e) => setConfCountry(e.target.value)} aria-label="Country code" />
            </div>
            <textarea
              className="field !text-[11px]"
              rows={4}
              spellCheck={false}
              placeholder={"[Interface]\nPrivateKey = …\n[Peer]\n…"}
              value={conf}
              onChange={(e) => setConf(e.target.value)}
              aria-label="WireGuard config"
            />
            <div className="flex items-center justify-between gap-2">
              <label className="btn btn-sm cursor-pointer">
                Choose .conf file
                <input
                  type="file"
                  accept=".conf,text/plain"
                  className="hidden"
                  onChange={(e) => {
                    const f = e.target.files?.[0];
                    if (!f) return;
                    void f.text().then((txt) => {
                      setConf(txt);
                      if (!confName) setConfName(f.name.replace(/\.conf$/i, ""));
                    });
                    e.target.value = "";
                  }}
                />
              </label>
              <button type="submit" className="btn btn-sm btn-cyan" disabled={!confName.trim() || !conf.includes("[Interface]") || !!s.busy.importConf}>
                {s.busy.importConf && <Spinner />} Import gateway
              </button>
            </div>
          </form>
        </Panel>
        <Panel title="Import">
          <form
            className="grid gap-2"
            onSubmit={(e) => {
              e.preventDefault();
              void act.importUri(uri).then((ok) => ok && setUri(""));
            }}
          >
            <textarea
              className="field !text-[11px]"
              rows={4}
              spellCheck={false}
              placeholder="voidwire://node/…  or  voidwire://f2f/…"
              value={uri}
              onChange={(e) => setUri(e.target.value)}
              aria-label="Node URI or friend invite"
            />
            <div className="flex items-center justify-between gap-2">
              <span className="text-[11px] text-dim">
                {kind === "node" ? "Node descriptor" : kind === "f2f" ? "Friend invite (single use)" : trimmed ? "Unrecognised URI" : " "}
              </span>
              <button type="submit" className="btn btn-sm btn-cyan" disabled={!kind || !!s.busy.import}>
                {s.busy.import && <Spinner />} {kind === "f2f" ? "Redeem invite" : "Import node"}
              </button>
            </div>
          </form>
        </Panel>
      </div>
    </div>
  );
}
