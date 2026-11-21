import { useStore } from "../hooks/store";
import { PROFILES, type Profile } from "../ipc/types";
import { ACTIVE_STATES, PROFILE_META } from "../lib/format";

const ICONS: Record<Profile, string> = {
  auto: "M4 12h4l3-7 4 14 3-7h2",
  warp: "M13 2 4 14h7l-1 8 9-12h-7l1-8Z",
  multihop: "M5 18a2 2 0 1 0 0-4 2 2 0 0 0 0 4Zm14-8a2 2 0 1 0 0-4 2 2 0 0 0 0 4ZM7 15l10-6",
  stealth: "M3 12s3.5-6 9-6 9 6 9 6-3.5 6-9 6-9-6-9-6Zm6 0a3 3 0 1 0 6 0 3 3 0 0 0-6 0M4 20 20 4",
  "max-anonymity": "M12 3 4 7v5c0 4.4 3.4 8.4 8 9 4.6-.6 8-4.6 8-9V7l-8-4Zm-3 9h6M12 9v6",
  f2f: "M8 11a3 3 0 1 0 0-6 3 3 0 0 0 0 6Zm8 0a3 3 0 1 0 0-6 3 3 0 0 0 0 6ZM2 20c0-3 3-5 6-5s6 2 6 5m-2-5c1-.6 2.4-1 4-1 3 0 6 2 6 5",
};

export function ModeSelector({
  profile,
  setProfile,
  country,
  setCountry,
}: {
  profile: Profile;
  setProfile: (p: Profile) => void;
  country: string;
  setCountry: (c: string) => void;
}) {
  const { s, act } = useStore();
  const state = s.status?.state;
  const active = state ? ACTIVE_STATES.includes(state) : false;
  const running = s.status?.profile ?? null;

  const pick = (p: Profile) => {
    setProfile(p);
    // Switching mode while a tunnel is up re-runs Up with the new profile.
    if (active && p !== running) void act.connect(p, country || null, null);
  };

  return (
    <div className="flex items-stretch gap-2">
      <div role="radiogroup" aria-label="Connection mode" className="grid flex-1 grid-cols-6 gap-2">
        {PROFILES.map((p) => {
          const sel = p === profile;
          const live = active && p === running;
          return (
            <button
              key={p}
              type="button"
              role="radio"
              aria-checked={sel}
              disabled={!!s.busy.connect}
              onClick={() => pick(p)}
              className={`glass focus-ring group relative flex min-w-0 flex-col items-start gap-1 !rounded-xl px-3 py-2.5 text-left transition-colors ${
                sel ? "!border-cyan/60 !bg-cyan/[0.07]" : "hover:!border-white/20"
              }`}
            >
              <div className="flex w-full items-center justify-between">
                <svg width="16" height="16" viewBox="0 0 24 24" aria-hidden>
                  <path
                    d={ICONS[p]}
                    fill="none"
                    stroke={sel ? "#00f0ff" : "#8a96a8"}
                    strokeWidth="1.8"
                    strokeLinecap="round"
                    strokeLinejoin="round"
                  />
                </svg>
                {live && <span className="chip chip-cyan !h-4 !px-1.5 !text-[9px]">LIVE</span>}
                {!live && p === "auto" && <span className="chip !h-4 !px-1.5 !text-[9px]">DEFAULT</span>}
              </div>
              <div className={`truncate text-[12.5px] font-semibold ${sel ? "text-[#c9fbff]" : "text-ink"}`}>
                {PROFILE_META[p].title}
              </div>
              <div className="line-clamp-2 text-[10.5px] leading-tight text-mute">{PROFILE_META[p].blurb}</div>
            </button>
          );
        })}
      </div>
      <label className="glass flex w-[104px] shrink-0 flex-col justify-center gap-1 !rounded-xl px-3">
        <span className="label !text-[9px]">Country</span>
        <input
          className="field num !h-7 uppercase"
          value={country}
          maxLength={2}
          placeholder="any"
          spellCheck={false}
          aria-label="Optional exit country filter (ISO code)"
          onChange={(e) => setCountry(e.target.value.replace(/[^a-zA-Z]/g, "").toUpperCase())}
        />
      </label>
    </div>
  );
}
