import type { ReactNode } from "react";

export function Panel({
  title,
  right,
  children,
  className = "",
  bodyClass = "p-4",
}: {
  title?: ReactNode;
  right?: ReactNode;
  children: ReactNode;
  className?: string;
  bodyClass?: string;
}) {
  return (
    <section className={`glass flex w-full min-w-0 min-h-0 flex-col ${className}`}>
      {(title || right) && (
        <header className="flex items-center justify-between gap-3 border-b border-line px-4 py-2.5">
          <h2 className="label">{title}</h2>
          <div className="flex items-center gap-2">{right}</div>
        </header>
      )}
      <div className={`min-h-0 flex-1 ${bodyClass}`}>{children}</div>
    </section>
  );
}

export function Switch({
  checked,
  onChange,
  disabled,
  label,
}: {
  checked: boolean;
  onChange: (v: boolean) => void;
  disabled?: boolean | undefined;
  label: string;
}) {
  return (
    <button
      type="button"
      role="switch"
      aria-checked={checked}
      aria-label={label}
      disabled={disabled}
      className="switch focus-ring"
      onClick={() => onChange(!checked)}
    />
  );
}

export function Spinner({ size = 12 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" className="anim-spin" aria-hidden>
      <circle cx="12" cy="12" r="9" fill="none" stroke="currentColor" strokeOpacity="0.25" strokeWidth="3" />
      <path d="M21 12a9 9 0 0 0-9-9" fill="none" stroke="currentColor" strokeWidth="3" strokeLinecap="round" />
    </svg>
  );
}

export function PqBadge({ pq }: { pq: boolean }) {
  return pq ? (
    <span className="chip chip-emerald" title="Hybrid X25519 + ML-KEM-1024 PSK, rotated">
      PQ
    </span>
  ) : (
    <span className="chip chip-amber" title="Classical WireGuard (no post-quantum PSK)">
      CLASSICAL
    </span>
  );
}

export function Empty({ children }: { children: ReactNode }) {
  return <div className="flex h-full min-h-16 items-center justify-center px-4 text-center text-mute">{children}</div>;
}

export function Stat({ label, value, tone }: { label: string; value: ReactNode; tone?: string | undefined }) {
  return (
    <div className="min-w-0">
      <div className="label !text-[9.5px]">{label}</div>
      <div className="num mt-0.5 truncate text-[15px]" style={tone ? { color: tone } : undefined}>
        {value}
      </div>
    </div>
  );
}

/** Two-step confirm for destructive actions (no blocking dialogs). */
export function ConfirmButton({
  children,
  confirmLabel,
  onConfirm,
  className = "btn btn-sm",
  disabled,
}: {
  children: ReactNode;
  confirmLabel: string;
  onConfirm: () => void;
  className?: string;
  disabled?: boolean | undefined;
}) {
  return (
    <details className="relative inline-block">
      <summary className={`${className} list-none`} aria-disabled={disabled}>
        {children}
      </summary>
      <div className="glass absolute right-0 z-20 mt-1 flex items-center gap-2 !rounded-lg p-2 whitespace-nowrap">
        <button
          type="button"
          className="btn btn-sm btn-crimson"
          disabled={disabled}
          onClick={(e) => {
            (e.currentTarget.closest("details") as HTMLDetailsElement | null)?.removeAttribute("open");
            onConfirm();
          }}
        >
          {confirmLabel}
        </button>
      </div>
    </details>
  );
}
