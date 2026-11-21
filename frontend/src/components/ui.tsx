import { useEffect, useId, useState, type ReactNode, type SVGProps } from "react";
import type { Severity, Status } from "../types";

// ------------------------------------------------------------------ icons
type IconName =
  | "arrow-up-right" | "arrow-right" | "arrow-left" | "github" | "upload" | "check" | "shield" | "sparkle"
  | "flow" | "file" | "database" | "alert" | "refresh" | "download" | "plus" | "terminal" | "chevron"
  | "layers" | "list" | "lock" | "eye" | "scan" | "book";

const PATHS: Record<IconName, ReactNode> = {
  "arrow-up-right": <path d="M7 17 17 7M8 7h9v9" />,
  "arrow-right": <path d="M5 12h14M13 6l6 6-6 6" />,
  "arrow-left": <path d="M19 12H5M11 6l-6 6 6 6" />,
  github: <path d="M9 19c-4.3 1.4-4.3-2.5-6-3m12 5v-3.5c0-1 .1-1.4-.5-2 2.8-.3 5.5-1.4 5.5-6a4.6 4.6 0 0 0-1.3-3.2 4.2 4.2 0 0 0-.1-3.2s-1.1-.3-3.5 1.3a12.3 12.3 0 0 0-6.2 0C6.5 2.8 5.4 3.1 5.4 3.1a4.2 4.2 0 0 0-.1 3.2A4.6 4.6 0 0 0 4 9.5c0 4.6 2.7 5.7 5.5 6-.6.6-.6 1.2-.5 2V21" />,
  upload: <path d="M12 16V4m0 0-5 5m5-5 5 5M4 16v2a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2v-2" />,
  check: <path d="m5 12.5 4.5 4.5L19 7.5" />,
  shield: <path d="M12 3 4.5 6v5.5c0 4.7 3.2 8.4 7.5 9.5 4.3-1.1 7.5-4.8 7.5-9.5V6L12 3Z" />,
  sparkle: <path d="M12 3c.6 4.3 2.7 6.4 7 7-4.3.6-6.4 2.7-7 7-.6-4.3-2.7-6.4-7-7 4.3-.6 6.4-2.7 7-7ZM19 15c.3 1.7 1 2.4 2.5 2.5-1.6.2-2.3.9-2.5 2.5-.2-1.6-.9-2.3-2.5-2.5 1.6-.1 2.3-.8 2.5-2.5Z" />,
  flow: <><circle cx="5" cy="6" r="2.2" /><circle cx="19" cy="18" r="2.2" /><path d="M7.2 6H12a3 3 0 0 1 3 3v6a3 3 0 0 0 1.8 2.8" /></>,
  file: <><path d="M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8l-5-5Z" /><path d="M14 3v5h5" /></>,
  database: <><ellipse cx="12" cy="5.5" rx="7" ry="2.5" /><path d="M5 5.5v13c0 1.4 3.1 2.5 7 2.5s7-1.1 7-2.5v-13M5 12c0 1.4 3.1 2.5 7 2.5s7-1.1 7-2.5" /></>,
  alert: <><path d="M12 4 2.8 19.5h18.4L12 4Z" /><path d="M12 10v4m0 3h.01" /></>,
  refresh: <path d="M20 11a8 8 0 0 0-14.6-4.5L4 8m0-4v4h4M4 13a8 8 0 0 0 14.6 4.5L20 16m0 4v-4h-4" />,
  download: <path d="M12 4v12m0 0-5-5m5 5 5-5M4 20h16" />,
  plus: <path d="M12 5v14M5 12h14" />,
  terminal: <><rect x="3" y="4.5" width="18" height="15" rx="3" /><path d="m7.5 10 3 2.5-3 2.5M13 15h3.5" /></>,
  chevron: <path d="m9 6 6 6-6 6" />,
  layers: <path d="m12 3 9 5-9 5-9-5 9-5Zm-9 9 9 5 9-5M3 16l9 5 9-5" />,
  list: <path d="M9 6h11M9 12h11M9 18h11M4.5 6h.01M4.5 12h.01M4.5 18h.01" />,
  lock: <><rect x="4.5" y="10.5" width="15" height="10" rx="2.5" /><path d="M8 10.5V7.5a4 4 0 0 1 8 0v3" /></>,
  eye: <><path d="M2.5 12S6 5 12 5s9.5 7 9.5 7-3.5 7-9.5 7-9.5-7-9.5-7Z" /><circle cx="12" cy="12" r="2.8" /></>,
  scan: <path d="M4 8V6a2 2 0 0 1 2-2h2m8 0h2a2 2 0 0 1 2 2v2m0 8v2a2 2 0 0 1-2 2h-2m-8 0H6a2 2 0 0 1-2-2v-2M4 12h16" />,
  book: <path d="M5 4.5A1.5 1.5 0 0 1 6.5 3H19v15H6.5A1.5 1.5 0 0 0 5 19.5m0-15v15M5 19.5A1.5 1.5 0 0 0 6.5 21H19" />,
};

export function Icon({ name, size = 18, className, ...rest }: { name: IconName; size?: number } & SVGProps<SVGSVGElement>) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.8}
      strokeLinecap="round" strokeLinejoin="round" aria-hidden="true" className={className} {...rest}>
      {PATHS[name]}
    </svg>
  );
}

/** Round arrow chip used on bento cards (the "↗" in a circle). */
export function ArrowChip({ dark = false, className = "" }: { dark?: boolean; className?: string }) {
  return (
    <span className={`inline-flex h-9 w-9 shrink-0 items-center justify-center rounded-full transition group-hover:rotate-45 ${dark ? "bg-ink-950 text-white" : "bg-white/10 text-white"} ${className}`}>
      <Icon name="arrow-up-right" size={16} />
    </span>
  );
}

// ------------------------------------------------------------------ score
export function scoreColor(score: number | null): string {
  if (score === null) return "#71717a";
  if (score >= 80) return "#d4ff3f";
  if (score >= 50) return "#ffd84d";
  return "#ff5c7a";
}

function useCountUp(target: number | null, ms = 1100) {
  const [v, setV] = useState(0);
  useEffect(() => {
    if (target === null) return;
    const reduce = window.matchMedia?.("(prefers-reduced-motion: reduce)").matches;
    if (reduce) { setV(target); return; }
    let raf = 0;
    const t0 = performance.now();
    const tick = (t: number) => {
      const p = Math.min(1, (t - t0) / ms);
      setV(target * (1 - Math.pow(1 - p, 3)));
      if (p < 1) raf = requestAnimationFrame(tick);
    };
    raf = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(raf);
  }, [target, ms]);
  return v;
}

export function Gauge({ score, size = 112, label, stroke = 10 }: { score: number | null; size?: number; label?: string; stroke?: number }) {
  const uid = useId().replace(/[^a-zA-Z0-9]/g, "");
  const shown = useCountUp(score);
  const r = size / 2 - stroke - 4;
  const c = 2 * Math.PI * r;
  const pct = score === null ? 0 : Math.max(0, Math.min(100, shown)) / 100;
  const color = scoreColor(score);
  const ticks = Array.from({ length: 40 }, (_, i) => i);
  return (
    <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`} role="img" aria-label={`${label ?? ""} score ${score === null ? "not available" : Math.round(score)}`}>
      <defs>
        <linearGradient id={`g${uid}`} x1="0" y1="0" x2="1" y2="1">
          <stop offset="0" stopColor="#ffffff" stopOpacity={0.95} />
          <stop offset="0.35" stopColor={color} />
          <stop offset="1" stopColor={color} stopOpacity={0.75} />
        </linearGradient>
        <filter id={`f${uid}`} x="-50%" y="-50%" width="200%" height="200%">
          <feGaussianBlur stdDeviation={size / 28} />
        </filter>
        <radialGradient id={`r${uid}`}>
          <stop offset="0" stopColor={color} stopOpacity={0.18} />
          <stop offset="1" stopColor={color} stopOpacity={0} />
        </radialGradient>
      </defs>
      <circle cx={size / 2} cy={size / 2} r={r - stroke} fill={`url(#r${uid})`} />
      {ticks.map((i) => {
        const a = (i / ticks.length) * Math.PI * 2 - Math.PI / 2;
        const r1 = r + stroke / 2 + 2, r2 = r1 + 2.5;
        return <line key={i} x1={size / 2 + Math.cos(a) * r1} y1={size / 2 + Math.sin(a) * r1} x2={size / 2 + Math.cos(a) * r2} y2={size / 2 + Math.sin(a) * r2}
          stroke="#ffffff" strokeOpacity={i / ticks.length <= pct ? 0.35 : 0.08} strokeWidth={1} />;
      })}
      <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke="rgba(255,255,255,.07)" strokeWidth={stroke} />
      {score !== null && (
        <>
          <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke={color} strokeOpacity={0.55} strokeWidth={stroke} strokeLinecap="round"
            strokeDasharray={`${c * pct} ${c}`} transform={`rotate(-90 ${size / 2} ${size / 2})`} filter={`url(#f${uid})`} />
          <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke={`url(#g${uid})`} strokeWidth={stroke} strokeLinecap="round"
            strokeDasharray={`${c * pct} ${c}`} transform={`rotate(-90 ${size / 2} ${size / 2})`} />
        </>
      )}
      <text x="50%" y="50%" textAnchor="middle" dominantBaseline="central" fontSize={size / 3.6} fontWeight={700}
        fill="#ffffff" style={{ fontFamily: "'Space Grotesk', Inter, sans-serif", letterSpacing: "-0.03em" }}>
        {score === null ? "n/a" : Math.round(shown)}
      </text>
    </svg>
  );
}

// ------------------------------------------------------------------ badges
const SEV: Record<Severity, string> = {
  critical: "bg-rose-500/15 text-rose-300 ring-1 ring-inset ring-rose-400/30",
  high: "bg-orange-500/15 text-orange-300 ring-1 ring-inset ring-orange-400/30",
  medium: "bg-amber-400/15 text-amber-200 ring-1 ring-inset ring-amber-300/30",
  low: "bg-sky-400/15 text-sky-200 ring-1 ring-inset ring-sky-300/30",
};
const ST: Record<Status, string> = {
  failed: "bg-rose-500 text-white shadow-[0_0_20px_-4px_rgba(244,63,94,.8)]",
  passed: "bg-lime text-ink-950 shadow-[0_0_20px_-6px_rgba(212,255,63,.8)]",
  needs_review: "bg-sun text-ink-950",
  not_assessable: "bg-white/10 text-zinc-300",
};
const SEV_DOT: Record<Severity, string> = { critical: "bg-rose-400", high: "bg-orange-400", medium: "bg-amber-300", low: "bg-sky-300" };

export const SeverityBadge = ({ s }: { s: Severity }) => (
  <span className={`badge ${SEV[s]}`}><i className={`h-1.5 w-1.5 rounded-full ${SEV_DOT[s]}`} />{s}</span>
);
export const StatusBadge = ({ s }: { s: Status }) => <span className={`badge ${ST[s]}`}>{s.replace("_", " ")}</span>;

// ------------------------------------------------------------------ code
export function Diff({ text }: { text: string }) {
  return (
    <div className="overflow-hidden rounded-2xl border border-white/[.07] bg-ink-950/90 shadow-lift">
      <div className="flex items-center gap-1.5 border-b border-white/[.06] px-4 py-2.5">
        <i className="h-2.5 w-2.5 rounded-full bg-rose-400/80" /><i className="h-2.5 w-2.5 rounded-full bg-amber-300/80" /><i className="h-2.5 w-2.5 rounded-full bg-lime/80" />
        <span className="ml-3 font-mono text-[11px] text-zinc-500">patch.diff</span>
      </div>
      <pre className="overflow-x-auto py-3 font-mono text-xs leading-relaxed text-zinc-300">
        {text.split("\n").map((l, i) => {
          const cls = l.startsWith("+++") || l.startsWith("---") || l.startsWith("@@")
            ? "text-violet-300"
            : l.startsWith("+") ? "bg-lime/[.07] text-lime-400" : l.startsWith("-") ? "bg-rose-500/10 text-rose-300" : l.startsWith("#") ? "text-zinc-500" : "";
          return <div key={i} className={`px-4 ${cls}`}>{l || " "}</div>;
        })}
      </pre>
    </div>
  );
}

export function Spinner({ className = "" }: { className?: string }) {
  return <span className={`inline-block h-4 w-4 animate-spin rounded-full border-2 border-violet-400/25 border-t-lime ${className}`} />;
}

/** Section heading with numbered kicker, matches the "05." style. */
export function SectionHead({ n, title, sub, right }: { n: string; title: string; sub?: string; right?: ReactNode }) {
  return (
    <div className="mb-5 flex flex-wrap items-end justify-between gap-3">
      <div>
        <span className="inline-flex h-7 min-w-7 items-center justify-center rounded-full bg-white/[.06] px-2 font-mono text-[11px] text-zinc-400 ring-1 ring-white/10">{n}</span>
        <h3 className="section-title mt-2">{title}</h3>
        {sub && <p className="mt-1 max-w-2xl text-sm text-zinc-400">{sub}</p>}
      </div>
      {right}
    </div>
  );
}
