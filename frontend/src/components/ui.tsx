import type { Severity, Status } from "../types";

export function scoreColor(score: number | null): string {
  if (score === null) return "#94a3b8";
  if (score >= 80) return "#16a34a";
  if (score >= 50) return "#d97706";
  return "#dc2626";
}

export function Gauge({ score, size = 112, label }: { score: number | null; size?: number; label?: string }) {
  const r = size / 2 - 9;
  const c = 2 * Math.PI * r;
  const pct = score === null ? 0 : Math.max(0, Math.min(100, score)) / 100;
  const color = scoreColor(score);
  return (
    <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`} role="img" aria-label={`${label ?? ""} score ${score ?? "n/a"}`}>
      <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke="#e2e8f0" strokeWidth={9} />
      <circle
        cx={size / 2} cy={size / 2} r={r} fill="none" stroke={color} strokeWidth={9} strokeLinecap="round"
        strokeDasharray={`${c * pct} ${c}`} transform={`rotate(-90 ${size / 2} ${size / 2})`}
        style={{ transition: "stroke-dasharray 0.8s ease" }}
      />
      <text x="50%" y="50%" textAnchor="middle" dominantBaseline="central" fontSize={size / 4} fontWeight={700} fill={color}>
        {score === null ? "n/a" : Math.round(score)}
      </text>
    </svg>
  );
}

const SEV: Record<Severity, string> = {
  critical: "bg-red-100 text-red-800",
  high: "bg-orange-100 text-orange-800",
  medium: "bg-amber-100 text-amber-800",
  low: "bg-sky-100 text-sky-800",
};
const ST: Record<Status, string> = {
  failed: "bg-red-100 text-red-800",
  passed: "bg-green-100 text-green-800",
  needs_review: "bg-amber-100 text-amber-800",
  not_assessable: "bg-slate-100 text-slate-600",
};

export const SeverityBadge = ({ s }: { s: Severity }) => <span className={`badge ${SEV[s]}`}>{s}</span>;
export const StatusBadge = ({ s }: { s: Status }) => <span className={`badge ${ST[s]}`}>{s.replace("_", " ")}</span>;

export function Diff({ text }: { text: string }) {
  return (
    <pre className="overflow-x-auto rounded-lg bg-slate-900 p-3 text-xs leading-relaxed text-slate-200">
      {text.split("\n").map((l, i) => {
        const cls = l.startsWith("+++") || l.startsWith("---") || l.startsWith("@@")
          ? "text-sky-300"
          : l.startsWith("+") ? "text-green-300" : l.startsWith("-") ? "text-red-300" : l.startsWith("#") ? "text-slate-400" : "";
        return <div key={i} className={cls}>{l || " "}</div>;
      })}
    </pre>
  );
}

export function Spinner() {
  return <span className="inline-block h-4 w-4 animate-spin rounded-full border-2 border-indigo-200 border-t-indigo-600" />;
}
