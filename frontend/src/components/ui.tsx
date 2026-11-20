import type { Severity, Status } from "../types";

export function Spinner({ size = 16 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 16 16" style={{ animation: "spin 0.8s linear infinite", flexShrink: 0 }}>
      <circle cx="8" cy="8" r="6" fill="none" stroke="var(--border)" strokeWidth="2" />
      <path d="M8 2 A6 6 0 0 1 14 8" fill="none" stroke="var(--teal)" strokeWidth="2" strokeLinecap="round" />
    </svg>
  );
}

const SEV_CLASS: Record<Severity, string> = {
  critical: "badge badge-critical",
  high:     "badge badge-high",
  medium:   "badge badge-medium",
  low:      "badge badge-low",
};
export function SeverityBadge({ s }: { s: Severity }) {
  return <span className={SEV_CLASS[s]}>{s}</span>;
}

const ST_CLASS: Record<Status, string> = {
  failed:         "badge badge-failed",
  passed:         "badge badge-passed",
  needs_review:   "badge badge-needs-review",
  not_assessable: "badge badge-not-assessable",
};
const ST_LABEL: Record<Status, string> = {
  failed:         "fail",
  passed:         "pass",
  needs_review:   "review",
  not_assessable: "n/a",
};
export function StatusBadge({ s }: { s: Status }) {
  return <span className={ST_CLASS[s]}>{ST_LABEL[s]}</span>;
}

export function Gauge({ score, size = 100, label }: { score: number | null; size?: number; label?: string }) {
  const r = 42;
  const circ = 2 * Math.PI * r;
  const pct = score === null ? 0 : Math.max(0, Math.min(100, score));
  const offset = circ - (pct / 100) * circ;

  // color based on score
  const color =
    score === null ? "var(--dim)" :
    pct < 40      ? "var(--red)" :
    pct < 70      ? "var(--amber)" :
                    "var(--teal)";

  return (
    <svg width={size} height={size} viewBox="0 0 100 100">
      <circle cx="50" cy="50" r={r} fill="none" stroke="var(--border)" strokeWidth="8" />
      <circle
        cx="50" cy="50" r={r}
        fill="none"
        stroke={color}
        strokeWidth="8"
        strokeLinecap="round"
        strokeDasharray={circ}
        strokeDashoffset={offset}
        transform="rotate(-90 50 50)"
        style={{ transition: "stroke-dashoffset 0.8s ease, stroke 0.4s ease", animation: "ring-draw 0.8s ease both" }}
      />
      <text x="50" y="46" textAnchor="middle" fontSize="20" fontWeight="700" fill={color} fontFamily="JetBrains Mono, monospace">
        {score === null ? "—" : Math.round(pct)}
      </text>
      {label && (
        <text x="50" y="62" textAnchor="middle" fontSize="9" fill="var(--subtle)" fontFamily="JetBrains Mono, monospace">
          {label.toUpperCase()}
        </text>
      )}
    </svg>
  );
}

export function Diff({ text }: { text: string }) {
  return (
    <pre
      style={{
        background: "var(--surface)",
        border: "1px solid var(--border)",
        borderRadius: 6,
        padding: "12px 16px",
        fontSize: 12,
        fontFamily: "JetBrains Mono, monospace",
        overflowX: "auto",
        lineHeight: 1.6,
      }}
    >
      {text.split("\n").map((line, i) => {
        const color =
          line.startsWith("+") ? "var(--green)" :
          line.startsWith("-") ? "var(--red)" :
          line.startsWith("@@") ? "var(--teal)" :
          "var(--text)";
        return (
          <span key={i} style={{ display: "block", color }}>
            {line || " "}
          </span>
        );
      })}
    </pre>
  );
}
