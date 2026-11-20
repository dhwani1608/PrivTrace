import type { FlowEdge, FlowNode } from "../types";

const W = 1000;
const BOX_W = 280;
const BOX_H = 28;
const ROW = 38;
const TOP = 34;

export default function FlowMap({ nodes, edges }: { nodes: FlowNode[]; edges: FlowEdge[] }) {
  if (!nodes.length) return (
    <p style={{ fontSize: 13, color: "var(--muted)", fontFamily: "var(--font-mono)" }}>
      No personal data flows detected.
    </p>
  );

  const cols: Record<FlowNode["type"], FlowNode[]> = { source: [], code: [], sink: [] };
  nodes.forEach((n) => cols[n.type].push(n));
  const xs = { source: 10, code: W / 2 - BOX_W / 2, sink: W - BOX_W - 10 };
  const pos = new Map<string, [number, number]>();
  (Object.keys(cols) as FlowNode["type"][]).forEach((t) =>
    cols[t].forEach((n, i) => pos.set(n.id, [xs[t], TOP + i * ROW]))
  );
  const H = TOP + Math.max(...Object.values(cols).map((c) => c.length)) * ROW + 10;

  // Dark theme colors
  const fill   = { source: "#0D1F2D", code: "#13171F", sink: "#1A1030" };
  const stroke = { source: "#1A4A6B", code: "#1E2530", sink: "#3A2060" };
  const label  = { source: "#38BDF8", code: "#94A3B8", sink: "#A78BFA" };

  return (
    <div style={{ overflowX: "auto" }}>
      <svg
        viewBox={`0 0 ${W} ${H}`}
        style={{ minWidth: 720, display: "block" }}
        width="100%"
        role="img"
        aria-label="Data-flow map"
      >
        {/* Column headers */}
        {([
          ["source", "PERSONAL DATA"],
          ["code",   "CODE PATH"],
          ["sink",   "STORE / SINK"],
        ] as const).map(([t, title]) => (
          <text
            key={t}
            x={xs[t] + BOX_W / 2}
            y={16}
            textAnchor="middle"
            fontSize={10}
            fontWeight={700}
            fontFamily="'JetBrains Mono', monospace"
            letterSpacing="0.08em"
            fill={label[t]}
          >
            {title}
          </text>
        ))}

        {/* Edges */}
        {edges.map((e, i) => {
          const a = pos.get(e.source);
          const b = pos.get(e.target);
          if (!a || !b) return null;
          const x1 = a[0] + BOX_W, y1 = a[1] + BOX_H / 2;
          const x2 = b[0],         y2 = b[1] + BOX_H / 2;
          const mx = (x1 + x2) / 2;
          return (
            <path
              key={i}
              d={`M${x1},${y1} C${mx},${y1} ${mx},${y2} ${x2},${y2}`}
              fill="none"
              stroke={e.risky ? "#FF4D6A" : "#2D3748"}
              strokeWidth={e.risky ? 2 : 1.4}
              strokeDasharray={e.risky ? undefined : "4 3"}
              opacity={e.risky ? 1 : 0.7}
            >
              <title>{e.locations.slice(0, 5).join(", ")}</title>
            </path>
          );
        })}

        {/* Nodes */}
        {nodes.map((n) => {
          const [x, y] = pos.get(n.id)!;
          return (
            <g key={n.id}>
              <rect
                x={x} y={y}
                width={BOX_W} height={BOX_H}
                rx={4}
                fill={fill[n.type]}
                stroke={stroke[n.type]}
                strokeWidth={1}
              />
              <text
                x={x + 10}
                y={y + BOX_H / 2}
                dominantBaseline="central"
                fontSize={11}
                fontFamily="'JetBrains Mono', monospace"
                fill="#CBD5E1"
              >
                {n.label.length > 38 ? n.label.slice(0, 37) + "…" : n.label}
              </text>
              <title>{n.label}</title>
            </g>
          );
        })}
      </svg>

      {/* Legend */}
      <div style={{
        marginTop: 12,
        display: "flex",
        gap: 20,
        fontSize: 11,
        color: "var(--muted)",
        fontFamily: "var(--font-mono)",
      }}>
        <span style={{ display: "flex", alignItems: "center", gap: 8 }}>
          <span style={{
            display: "inline-block", width: 20, height: 2,
            background: "#FF4D6A", borderRadius: 1,
          }} />
          risky — unredacted to AI / logs / 3rd parties
        </span>
        <span style={{ display: "flex", alignItems: "center", gap: 8 }}>
          <span style={{
            display: "inline-block", width: 20, height: 0,
            borderTop: "2px dashed #2D3748",
          }} />
          other flow
        </span>
      </div>
    </div>
  );
}
