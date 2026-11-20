import type { FlowEdge, FlowNode } from "../types";

const W = 1000;
const BOX_W = 280;
const BOX_H = 28;
const ROW = 38;
const TOP = 34;

export default function FlowMap({ nodes, edges }: { nodes: FlowNode[]; edges: FlowEdge[] }) {
  if (!nodes.length) return <p className="text-sm text-slate-500">No personal data flows were detected.</p>;
  const cols: Record<FlowNode["type"], FlowNode[]> = { source: [], code: [], sink: [] };
  nodes.forEach((n) => cols[n.type].push(n));
  const xs = { source: 10, code: W / 2 - BOX_W / 2, sink: W - BOX_W - 10 };
  const pos = new Map<string, [number, number]>();
  (Object.keys(cols) as FlowNode["type"][]).forEach((t) => cols[t].forEach((n, i) => pos.set(n.id, [xs[t], TOP + i * ROW])));
  const H = TOP + Math.max(...Object.values(cols).map((c) => c.length)) * ROW + 10;
  const fill = { source: "#eff6ff", code: "#f8fafc", sink: "#fdf4ff" };
  const stroke = { source: "#93c5fd", code: "#cbd5e1", sink: "#d8b4fe" };
  return (
    <div className="overflow-x-auto">
      <svg viewBox={`0 0 ${W} ${H}`} className="min-w-[720px]" width="100%" role="img" aria-label="Data-flow map">
        {([["source", "Personal data"], ["code", "Code path"], ["sink", "Store / sink"]] as const).map(([t, title]) => (
          <text key={t} x={xs[t] + BOX_W / 2} y={18} textAnchor="middle" fontSize={12} fontWeight={700} fill="#64748b">{title}</text>
        ))}
        {edges.map((e, i) => {
          const a = pos.get(e.source);
          const b = pos.get(e.target);
          if (!a || !b) return null;
          const x1 = a[0] + BOX_W, y1 = a[1] + BOX_H / 2, x2 = b[0], y2 = b[1] + BOX_H / 2, mx = (x1 + x2) / 2;
          return (
            <path key={i} d={`M${x1},${y1} C${mx},${y1} ${mx},${y2} ${x2},${y2}`} fill="none"
              stroke={e.risky ? "#dc2626" : "#94a3b8"} strokeWidth={e.risky ? 2.2 : 1.4}>
              <title>{e.locations.slice(0, 5).join(", ")}</title>
            </path>
          );
        })}
        {nodes.map((n) => {
          const [x, y] = pos.get(n.id)!;
          return (
            <g key={n.id}>
              <rect x={x} y={y} width={BOX_W} height={BOX_H} rx={6} fill={fill[n.type]} stroke={stroke[n.type]} />
              <text x={x + 10} y={y + BOX_H / 2} dominantBaseline="central" fontSize={12} fill="#0f172a">
                {n.label.length > 40 ? n.label.slice(0, 39) + "…" : n.label}
              </text>
              <title>{n.label}</title>
            </g>
          );
        })}
      </svg>
      <div className="mt-2 flex gap-5 text-xs text-slate-500">
        <span><i className="mr-1.5 inline-block h-0.5 w-5 bg-red-600 align-middle" />risky (unredacted to AI / logs / third parties)</span>
        <span><i className="mr-1.5 inline-block h-0.5 w-5 bg-slate-400 align-middle" />other flow</span>
      </div>
    </div>
  );
}
