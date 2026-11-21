import { useState } from "react";
import type { FlowEdge, FlowNode } from "../types";

const W = 1000;
const BOX_W = 270;
const BOX_H = 34;
const ROW = 46;
const TOP = 50;

const TONE = {
  source: { dot: "#a78bfa", stroke: "rgba(167,139,250,.45)", fill: "rgba(139,92,246,.14)" },
  code: { dot: "#a1a1aa", stroke: "rgba(255,255,255,.14)", fill: "rgba(255,255,255,.05)" },
  sink: { dot: "#d4ff3f", stroke: "rgba(212,255,63,.35)", fill: "rgba(212,255,63,.07)" },
};

export default function FlowMap({ nodes, edges }: { nodes: FlowNode[]; edges: FlowEdge[] }) {
  const [hover, setHover] = useState<string | null>(null);
  if (!nodes.length) {
    return <div className="dot-grid rounded-2xl border border-white/[.06] bg-ink-950/60 p-10 text-center text-sm text-zinc-400">No personal data flows were detected.</div>;
  }
  const cols: Record<FlowNode["type"], FlowNode[]> = { source: [], code: [], sink: [] };
  nodes.forEach((n) => cols[n.type].push(n));
  const xs = { source: 20, code: W / 2 - BOX_W / 2, sink: W - BOX_W - 20 };
  const pos = new Map<string, [number, number]>();
  (Object.keys(cols) as FlowNode["type"][]).forEach((t) => cols[t].forEach((n, i) => pos.set(n.id, [xs[t], TOP + i * ROW])));
  const H = TOP + Math.max(...Object.values(cols).map((c) => c.length)) * ROW + 16;
  const linked = (e: FlowEdge) => hover !== null && (e.source === hover || e.target === hover);

  return (
    <div>
      <div className="dot-grid overflow-x-auto rounded-2xl border border-white/[.06] bg-ink-950/70 p-2">
        <svg viewBox={`0 0 ${W} ${H}`} className="min-w-[760px]" width="100%" role="img" aria-label="Data-flow map">
          <defs>
            <filter id="pt-glow" x="-20%" y="-50%" width="140%" height="200%"><feGaussianBlur stdDeviation="3.5" /></filter>
            <linearGradient id="pt-risky" x1="0" x2="1"><stop offset="0" stopColor="#ff5c7a" /><stop offset="1" stopColor="#ff9a5c" /></linearGradient>
            <linearGradient id="pt-safe" x1="0" x2="1"><stop offset="0" stopColor="#8b5cf6" /><stop offset="1" stopColor="#d4ff3f" stopOpacity={0.7} /></linearGradient>
          </defs>
          {([["source", "Personal data"], ["code", "Code path"], ["sink", "Store / sink"]] as const).map(([t, title]) => (
            <g key={t}>
              <circle cx={xs[t] + 6} cy={22} r={4} fill={TONE[t].dot} />
              <text x={xs[t] + 18} y={22} dominantBaseline="central" fontSize={12} fontWeight={600} fill="#a1a1aa" style={{ letterSpacing: ".08em", textTransform: "uppercase" }}>{title}</text>
            </g>
          ))}
          {edges.map((e, i) => {
            const a = pos.get(e.source);
            const b = pos.get(e.target);
            if (!a || !b) return null;
            const x1 = a[0] + BOX_W, y1 = a[1] + BOX_H / 2, x2 = b[0], y2 = b[1] + BOX_H / 2, mx = (x1 + x2) / 2;
            const d = `M${x1},${y1} C${mx},${y1} ${mx},${y2} ${x2},${y2}`;
            const dim = hover !== null && !linked(e);
            return (
              <g key={i} opacity={dim ? 0.12 : 1} style={{ transition: "opacity .2s" }}>
                {e.risky && <path d={d} fill="none" stroke="#ff5c7a" strokeOpacity={0.6} strokeWidth={5} filter="url(#pt-glow)" />}
                <path d={d} fill="none" stroke={e.risky ? "url(#pt-risky)" : "url(#pt-safe)"} strokeOpacity={e.risky ? 1 : 0.55} strokeWidth={e.risky ? 2 : 1.4}
                  strokeDasharray={e.risky ? "6 6" : undefined} className={e.risky ? "animate-flow-dash" : undefined}>
                  <title>{[e.label, ...e.locations.slice(0, 5)].filter(Boolean).join(" · ")}</title>
                </path>
                <circle cx={x2} cy={y2} r={2.5} fill={e.risky ? "#ff5c7a" : "#a78bfa"} />
              </g>
            );
          })}
          {nodes.map((n) => {
            const [x, y] = pos.get(n.id)!;
            const tone = TONE[n.type];
            const active = hover === n.id;
            return (
              <g key={n.id} onMouseEnter={() => setHover(n.id)} onMouseLeave={() => setHover(null)} style={{ cursor: "default" }}>
                <rect x={x} y={y} width={BOX_W} height={BOX_H} rx={10} fill={tone.fill} stroke={active ? tone.dot : tone.stroke} strokeWidth={active ? 1.5 : 1} />
                <rect x={x} y={y} width={BOX_W} height={BOX_H} rx={10} fill="rgba(10,9,18,.55)" />
                <rect x={x} y={y} width={BOX_W} height={BOX_H} rx={10} fill={tone.fill} />
                <circle cx={x + 14} cy={y + BOX_H / 2} r={3.5} fill={tone.dot} />
                <text x={x + 26} y={y + BOX_H / 2} dominantBaseline="central" fontSize={12.5} fill="#f4f4f5" style={{ fontFamily: "'JetBrains Mono', ui-monospace, monospace" }}>
                  {n.label.length > 32 ? n.label.slice(0, 31) + "…" : n.label}
                </text>
                <title>{n.label}{n.category ? ` (${n.category})` : ""}</title>
              </g>
            );
          })}
        </svg>
      </div>
      <div className="mt-3 flex flex-wrap gap-x-6 gap-y-2 text-xs text-zinc-400">
        <span className="flex items-center gap-2"><i className="inline-block h-0.5 w-6 rounded bg-rose-400 shadow-[0_0_8px_rgba(255,92,122,.9)]" />risky (unredacted to AI / logs / third parties)</span>
        <span className="flex items-center gap-2"><i className="inline-block h-0.5 w-6 rounded bg-gradient-to-r from-violet-500 to-lime/70" />other flow</span>
        <span className="text-zinc-500">Hover a node to isolate its flows.</span>
      </div>
    </div>
  );
}
