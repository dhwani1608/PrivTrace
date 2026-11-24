import { useEffect, useMemo, useState } from "react";
import { api } from "../api";
import type { CiRepo, CiRun } from "../types";
import { Icon, SectionHead, Spinner } from "./ui";

const W = 720;
const H = 220;
const PAD = { l: 36, r: 16, t: 14, b: 26 };

function fmtDate(iso: string) {
  return new Date(iso).toLocaleDateString(undefined, { month: "short", day: "numeric" });
}

/** Overall score per CI run, oldest → newest. One series, so no legend: the heading names it. */
function TrendChart({ runs }: { runs: CiRun[] }) {
  const pts = useMemo(() => [...runs].reverse().filter((r) => r.overall_score !== null), [runs]);
  const [hover, setHover] = useState<number | null>(null);
  if (pts.length < 2) return <p className="text-sm text-zinc-500">The trend appears after two runs with a score.</p>;
  const x = (i: number) => PAD.l + (i * (W - PAD.l - PAD.r)) / (pts.length - 1);
  const y = (v: number) => PAD.t + ((100 - v) * (H - PAD.t - PAD.b)) / 100;
  const d = pts.map((p, i) => `${i ? "L" : "M"}${x(i).toFixed(1)},${y(p.overall_score!).toFixed(1)}`).join(" ");
  const h = hover !== null ? pts[hover] : null;
  return (
    <div className="relative">
      <svg viewBox={`0 0 ${W} ${H}`} className="w-full" role="img" aria-label={`Overall score over ${pts.length} CI runs`}
        onMouseLeave={() => setHover(null)}>
        {[0, 25, 50, 75, 100].map((v) => (
          <g key={v}>
            <line x1={PAD.l} x2={W - PAD.r} y1={y(v)} y2={y(v)} stroke="rgba(255,255,255,.06)" strokeWidth={1} />
            <text x={PAD.l - 8} y={y(v)} textAnchor="end" dominantBaseline="central" className="fill-zinc-500 text-[10px]">{v}</text>
          </g>
        ))}
        <text x={PAD.l} y={H - 6} className="fill-zinc-500 text-[10px]">{fmtDate(pts[0].received_at)}</text>
        <text x={W - PAD.r} y={H - 6} textAnchor="end" className="fill-zinc-500 text-[10px]">{fmtDate(pts[pts.length - 1].received_at)}</text>
        {h && <line x1={x(hover!)} x2={x(hover!)} y1={PAD.t} y2={H - PAD.b} stroke="rgba(255,255,255,.25)" strokeWidth={1} />}
        <path d={d} fill="none" stroke="#a78bfa" strokeWidth={2} strokeLinejoin="round" strokeLinecap="round" />
        {pts.map((p, i) => (
          <g key={p.id} onMouseEnter={() => setHover(i)}>
            <rect x={x(i) - 12} y={PAD.t} width={24} height={H - PAD.t - PAD.b} fill="transparent" />
            <circle cx={x(i)} cy={y(p.overall_score!)} r={hover === i ? 5.5 : 4} fill={p.passed ? "#a78bfa" : "#0b0b12"}
              stroke="#a78bfa" strokeWidth={2} />
          </g>
        ))}
      </svg>
      {h && (
        <div className="pointer-events-none absolute top-0 rounded-xl border border-white/10 bg-ink-900/95 px-3 py-2 text-xs shadow-lift"
          style={{ left: `${Math.min(80, (x(hover!) / W) * 100)}%` }}>
          <div className="font-semibold text-white">{Math.round(h.overall_score!)} · {h.passed ? "✅ passed" : "❌ failed"}</div>
          <div className="text-zinc-400">{h.pr_number ? `PR #${h.pr_number} · ` : ""}{h.ref ?? "—"}</div>
          <div className="text-zinc-500">{new Date(h.received_at).toLocaleString()}</div>
        </div>
      )}
      <p className="mt-1 text-[11px] text-zinc-500">Filled dot: gate passed · hollow dot: gate failed.</p>
    </div>
  );
}

export default function CiHistory({ onBack }: { onBack: () => void }) {
  const [repos, setRepos] = useState<CiRepo[] | null>(null);
  const [repo, setRepo] = useState<string | null>(null);
  const [runs, setRuns] = useState<CiRun[] | null>(null);
  const [branch, setBranch] = useState<string>("all");
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api.ciRepos().then((r) => { setRepos(r); setRepo(r[0]?.repo ?? null); }).catch((e) => setError((e as Error).message));
  }, []);
  useEffect(() => {
    if (!repo) return;
    setRuns(null);
    setBranch("all");
    api.ciRuns(repo).then(setRuns).catch((e) => setError((e as Error).message));
  }, [repo]);

  const branches = useMemo(() => [...new Set((runs ?? []).map((r) => r.ref ?? "—"))], [runs]);
  const shown = useMemo(() => (runs ?? []).filter((r) => branch === "all" || (r.ref ?? "—") === branch), [runs, branch]);
  const prs = useMemo(() => (runs ?? []).filter((r) => r.pr_number !== null).slice(0, 10), [runs]);

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <span className="kicker">CI history</span>
          <h1 className="mt-2 font-display text-3xl font-semibold tracking-tight text-white sm:text-4xl">Compliance gate over time</h1>
          <p className="mt-1 text-sm text-zinc-400">Scores and gate results uploaded by <code className="text-zinc-300">privtrace ci --upload</code>. No code is stored.</p>
        </div>
        <button className="btn-ghost" onClick={onBack}><Icon name="arrow-left" size={15} /> Back to scanning</button>
      </div>

      {error && <div role="alert" className="rounded-2xl border border-rose-400/30 bg-rose-500/10 px-4 py-3 text-sm text-rose-200">{error}</div>}
      {repos === null && !error && <div className="glass flex items-center gap-3 p-6 text-sm text-zinc-400"><Spinner /> Loading…</div>}
      {repos !== null && repos.length === 0 && (
        <div className="glass p-6 text-sm text-zinc-300">
          <p className="font-medium text-white">No CI runs uploaded yet.</p>
          <p className="mt-2">Set <code>PRIVTRACE_CI_TOKEN</code> on this server, then in CI:</p>
          <pre className="mt-2 overflow-x-auto rounded-xl bg-ink-950/70 p-3 font-mono text-xs text-zinc-200">privtrace ci --base origin/main --upload {window.location.origin} --token $PRIVTRACE_TOKEN</pre>
        </div>
      )}

      {repos !== null && repos.length > 0 && (
        <>
          <div className="glass flex flex-wrap items-center gap-3 p-4">
            <label className="flex items-center gap-2 text-sm text-zinc-400">Repository
              <select value={repo ?? ""} onChange={(e) => setRepo(e.target.value)}
                className="rounded-xl bg-ink-950/70 px-3 py-1.5 text-sm text-white ring-1 ring-white/10">
                {repos.map((r) => <option key={r.repo} value={r.repo}>{r.repo} ({r.runs})</option>)}
              </select>
            </label>
            <label className="flex items-center gap-2 text-sm text-zinc-400">Branch
              <select value={branch} onChange={(e) => setBranch(e.target.value)}
                className="rounded-xl bg-ink-950/70 px-3 py-1.5 text-sm text-white ring-1 ring-white/10">
                <option value="all">All branches</option>
                {branches.map((b) => <option key={b} value={b}>{b}</option>)}
              </select>
            </label>
          </div>

          <div className="glass p-5 sm:p-6">
            <SectionHead n="◎" title="Overall score" sub={`${shown.length} run(s)${branch === "all" ? "" : ` on ${branch}`}`} />
            {runs === null ? <Spinner /> : <TrendChart runs={shown} />}
          </div>

          <div className="glass p-5 sm:p-6">
            <SectionHead n="◎" title="Last 10 pull requests" sub="Newest first." />
            {!prs.length ? <p className="text-sm text-zinc-500">No pull request runs yet.</p> : (
              <div className="overflow-x-auto">
                <table className="w-full text-left text-sm">
                  <thead className="text-xs text-zinc-500">
                    <tr><th className="py-2 pr-3">PR</th><th className="pr-3">Branch</th><th className="pr-3">Gate</th><th className="pr-3 text-right">Score</th>
                      <th className="pr-3 text-right">Change</th><th className="pr-3 text-right">New</th><th className="pr-3 text-right">Fixed</th><th>When</th></tr>
                  </thead>
                  <tbody>
                    {prs.map((r) => (
                      <tr key={r.id} className="border-t border-white/[.05]">
                        <td className="py-2 pr-3 font-mono">{r.run_url ? <a className="text-violet-300 hover:text-violet-200" href={r.run_url} target="_blank" rel="noreferrer">#{r.pr_number}</a> : `#${r.pr_number}`}</td>
                        <td className="max-w-[220px] truncate pr-3 font-mono text-xs text-zinc-300">{r.ref ?? "—"}</td>
                        <td className="pr-3">{r.passed ? <span className="text-lime">✅ passed</span> : <span className="text-rose-300" title={r.reasons.join("\n")}>❌ failed</span>}</td>
                        <td className="pr-3 text-right font-mono text-zinc-100">{r.overall_score === null ? "n/a" : Math.round(r.overall_score)}</td>
                        <td className="pr-3 text-right font-mono text-zinc-300">{r.overall_delta === null ? "–" : `${r.overall_delta > 0 ? "▲" : r.overall_delta < 0 ? "▼" : ""}${Math.abs(r.overall_delta).toFixed(0)}`}</td>
                        <td className="pr-3 text-right font-mono text-zinc-300">{r.new}</td>
                        <td className="pr-3 text-right font-mono text-zinc-300">{r.fixed}</td>
                        <td className="text-xs text-zinc-500">{new Date(r.received_at).toLocaleString()}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </>
      )}
    </div>
  );
}
