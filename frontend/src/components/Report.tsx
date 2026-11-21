import { useMemo, useState } from "react";
import { api } from "../api";
import type { RuleResult, ScanResult, Status } from "../types";
import FlowMap from "./FlowMap";
import { ArrowChip, Diff, Gauge, Icon, SectionHead, SeverityBadge, StatusBadge, scoreColor } from "./ui";

const SEV_ORDER = { critical: 0, high: 1, medium: 2, low: 3 };
const ST_ORDER: Record<Status, number> = { failed: 0, needs_review: 1, passed: 2, not_assessable: 3 };
const RISK_CARD = {
  Critical: "bg-rose-500 text-white shadow-[0_20px_60px_-20px_rgba(244,63,94,.8)]",
  High: "bg-orange-500 text-white shadow-[0_20px_60px_-20px_rgba(249,115,22,.8)]",
  Medium: "bg-sun text-ink-950 shadow-[0_20px_60px_-20px_rgba(255,216,77,.6)]",
  Low: "bg-lime text-ink-950 shadow-lime-glow",
};
const ST_BAR: Record<Status, string> = { failed: "bg-rose-500", passed: "bg-lime", needs_review: "bg-sun", not_assessable: "bg-zinc-500" };

function Delta({ v }: { v: number | null }) {
  if (v === null) return null;
  return <span className={`rounded-full px-2 py-0.5 font-mono text-xs font-semibold ${v >= 0 ? "bg-lime/15 text-lime" : "bg-rose-500/15 text-rose-300"}`}>{v >= 0 ? "+" : ""}{v.toFixed(1)}</span>;
}

function Finding({ r }: { r: RuleResult }) {
  const [open, setOpen] = useState(r.status === "failed");
  return (
    <div id={`${r.pack_id}-${r.rule_id}`} className={`scroll-mt-28 overflow-hidden rounded-2xl border transition ${open ? "border-white/10 bg-white/[.04]" : "border-white/[.06] bg-white/[.02] hover:bg-white/[.04]"}`}>
      <button onClick={() => setOpen(!open)} aria-expanded={open} className="flex w-full items-center gap-3 px-4 py-3.5 text-left">
        <span className={`h-8 w-1 shrink-0 rounded-full ${ST_BAR[r.status]}`} />
        <div className="flex min-w-0 flex-1 flex-wrap items-center gap-2">
          <StatusBadge s={r.status} />
          <SeverityBadge s={r.severity} />
          <span className="min-w-[180px] flex-1 font-medium text-white">{r.title}</span>
        </div>
        <code className="hidden text-xs text-zinc-500 sm:inline">{r.rule_id}</code>
        <Icon name="chevron" size={16} className={`shrink-0 text-zinc-500 transition ${open ? "rotate-90" : ""}`} />
      </button>
      {open && (
        <div className="space-y-5 border-t border-white/[.06] px-4 py-5 text-sm sm:px-6">
          <p className="text-zinc-200">{r.message}</p>
          <dl className="grid gap-x-6 gap-y-3 md:grid-cols-[150px_1fr]">
            <dt className="kicker pt-0.5">Legal reference</dt>
            <dd className="text-zinc-300">
              {r.reference}{" "}
              {!r.reference_verified && <span className="badge bg-sun/15 text-sun ring-1 ring-inset ring-sun/30" title="Awaiting human verification">unverified</span>}{" "}
              <a className="inline-flex items-center gap-0.5 text-violet-300 hover:text-violet-200" href={r.source_url} target="_blank" rel="noreferrer">source <Icon name="arrow-up-right" size={12} /></a>
            </dd>
            <dt className="kicker pt-0.5">Why it matters</dt><dd className="text-zinc-300">{r.why_it_matters}</dd>
            <dt className="kicker pt-0.5">How to fix</dt><dd className="text-zinc-300">{r.remediation}</dd>
            {r.question && (<><dt className="kicker pt-0.5">Checklist</dt><dd className="text-zinc-300">{r.question} — <b className="text-white">{r.manual_answer?.replace("_", " ") ?? "not answered"}</b></dd></>)}
          </dl>
          {r.evidence.length > 0 && (
            <div className="overflow-x-auto rounded-2xl border border-white/[.07] bg-ink-950/60">
              <table className="w-full text-xs">
                <thead className="text-left"><tr className="border-b border-white/[.06]"><th className="kicker px-4 py-2.5 font-normal">Location</th><th className="kicker px-4 py-2.5 font-normal">Evidence (redacted)</th></tr></thead>
                <tbody>
                  {r.evidence.map((e, i) => (
                    <tr key={i} className="border-t border-white/[.04] align-top">
                      <td className="whitespace-nowrap px-4 py-2.5 font-mono text-violet-300">{e.file}:{e.line}</td>
                      <td className="px-4 py-2.5">
                        {e.snippet && <code className="mb-1 block break-all rounded-lg bg-white/[.04] px-2 py-1 text-zinc-200">{e.snippet}</code>}
                        <span className="text-zinc-500">{e.detail}</span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
          {r.ai?.explanation && (
            <div className="rounded-2xl border border-violet-400/25 bg-gradient-to-br from-violet-500/15 to-transparent p-4 text-zinc-200">
              <span className="badge mb-2 bg-violet-500 text-white"><Icon name="sparkle" size={11} /> AI explanation</span>
              <p>{r.ai.explanation}</p>
            </div>
          )}
          {r.fix_diff ? (
            <div><div className="mb-2 font-medium text-white">Suggested change <span className="font-normal text-zinc-500">(template-generated — review before applying)</span></div><Diff text={r.fix_diff} /></div>
          ) : r.ai && (r.ai.suggested_diff || r.ai.suggested_fix) ? (
            <div>
              <div className="mb-2 flex flex-wrap items-center gap-2 font-medium text-white">Suggested change <span className="badge bg-violet-500/20 text-violet-200">AI-suggested — review before applying</span></div>
              {r.ai.suggested_fix && <p className="mb-2 text-zinc-300">{r.ai.suggested_fix}</p>}
              {r.ai.suggested_diff && <Diff text={r.ai.suggested_diff} />}
            </div>
          ) : null}
        </div>
      )}
    </div>
  );
}

const DOCK: [string, string, Parameters<typeof Icon>[0]["name"]][] = [
  ["summary", "Summary", "layers"], ["flow", "Data flow", "flow"], ["findings", "Findings", "alert"],
  ["checklist", "Checklist", "list"], ["coverage", "Coverage", "eye"], ["disclaimer", "Disclaimer", "book"],
];

export default function Report({ result, canRescan, onRescan, onUploadFixed, onNew }: {
  result: ScanResult;
  canRescan: boolean;
  onRescan: () => void;
  onUploadFixed: () => void;
  onNew: () => void;
}) {
  const [filter, setFilter] = useState<Status | "all">("all");
  const top = useMemo(() => {
    const seen = new Set<string>();
    return result.results
      .filter((r) => r.status === "failed")
      .sort((a, b) => SEV_ORDER[a.severity] - SEV_ORDER[b.severity])
      .filter((r) => (seen.has(r.title) ? false : (seen.add(r.title), true)))
      .slice(0, 5);
  }, [result]);
  const counts = useMemo(() => {
    const c: Record<Status, number> = { failed: 0, passed: 0, needs_review: 0, not_assessable: 0 };
    result.results.forEach((r) => { c[r.status] += 1; });
    return c;
  }, [result]);
  const manual = result.results.filter((r) => r.check_type !== "automated" && r.question);
  const d = result.diff;
  const s = result.summary;

  return (
    <div className="space-y-6 pb-20">
      {/* header */}
      <div className="flex flex-wrap items-end justify-between gap-6">
        <div className="min-w-0">
          <span className="kicker">Report · scan {result.scan_id}</span>
          <h1 className="mt-2 break-all font-display text-3xl font-semibold tracking-tight text-white sm:text-5xl">{result.target}</h1>
          <div className="mt-2 flex flex-wrap items-center gap-2 text-xs text-zinc-400">
            <span>{new Date(result.created_at).toLocaleString()}</span>
            {result.ai_used && <span className="badge bg-violet-500/15 text-violet-200 ring-1 ring-inset ring-violet-400/30"><Icon name="sparkle" size={11} /> {result.ai_model}</span>}
          </div>
        </div>
        <div className="flex flex-wrap gap-2">
          {canRescan
            ? <button className="btn-primary" onClick={onRescan}><Icon name="refresh" size={16} /> Rescan after fixes</button>
            : <button className="btn-primary" onClick={onUploadFixed}><Icon name="upload" size={16} /> Upload fixed version</button>}
          <a className="btn-ghost" href={api.reportHtmlUrl(result.scan_id, true)}><Icon name="download" size={15} /> HTML</a>
          <a className="btn-ghost" href={api.reportJsonUrl(result.scan_id)} download={`privtrace-${result.scan_id}.json`}><Icon name="download" size={15} /> JSON</a>
          <button className="btn-ghost" onClick={onNew}><Icon name="plus" size={15} /> New scan</button>
        </div>
      </div>

      <div className="flex items-start gap-3 rounded-2xl border border-sun/25 bg-sun/[.07] px-4 py-3 text-sm text-amber-100">
        <Icon name="shield" size={18} className="mt-0.5 shrink-0 text-sun" />
        <p><b className="text-sun">Not legal advice.</b> {result.disclaimer}</p>
      </div>

      {/* 1. summary bento */}
      <section id="summary" className="scroll-mt-28">
        <div className="grid gap-4 md:grid-cols-4">
          <div className="glass relative flex flex-col items-center justify-center overflow-hidden p-6 md:col-span-2 md:row-span-2">
            <div className="absolute inset-0 opacity-40 [mask-image:radial-gradient(circle,black,transparent_70%)] dot-grid" aria-hidden="true" />
            <div className="absolute left-1/2 top-1/2 h-64 w-64 -translate-x-1/2 -translate-y-1/2 rounded-full blur-[80px]" style={{ background: scoreColor(result.overall_score), opacity: 0.18 }} aria-hidden="true" />
            <span className="kicker relative">Overall score</span>
            <div className="relative mt-3"><Gauge score={result.overall_score} size={220} stroke={14} label="Overall" /></div>
            <div className="relative mt-4 flex w-full max-w-sm gap-1.5" aria-label="Rule outcomes">
              {(["failed", "needs_review", "passed", "not_assessable"] as Status[]).map((k) => counts[k] > 0 && (
                <div key={k} className="min-w-0" style={{ flex: counts[k] }}>
                  <div className={`h-1.5 rounded-full ${ST_BAR[k]}`} />
                  <div className="mt-1.5 truncate text-[11px] text-zinc-400"><b className="text-white">{counts[k]}</b> {k.replace("_", " ")}</div>
                </div>
              ))}
            </div>
          </div>

          <div className={`group flex flex-col justify-between rounded-3xl p-5 ${RISK_CARD[result.risk_level]}`}>
            <div className="flex items-start justify-between"><span className="text-sm font-semibold leading-tight">Risk<br />level</span><ArrowChip dark /></div>
            <div className="mt-6 font-display text-4xl font-bold tracking-tight">{result.risk_level}</div>
          </div>

          <div className="flex flex-col justify-between rounded-3xl bg-white p-5 text-ink-950 shadow-lift">
            <span className="text-sm font-semibold leading-tight">Files<br />scanned</span>
            <div className="mt-6"><div className="font-display text-5xl font-bold tracking-tight">{s.files_scanned}</div><div className="text-xs text-zinc-500">{s.python_files} Python</div></div>
          </div>

          <div className="flex flex-col justify-between rounded-3xl bg-sun p-5 text-ink-950 shadow-lift">
            <div className="flex items-start justify-between"><span className="text-sm font-semibold leading-tight">Models holding<br />personal data</span><span className="leading-none">⋮</span></div>
            <div className="mt-6 font-display text-5xl font-bold tracking-tight">{s.models_with_pii}</div>
          </div>

          <div className="glass flex flex-col justify-between p-5">
            <div className="flex items-start justify-between text-white"><span className="text-sm font-semibold leading-tight">Personal data<br />reaching a sink</span><Icon name="database" className="text-violet-300" /></div>
            <div className="mt-6 flex items-end justify-between">
              <div className="font-display text-5xl font-bold tracking-tight text-white">{s.pii_sinks}</div>
              <div className="text-right"><div className="font-display text-2xl font-bold text-rose-400">{s.risky_flows}</div><div className="text-[11px] uppercase tracking-wide text-zinc-500">risky flows</div></div>
            </div>
          </div>
        </div>

        {/* per-pack */}
        <div className="mt-4 grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
          {result.pack_scores.map((p) => (
            <div key={p.pack_id} className="glass flex items-center gap-4 p-4">
              <Gauge score={p.score} size={92} stroke={8} label={p.short_name} />
              <div className="min-w-0">
                <div className="font-display text-lg font-semibold text-white">{p.short_name}</div>
                <div className="mt-1 flex flex-wrap gap-x-2 text-[11px] font-medium">
                  <span className="text-lime">{p.passed} passed</span><span className="text-rose-300">{p.failed} failed</span><span className="text-sun">{p.needs_review} review</span>
                </div>
                <div className="mt-1.5 text-[11px] leading-snug text-zinc-500">
                  {p.coverage.automated_checked}/{p.coverage.total} automated · {p.coverage.manual_answered} answered · {p.coverage.not_assessable} not assessable
                </div>
              </div>
            </div>
          ))}
        </div>

        {d && (
          <div className="relative mt-4 overflow-hidden rounded-3xl border border-violet-400/25 bg-gradient-to-br from-violet-600/20 via-violet-500/[.06] to-transparent p-5 sm:p-6">
            <div className="flex flex-wrap items-center justify-between gap-4">
              <div>
                <span className="kicker text-violet-300/80">Changes since last scan</span>
                <div className="mt-2 flex flex-wrap items-center gap-3 font-display text-3xl font-bold text-white">
                  <span className="text-zinc-500">{d.overall_before ?? "n/a"}</span>
                  <Icon name="arrow-right" className="text-violet-300" />
                  <span>{d.overall_after ?? "n/a"}</span>
                  <Delta v={d.overall_delta} />
                </div>
                <div className="mt-1 text-sm text-zinc-400">Risk {d.risk_before} → <b className="text-white">{d.risk_after}</b></div>
              </div>
              <div className="flex flex-wrap gap-2">
                {d.packs.map((p) => (
                  <span key={p.pack_id} className="glass-tile flex items-center gap-2 px-3 py-2 text-xs text-zinc-300">
                    <b className="text-white">{p.short_name}</b> {p.before ?? "n/a"} → {p.after ?? "n/a"} <Delta v={p.delta} />
                  </span>
                ))}
              </div>
            </div>
            {(d.fixed.length > 0 || d.regressed.length > 0) && (
              <div className="mt-4 flex flex-wrap gap-2 text-xs">
                {d.fixed.map((f) => <span key={"f" + f.rule_id} className="rounded-full bg-lime/15 px-2.5 py-1 font-mono text-lime" title={f.title}>✓ {f.rule_id}</span>)}
                {d.regressed.map((f) => <span key={"r" + f.rule_id} className="rounded-full bg-rose-500/15 px-2.5 py-1 font-mono text-rose-300" title={f.title}>✕ {f.rule_id}</span>)}
              </div>
            )}
          </div>
        )}

        <div className="glass mt-4 p-5 sm:p-6">
          <SectionHead n="01" title="Top fixes" sub="Highest-severity failures first — start here." />
          {top.length ? (
            <ol className="grid gap-3 lg:grid-cols-2">
              {top.map((t, i) => (
                <li key={t.rule_id} className={i === 0 ? "lg:col-span-2" : ""}>
                  <a href={`#${t.pack_id}-${t.rule_id}`} className="group flex h-full gap-4 rounded-2xl border border-white/[.06] bg-white/[.02] p-4 transition hover:-translate-y-0.5 hover:border-violet-400/30 hover:bg-white/[.05]">
                    <span className="font-display text-3xl font-bold leading-none text-white/20 transition group-hover:text-lime">{String(i + 1).padStart(2, "0")}</span>
                    <div className="min-w-0 flex-1 text-sm">
                      <div className="flex flex-wrap items-center gap-2"><SeverityBadge s={t.severity} /><span className="font-medium text-white">{t.title}</span></div>
                      {t.evidence[0] && <code className="mt-1 block truncate text-xs text-violet-300">{t.evidence[0].file}:{t.evidence[0].line}</code>}
                      <div className="mt-1.5 text-zinc-400">{t.remediation}</div>
                    </div>
                    <Icon name="arrow-up-right" size={16} className="shrink-0 text-zinc-600 transition group-hover:text-white" />
                  </a>
                </li>
              ))}
            </ol>
          ) : (
            <div className="flex items-center gap-3 rounded-2xl bg-lime/10 p-4 text-sm text-lime"><Icon name="check" strokeWidth={2.6} /> No failed rules.</div>
          )}
        </div>
      </section>

      {/* 2. data flow */}
      <section id="flow" className="glass scroll-mt-28 p-5 sm:p-6">
        <SectionHead n="02" title="Data-flow map" sub="Where personal data enters, which functions carry it, and which stores or third parties it reaches." />
        <FlowMap nodes={result.data_flow.nodes} edges={result.data_flow.edges} />
        {result.ai_classifications.length > 0 && (
          <div className="mt-5 rounded-2xl border border-violet-400/20 bg-violet-500/[.06] p-4 text-sm">
            <div className="flex flex-wrap items-center gap-2 font-medium text-white">Possible personal data in generic fields <span className="badge bg-violet-500/20 text-violet-200">AI-classified — review</span></div>
            <ul className="mt-2 space-y-1 text-zinc-400">
              {result.ai_classifications.map((c) => <li key={c.name}><code className="text-violet-200">{c.name}</code> ({c.category}) {c.file && <span className="font-mono text-xs text-zinc-500">{c.file}:{c.line}</span>} — {c.reason}</li>)}
            </ul>
          </div>
        )}
      </section>

      {/* 3. findings */}
      <section id="findings" className="glass scroll-mt-28 p-5 sm:p-6">
        <SectionHead n="03" title="Findings by framework"
          right={
            <div className="flex max-w-full overflow-x-auto rounded-full bg-ink-950/80 p-1 text-xs ring-1 ring-white/[.07]" role="tablist" aria-label="Filter findings">
              {(["all", "failed", "needs_review", "passed", "not_assessable"] as const).map((f) => (
                <button key={f} role="tab" aria-selected={filter === f} onClick={() => setFilter(f)}
                  className={`whitespace-nowrap rounded-full px-3 py-1.5 font-semibold capitalize transition ${filter === f ? "bg-white text-ink-950" : "text-zinc-400 hover:text-white"}`}>
                  {f.replace("_", " ")}{f !== "all" && <span className="ml-1 opacity-60">{counts[f]}</span>}
                </button>
              ))}
            </div>
          } />
        <div className="space-y-8">
          {result.pack_scores.map((p) => {
            const rs = result.results.filter((r) => r.pack_id === p.pack_id && (filter === "all" || r.status === filter))
              .sort((a, b) => ST_ORDER[a.status] - ST_ORDER[b.status] || SEV_ORDER[a.severity] - SEV_ORDER[b.severity]);
            return (
              <div key={p.pack_id}>
                <div className="mb-3 flex flex-wrap items-baseline justify-between gap-2 border-b border-white/[.06] pb-3">
                  <h4 className="font-display text-lg font-semibold text-white">{p.name}</h4>
                  <span className="font-mono text-xs text-zinc-500">
                    <b style={{ color: scoreColor(p.score) }}>{p.score === null ? "n/a" : `${Math.round(p.score)}/100`}</b> · {p.passed} passed · {p.failed} failed · {p.needs_review} review · {p.not_assessable} n/a
                  </span>
                </div>
                <div className="space-y-2">{rs.map((r) => <Finding key={r.rule_id} r={r} />)}{!rs.length && <p className="py-2 text-sm text-zinc-500">Nothing in this filter.</p>}</div>
              </div>
            );
          })}
        </div>
      </section>

      {/* 4. checklist */}
      <section id="checklist" className="glass scroll-mt-28 p-5 sm:p-6">
        <SectionHead n="04" title="Manual checklist answers" />
        {manual.length ? (
          <div className="overflow-x-auto rounded-2xl border border-white/[.06]">
            <table className="w-full text-sm">
              <thead className="text-left"><tr className="border-b border-white/[.06]"><th className="kicker px-4 py-3 font-normal">Rule</th><th className="kicker px-4 py-3 font-normal">Question</th><th className="kicker px-4 py-3 font-normal">Answer</th><th className="kicker px-4 py-3 font-normal">Result</th></tr></thead>
              <tbody>
                {manual.map((m) => (
                  <tr key={m.pack_id + m.rule_id} className="border-t border-white/[.04] align-top transition hover:bg-white/[.02]">
                    <td className="px-4 py-3"><code className="text-xs text-violet-300">{m.rule_id}</code></td>
                    <td className="px-4 py-3 text-zinc-300">{m.question}</td>
                    <td className="whitespace-nowrap px-4 py-3 capitalize text-zinc-200">{m.manual_answer?.replace("_", " ") ?? "—"}</td>
                    <td className="px-4 py-3"><StatusBadge s={m.status} /></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : <p className="text-sm text-zinc-500">No manual questions for these frameworks.</p>}
      </section>

      {/* 5. coverage + 6. disclaimer */}
      <div className="grid gap-6 lg:grid-cols-2">
        <section id="coverage" className="glass scroll-mt-28 p-5 text-sm sm:p-6">
          <SectionHead n="05" title="Coverage and limitations" />
          <ul className="space-y-2.5 text-zinc-400">
            {result.pack_scores.map((p) => (
              <li key={p.pack_id} className="flex gap-2"><span className="mt-2 h-1 w-1 shrink-0 rounded-full bg-violet-400" /><span><b className="text-white">{p.short_name}</b>: {p.coverage.automated_checked} of {p.coverage.total} rules checked automatically, {p.coverage.manual_answered} answered manually,
                {" "}{p.coverage.not_assessable} not assessable from code, {p.coverage.needs_review} need review.</span></li>
            ))}
            {["Python is analysed in depth; other files get identifier, secret and configuration checks.",
              "Flow tracking is intra-function plus calls into repo modules; dynamic dispatch and infrastructure config are not followed.",
              "Consent, minimisation, children’s data and third-party sharing are heuristics and never “fail” on their own."].map((t) => (
              <li key={t} className="flex gap-2"><span className="mt-2 h-1 w-1 shrink-0 rounded-full bg-zinc-600" /><span>{t}</span></li>
            ))}
          </ul>
        </section>
        <section id="disclaimer" className="glass scroll-mt-28 p-5 text-sm sm:p-6">
          <SectionHead n="06" title="Disclaimer" />
          <p className="text-zinc-400">{result.disclaimer}</p>
          <div className="mt-4 rounded-2xl bg-ink-950/60 p-4 text-xs text-zinc-400 ring-1 ring-white/[.05]"><b className="text-white">How the score is calculated.</b> {result.scoring_formula}</div>
        </section>
      </div>

      {/* floating section dock */}
      <nav aria-label="Report sections" className="fixed bottom-5 left-1/2 z-40 -translate-x-1/2">
        <div className="flex items-center gap-1 rounded-full border border-white/10 bg-ink-900/85 p-1.5 shadow-lift backdrop-blur-xl">
          {DOCK.map(([id, label, icon], i) => (
            <a key={id} href={`#${id}`} title={label} aria-label={label}
              className={`flex h-10 w-10 items-center justify-center rounded-full transition ${i === 0 ? "bg-violet-500 text-white shadow-glow" : "text-zinc-400 hover:bg-white/[.08] hover:text-white"}`}>
              <Icon name={icon} size={17} />
            </a>
          ))}
        </div>
      </nav>
    </div>
  );
}
