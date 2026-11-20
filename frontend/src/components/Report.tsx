import { useMemo, useState } from "react";
import { api } from "../api";
import type { RuleResult, ScanResult, Status } from "../types";
import FlowMap from "./FlowMap";
import { Diff, Gauge, SeverityBadge, StatusBadge } from "./ui";

const SEV_ORDER = { critical: 0, high: 1, medium: 2, low: 3 };
const ST_ORDER: Record<Status, number> = { failed: 0, needs_review: 1, passed: 2, not_assessable: 3 };
const RISK_COLOR = { Critical: "text-red-600", High: "text-orange-600", Medium: "text-amber-600", Low: "text-green-600" };

function Delta({ v }: { v: number | null }) {
  if (v === null) return null;
  return <span className={`font-semibold ${v >= 0 ? "text-green-600" : "text-red-600"}`}>{v >= 0 ? "+" : ""}{v.toFixed(1)}</span>;
}

function Finding({ r }: { r: RuleResult }) {
  const [open, setOpen] = useState(r.status === "failed");
  return (
    <div id={`${r.pack_id}-${r.rule_id}`} className="overflow-hidden rounded-xl border border-slate-200 bg-white">
      <button onClick={() => setOpen(!open)} className="flex w-full flex-wrap items-center gap-2 px-4 py-3 text-left hover:bg-slate-50">
        <StatusBadge s={r.status} />
        <SeverityBadge s={r.severity} />
        <span className="min-w-[200px] flex-1 font-medium">{r.title}</span>
        <code className="text-xs text-slate-400">{r.rule_id}</code>
        <span className="text-slate-400">{open ? "▾" : "▸"}</span>
      </button>
      {open && (
        <div className="space-y-4 border-t border-slate-100 px-4 py-4 text-sm">
          <p>{r.message}</p>
          <dl className="grid gap-x-4 gap-y-2 md:grid-cols-[150px_1fr]">
            <dt className="text-slate-500">Legal reference</dt>
            <dd>
              {r.reference}{" "}
              {!r.reference_verified && <span className="badge bg-amber-100 text-amber-800" title="Awaiting human verification">unverified</span>}{" "}
              <a className="text-indigo-600 hover:underline" href={r.source_url} target="_blank" rel="noreferrer">source ↗</a>
            </dd>
            <dt className="text-slate-500">Why it matters</dt><dd>{r.why_it_matters}</dd>
            <dt className="text-slate-500">How to fix</dt><dd>{r.remediation}</dd>
            {r.question && (<><dt className="text-slate-500">Checklist</dt><dd>{r.question} — <b>{r.manual_answer?.replace("_", " ") ?? "not answered"}</b></dd></>)}
          </dl>
          {r.evidence.length > 0 && (
            <div className="overflow-x-auto rounded-lg border border-slate-200">
              <table className="w-full text-xs">
                <thead className="bg-slate-50 text-left text-slate-500"><tr><th className="px-3 py-2">Location</th><th className="px-3 py-2">Evidence (redacted)</th></tr></thead>
                <tbody>
                  {r.evidence.map((e, i) => (
                    <tr key={i} className="border-t border-slate-100 align-top">
                      <td className="whitespace-nowrap px-3 py-2 font-mono">{e.file}:{e.line}</td>
                      <td className="px-3 py-2">
                        {e.snippet && <code className="block break-all rounded bg-slate-50 px-1.5 py-0.5">{e.snippet}</code>}
                        <span className="text-slate-500">{e.detail}</span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
          {r.ai?.explanation && (
            <p className="rounded-lg bg-violet-50 p-3"><span className="badge mr-2 bg-violet-200 text-violet-800">AI explanation</span>{r.ai.explanation}</p>
          )}
          {r.fix_diff ? (
            <div><div className="mb-1 font-medium">Suggested change <span className="font-normal text-slate-500">(template-generated — review before applying)</span></div><Diff text={r.fix_diff} /></div>
          ) : r.ai && (r.ai.suggested_diff || r.ai.suggested_fix) ? (
            <div>
              <div className="mb-1 font-medium">Suggested change <span className="badge bg-violet-200 text-violet-800">AI-suggested — review before applying</span></div>
              {r.ai.suggested_fix && <p className="mb-2">{r.ai.suggested_fix}</p>}
              {r.ai.suggested_diff && <Diff text={r.ai.suggested_diff} />}
            </div>
          ) : null}
        </div>
      )}
    </div>
  );
}

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
  const manual = result.results.filter((r) => r.check_type !== "automated" && r.question);
  const d = result.diff;

  return (
    <div className="space-y-6">
      {/* header */}
      <div className="card flex flex-wrap items-center justify-between gap-4 p-5">
        <div>
          <div className="text-xs uppercase tracking-wide text-slate-500">Report · scan {result.scan_id}</div>
          <h2 className="text-xl font-semibold">{result.target}</h2>
          <div className="text-xs text-slate-500">{new Date(result.created_at).toLocaleString()} {result.ai_used && `· AI: ${result.ai_model}`}</div>
        </div>
        <div className="flex flex-wrap gap-2">
          {canRescan ? <button className="btn-primary" onClick={onRescan}>Rescan after fixes</button>
            : <button className="btn-primary" onClick={onUploadFixed}>Upload fixed version</button>}
          <a className="btn-ghost" href={api.reportHtmlUrl(result.scan_id, true)}>HTML</a>
          <a className="btn-ghost" href={api.reportJsonUrl(result.scan_id)} download={`privtrace-${result.scan_id}.json`}>JSON</a>
          <button className="btn-ghost" onClick={onNew}>New scan</button>
        </div>
      </div>

      <div className="rounded-xl border border-amber-200 bg-amber-50 px-4 py-3 text-sm text-amber-900"><b>Not legal advice.</b> {result.disclaimer}</div>

      {/* 1. summary */}
      <section className="card p-5">
        <h3 className="mb-4 font-semibold">1. Summary</h3>
        <div className="flex flex-wrap gap-4">
          <div className="flex min-w-[170px] flex-col items-center rounded-xl border border-slate-200 p-4">
            <Gauge score={result.overall_score} size={132} label="Overall" />
            <div className="mt-1 font-semibold">Overall</div>
            <div className="text-xs text-slate-500">Risk level</div>
            <div className={`text-xl font-bold ${RISK_COLOR[result.risk_level]}`}>{result.risk_level}</div>
          </div>
          {result.pack_scores.map((p) => (
            <div key={p.pack_id} className="flex w-[180px] flex-col items-center rounded-xl border border-slate-200 p-4 text-center">
              <Gauge score={p.score} label={p.short_name} />
              <div className="mt-1 font-semibold">{p.short_name}</div>
              <div className="mt-1 text-xs text-slate-500">
                {p.coverage.automated_checked} of {p.coverage.total} rules checked automatically, {p.coverage.manual_answered} answered manually,{" "}
                {p.coverage.not_assessable} not assessable from code
              </div>
            </div>
          ))}
        </div>
        <div className="mt-4 grid grid-cols-2 gap-3 md:grid-cols-4">
          {[
            [result.summary.files_scanned, `files scanned (${result.summary.python_files} Python)`],
            [result.summary.models_with_pii, "data models holding personal data"],
            [result.summary.pii_sinks, "places personal data reaches a sink"],
            [result.summary.risky_flows, "risky flows"],
          ].map(([v, l], i) => (
            <div key={i} className="rounded-xl border border-slate-200 p-3">
              <div className={`text-2xl font-bold ${i === 3 ? "text-red-600" : ""}`}>{v}</div>
              <div className="text-xs text-slate-500">{l}</div>
            </div>
          ))}
        </div>

        {d && (
          <div className="mt-5 rounded-xl border border-indigo-200 bg-indigo-50/50 p-4 text-sm">
            <div className="font-semibold">Changes since last scan</div>
            <div className="mt-1">
              Overall {d.overall_before ?? "n/a"} → <b>{d.overall_after ?? "n/a"}</b> <Delta v={d.overall_delta} /> · Risk {d.risk_before} → <b>{d.risk_after}</b>
            </div>
            <div className="mt-2 flex flex-wrap gap-3 text-xs">
              {d.packs.map((p) => <span key={p.pack_id}>{p.short_name}: {p.before ?? "n/a"} → {p.after ?? "n/a"} <Delta v={p.delta} /></span>)}
            </div>
            {d.fixed.length > 0 && <div className="mt-2 text-green-700">Fixed: {d.fixed.map((f) => f.rule_id).join(", ")}</div>}
            {d.regressed.length > 0 && <div className="mt-1 text-red-700">New failures: {d.regressed.map((f) => f.rule_id).join(", ")}</div>}
          </div>
        )}

        <h4 className="mb-2 mt-6 font-semibold">Top fixes</h4>
        {top.length ? (
          <ol className="space-y-2">
            {top.map((t, i) => (
              <li key={t.rule_id} className="flex gap-3 rounded-lg border border-slate-200 p-3 text-sm">
                <span className="font-bold text-slate-400">{i + 1}</span>
                <div className="flex-1">
                  <div className="flex flex-wrap items-center gap-2"><SeverityBadge s={t.severity} /><a href={`#${t.pack_id}-${t.rule_id}`} className="font-medium hover:underline">{t.title}</a>
                    {t.evidence[0] && <code className="text-xs text-slate-500">{t.evidence[0].file}:{t.evidence[0].line}</code>}</div>
                  <div className="mt-1 text-slate-600">{t.remediation}</div>
                </div>
              </li>
            ))}
          </ol>
        ) : <p className="text-sm text-slate-500">No failed rules.</p>}
      </section>

      {/* 2. data flow */}
      <section className="card p-5">
        <h3 className="mb-1 font-semibold">2. Data-flow map</h3>
        <p className="mb-3 text-sm text-slate-500">Where personal data enters, which functions carry it, and which stores or third parties it reaches.</p>
        <FlowMap nodes={result.data_flow.nodes} edges={result.data_flow.edges} />
        {result.ai_classifications.length > 0 && (
          <div className="mt-4 text-sm">
            <div className="font-medium">Possible personal data in generic fields <span className="badge bg-violet-200 text-violet-800">AI-classified — review</span></div>
            <ul className="mt-1 list-inside list-disc text-slate-600">
              {result.ai_classifications.map((c) => <li key={c.name}><code>{c.name}</code> ({c.category}) {c.file && <span className="text-xs">{c.file}:{c.line}</span>} — {c.reason}</li>)}
            </ul>
          </div>
        )}
      </section>

      {/* 3. findings */}
      <section className="card p-5">
        <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
          <h3 className="font-semibold">3. Findings by framework</h3>
          <div className="inline-flex rounded-lg bg-slate-100 p-1 text-xs">
            {(["all", "failed", "needs_review", "passed", "not_assessable"] as const).map((f) => (
              <button key={f} onClick={() => setFilter(f)} className={`rounded-md px-2.5 py-1 font-medium ${filter === f ? "bg-white shadow-sm" : "text-slate-500"}`}>
                {f.replace("_", " ")}
              </button>
            ))}
          </div>
        </div>
        {result.pack_scores.map((p) => {
          const rs = result.results.filter((r) => r.pack_id === p.pack_id && (filter === "all" || r.status === filter))
            .sort((a, b) => ST_ORDER[a.status] - ST_ORDER[b.status] || SEV_ORDER[a.severity] - SEV_ORDER[b.severity]);
          return (
            <div key={p.pack_id} className="mt-5">
              <div className="mb-2 flex flex-wrap items-baseline gap-2">
                <h4 className="font-semibold">{p.name}</h4>
                <span className="text-sm text-slate-500">{p.score === null ? "n/a" : `${Math.round(p.score)}/100`} · {p.passed} passed · {p.failed} failed · {p.needs_review} review · {p.not_assessable} n/a</span>
              </div>
              <div className="space-y-2">{rs.map((r) => <Finding key={r.rule_id} r={r} />)}{!rs.length && <p className="text-sm text-slate-400">Nothing in this filter.</p>}</div>
            </div>
          );
        })}
      </section>

      {/* 4. checklist */}
      <section className="card p-5">
        <h3 className="mb-3 font-semibold">4. Manual checklist answers</h3>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead className="text-left text-slate-500"><tr><th className="py-2 pr-3">Rule</th><th className="py-2 pr-3">Question</th><th className="py-2 pr-3">Answer</th><th className="py-2">Result</th></tr></thead>
            <tbody>
              {manual.map((m) => (
                <tr key={m.pack_id + m.rule_id} className="border-t border-slate-100 align-top">
                  <td className="py-2 pr-3"><code className="text-xs">{m.rule_id}</code></td>
                  <td className="py-2 pr-3">{m.question}</td>
                  <td className="py-2 pr-3">{m.manual_answer?.replace("_", " ") ?? "—"}</td>
                  <td className="py-2"><StatusBadge s={m.status} /></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      {/* 5. coverage */}
      <section className="card p-5 text-sm">
        <h3 className="mb-3 font-semibold">5. Coverage and limitations</h3>
        <ul className="list-inside list-disc space-y-1 text-slate-600">
          {result.pack_scores.map((p) => (
            <li key={p.pack_id}><b>{p.short_name}</b>: {p.coverage.automated_checked} of {p.coverage.total} rules checked automatically, {p.coverage.manual_answered} answered manually,
              {" "}{p.coverage.not_assessable} not assessable from code, {p.coverage.needs_review} need review.</li>
          ))}
          <li>Python is analysed in depth; other files get identifier, secret and configuration checks.</li>
          <li>Flow tracking is intra-function plus calls into repo modules; dynamic dispatch and infrastructure config are not followed.</li>
          <li>Consent, minimisation, children’s data and third-party sharing are heuristics and never “fail” on their own.</li>
        </ul>
      </section>

      {/* 6. disclaimer + formula */}
      <section className="card p-5 text-sm text-slate-600">
        <h3 className="mb-2 font-semibold text-slate-900">6. Disclaimer</h3>
        <p>{result.disclaimer}</p>
        <p className="mt-3 text-xs"><b>How the score is calculated.</b> {result.scoring_formula}</p>
      </section>
    </div>
  );
}
