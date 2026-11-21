import { useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { api } from "../api";
import type { PackScore, RuleResult, ScanResult, Severity, Status } from "../types";
import FlowMap from "./FlowMap";
import { ArrowChip, Diff, Gauge, Icon, SectionHead, SeverityBadge, StatusBadge, scoreColor } from "./ui";

const SEV_ORDER: Record<Severity, number> = { critical: 0, high: 1, medium: 2, low: 3 };
const ST_ORDER: Record<Status, number> = { failed: 0, needs_review: 1, passed: 2, not_assessable: 3 };
const RISK_CARD = {
  Critical: "bg-rose-500 text-white shadow-[0_20px_60px_-20px_rgba(244,63,94,.8)]",
  High: "bg-orange-500 text-white shadow-[0_20px_60px_-20px_rgba(249,115,22,.8)]",
  Medium: "bg-sun text-ink-950 shadow-[0_20px_60px_-20px_rgba(255,216,77,.6)]",
  Low: "bg-lime text-ink-950 shadow-lime-glow",
};
const ST_BAR: Record<Status, string> = { failed: "bg-rose-500", passed: "bg-lime", needs_review: "bg-sun", not_assessable: "bg-zinc-500" };
const SEV_DOT: Record<Severity, string> = { critical: "bg-rose-400", high: "bg-orange-400", medium: "bg-amber-300", low: "bg-sky-300" };

const keyOf = (r: RuleResult) => `${r.pack_id}::${r.rule_id}`;
const byPriority = (a: RuleResult, b: RuleResult) => ST_ORDER[a.status] - ST_ORDER[b.status] || SEV_ORDER[a.severity] - SEV_ORDER[b.severity];
const splitPath = (p: string) => { const i = p.lastIndexOf("/"); return i < 0 ? ["", p] : [p.slice(0, i + 1), p.slice(i + 1)]; };

type View = "overview" | "hotspots" | "flow" | "checklist" | "coverage" | `pack:${string}`;

function Delta({ v }: { v: number | null }) {
  if (v === null) return null;
  return <span className={`rounded-full px-2 py-0.5 font-mono text-xs font-semibold ${v >= 0 ? "bg-lime/15 text-lime" : "bg-rose-500/15 text-rose-300"}`}>{v >= 0 ? "+" : ""}{v.toFixed(1)}</span>;
}

function CopyLoc({ text }: { text: string }) {
  const [ok, setOk] = useState(false);
  return (
    <button type="button" title="Copy location" aria-label={`Copy ${text}`}
      onClick={(e) => { e.stopPropagation(); navigator.clipboard?.writeText(text).then(() => { setOk(true); setTimeout(() => setOk(false), 1200); }).catch(() => {}); }}
      className={`rounded-md px-1.5 py-0.5 font-mono text-[10px] transition ${ok ? "bg-lime/20 text-lime" : "text-zinc-500 hover:bg-white/10 hover:text-white"}`}>
      {ok ? "copied" : "copy"}
    </button>
  );
}

// ------------------------------------------------------------------ hotspots (where it breaks)
type Hit = { r: RuleResult; line: number; snippet: string; detail: string };
type Hotspot = { file: string; hits: Hit[]; failed: number; review: number; worst: Severity };

function useHotspots(results: RuleResult[]): Hotspot[] {
  return useMemo(() => {
    const m = new Map<string, Hit[]>();
    results.filter((r) => r.status === "failed" || r.status === "needs_review").forEach((r) =>
      r.evidence.forEach((e) => { if (e.file) { const a = m.get(e.file) ?? []; a.push({ r, line: e.line, snippet: e.snippet, detail: e.detail }); m.set(e.file, a); } }));
    return [...m.entries()].map(([file, hits]) => {
      hits.sort((a, b) => a.line - b.line || byPriority(a.r, b.r));
      const failedHits = hits.filter((h) => h.r.status === "failed");
      const worst = (failedHits.length ? failedHits : hits).reduce<Severity>((w, h) => (SEV_ORDER[h.r.severity] < SEV_ORDER[w] ? h.r.severity : w), "low");
      return { file, hits, failed: failedHits.length, review: hits.length - failedHits.length, worst };
    }).sort((a, b) => (b.failed > 0 ? 1 : 0) - (a.failed > 0 ? 1 : 0) || SEV_ORDER[a.worst] - SEV_ORDER[b.worst] || b.hits.length - a.hits.length);
  }, [results]);
}

function HotspotsView({ spots, packName, onOpen }: { spots: Hotspot[]; packName: (id: string) => string; onOpen: (r: RuleResult) => void }) {
  const [open, setOpen] = useState<Set<string>>(() => new Set(spots.slice(0, 2).map((s) => s.file)));
  const max = Math.max(1, ...spots.map((s) => s.hits.length));
  const toggle = (f: string) => setOpen((o) => { const n = new Set(o); n.has(f) ? n.delete(f) : n.add(f); return n; });
  return (
    <div className="glass p-5 sm:p-6">
      <SectionHead n="◎" title="Where it breaks" sub="Every file with a failing or needs-review finding, worst first. Expand a file to see the exact lines, then jump to the finding." />
      {!spots.length && <div className="flex items-center gap-3 rounded-2xl bg-lime/10 p-4 text-sm text-lime"><Icon name="check" strokeWidth={2.6} /> No file-level problems found.</div>}
      <div className="space-y-2">
        {spots.map((s) => {
          const [dir, base] = splitPath(s.file);
          const isOpen = open.has(s.file);
          return (
            <div key={s.file} className={`overflow-hidden rounded-2xl border transition ${isOpen ? "border-white/10 bg-white/[.035]" : "border-white/[.06] bg-white/[.015] hover:bg-white/[.03]"}`}>
              <button onClick={() => toggle(s.file)} aria-expanded={isOpen} className="flex w-full items-center gap-3 px-4 py-3 text-left">
                <span className={`h-2.5 w-2.5 shrink-0 rounded-full ${s.failed ? SEV_DOT[s.worst] : "bg-sun"}`} />
                <Icon name="file" size={16} className="shrink-0 text-zinc-500" />
                <span className="min-w-0 flex-1 truncate font-mono text-sm"><span className="text-zinc-500">{dir}</span><span className="text-white">{base}</span></span>
                <span className="hidden w-32 sm:block"><span className="block h-1.5 overflow-hidden rounded-full bg-white/[.06]">
                  <span className="flex h-full" style={{ width: `${(s.hits.length / max) * 100}%` }}>
                    <span className="bg-rose-500" style={{ flex: s.failed }} /><span className="bg-sun" style={{ flex: s.review }} />
                  </span></span></span>
                {s.failed > 0 && <span className="rounded-full bg-rose-500/15 px-2 py-0.5 font-mono text-[11px] font-semibold text-rose-300">{s.failed} failed</span>}
                {s.review > 0 && <span className="hidden rounded-full bg-sun/15 px-2 py-0.5 font-mono text-[11px] font-semibold text-sun sm:inline">{s.review} review</span>}
                <Icon name="chevron" size={16} className={`shrink-0 text-zinc-500 transition ${isOpen ? "rotate-90" : ""}`} />
              </button>
              {isOpen && (
                <ul className="border-t border-white/[.06] bg-ink-950/50">
                  {s.hits.map((h, i) => (
                    <li key={i}>
                      <button onClick={() => onOpen(h.r)} className="group flex w-full items-start gap-3 border-t border-white/[.03] px-4 py-2.5 text-left first:border-t-0 hover:bg-violet-500/10">
                        <span className="w-12 shrink-0 pt-0.5 text-right font-mono text-xs text-violet-300">L{h.line}</span>
                        <span className={`mt-1.5 h-4 w-0.5 shrink-0 rounded ${ST_BAR[h.r.status]}`} />
                        <span className="min-w-0 flex-1">
                          <span className="flex flex-wrap items-center gap-2 text-sm">
                            <span className="font-medium text-white">{h.r.title}</span>
                            <SeverityBadge s={h.r.severity} />
                            <span className="text-[11px] text-zinc-500">{packName(h.r.pack_id)}</span>
                          </span>
                          {h.snippet && <code className="mt-1 block truncate text-xs text-zinc-400">{h.snippet}</code>}
                        </span>
                        <span className="flex shrink-0 items-center gap-1 pt-0.5 text-xs text-zinc-600 group-hover:text-white">Open <Icon name="arrow-right" size={13} /></span>
                      </button>
                    </li>
                  ))}
                </ul>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}

// ------------------------------------------------------------------ finding detail: what / where / why / how
function Block({ tone, icon, label, title, children }: { tone: string; icon: Parameters<typeof Icon>[0]["name"]; label: string; title: string; children: ReactNode }) {
  return (
    <section className="relative pl-12">
      <span className={`absolute left-0 top-0 flex h-9 w-9 items-center justify-center rounded-xl ${tone}`}><Icon name={icon} size={17} /></span>
      <div className="kicker">{label}</div>
      <h4 className="mt-0.5 font-display text-base font-semibold text-white">{title}</h4>
      <div className="mt-3 text-sm text-zinc-300">{children}</div>
    </section>
  );
}

function FindingDetail({ r, packLabel, pos, onPrev, onNext }: {
  r: RuleResult; packLabel: string; pos?: string; onPrev?: () => void; onNext?: () => void;
}) {
  const byFile = useMemo(() => {
    const m = new Map<string, RuleResult["evidence"]>();
    r.evidence.forEach((e) => { const k = e.file || "(no file)"; m.set(k, [...(m.get(k) ?? []), e]); });
    return [...m.entries()];
  }, [r]);
  const ok = r.status === "passed";

  return (
    <article className="glass overflow-hidden">
      <header className="relative border-b border-white/[.06] p-5 sm:p-6">
        <span className={`absolute inset-x-0 top-0 h-0.5 ${ST_BAR[r.status]}`} />
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div className="flex flex-wrap items-center gap-2"><StatusBadge s={r.status} /><SeverityBadge s={r.severity} /><span className="badge bg-white/[.06] text-zinc-400">{r.check_type}</span></div>
          {(onPrev || onNext) && (
            <div className="flex items-center gap-1">
              {pos && <span className="mr-1 font-mono text-[11px] text-zinc-500">{pos}</span>}
              <button onClick={onPrev} disabled={!onPrev} aria-label="Previous finding" className="flex h-8 w-8 items-center justify-center rounded-full text-zinc-400 ring-1 ring-white/10 transition hover:bg-white/10 hover:text-white disabled:opacity-30"><Icon name="arrow-left" size={14} /></button>
              <button onClick={onNext} disabled={!onNext} aria-label="Next finding" className="flex h-8 w-8 items-center justify-center rounded-full text-zinc-400 ring-1 ring-white/10 transition hover:bg-white/10 hover:text-white disabled:opacity-30"><Icon name="arrow-right" size={14} /></button>
            </div>
          )}
        </div>
        <h3 className="mt-3 font-display text-2xl font-semibold leading-tight tracking-tight text-white">{r.title}</h3>
        <div className="mt-1 font-mono text-xs text-zinc-500">{packLabel} · {r.rule_id}</div>
      </header>

      <div className="space-y-8 p-5 sm:p-6">
        <Block tone={ok ? "bg-lime/15 text-lime" : "bg-rose-500/15 text-rose-300"} icon={ok ? "check" : "alert"} label="01 · What" title={ok ? "What was checked" : r.status === "failed" ? "What is failing" : "What needs a look"}>
          <p className="leading-relaxed text-zinc-200">{r.message}</p>
          {r.question && (
            <div className="mt-3 rounded-xl bg-white/[.03] px-3.5 py-2.5 ring-1 ring-white/[.06]">
              <span className="kicker">Checklist answer</span>
              <p className="mt-1">{r.question} — <b className="capitalize text-white">{r.manual_answer?.replace("_", " ") ?? "not answered"}</b></p>
            </div>
          )}
        </Block>

        <Block tone="bg-violet-500/15 text-violet-300" icon="file" label="02 · Where" title={r.evidence.length ? `${r.evidence.length} location${r.evidence.length === 1 ? "" : "s"} in ${byFile.length} file${byFile.length === 1 ? "" : "s"}` : "Where"}>
          {r.evidence.length ? (
            <div className="space-y-3">
              {byFile.map(([file, evs]) => {
                const [dir, base] = splitPath(file);
                return (
                  <div key={file} className="overflow-hidden rounded-2xl border border-white/[.07] bg-ink-950/70">
                    <div className="flex items-center gap-2 border-b border-white/[.06] bg-white/[.02] px-3.5 py-2">
                      <Icon name="file" size={14} className="shrink-0 text-zinc-500" />
                      <span className="min-w-0 flex-1 truncate font-mono text-xs"><span className="text-zinc-500">{dir}</span><span className="text-white">{base}</span></span>
                      <span className="font-mono text-[10px] text-zinc-500">{evs.length}×</span>
                    </div>
                    {evs.map((e, i) => (
                      <div key={i} className="flex gap-3 border-t border-white/[.04] px-3.5 py-2.5 first:border-t-0">
                        <span className="w-10 shrink-0 select-none pt-0.5 text-right font-mono text-xs text-violet-300">{e.line ? `L${e.line}` : "—"}</span>
                        <div className="min-w-0 flex-1">
                          {e.snippet && <code className="block overflow-x-auto whitespace-pre rounded-lg bg-rose-500/[.07] px-2 py-1 text-xs text-zinc-100 ring-1 ring-inset ring-rose-400/15">{e.snippet}</code>}
                          {e.detail && <p className="mt-1 text-xs text-zinc-500">{e.detail}</p>}
                        </div>
                        {e.file && <CopyLoc text={`${e.file}:${e.line}`} />}
                      </div>
                    ))}
                  </div>
                );
              })}
              <p className="text-[11px] text-zinc-500">Snippets are redacted — identifiers and personal values are masked.</p>
            </div>
          ) : (
            <p className="text-zinc-400">{r.check_type === "manual" ? "Organisational control — answered from the checklist, not from code." : "No specific code location for this rule."}</p>
          )}
        </Block>

        <Block tone="bg-sun/15 text-sun" icon="book" label="03 · Why" title="Why it matters">
          <p className="leading-relaxed">{r.why_it_matters}</p>
          <div className="mt-3 flex flex-wrap items-center gap-2 rounded-xl bg-white/[.03] px-3.5 py-2.5 text-xs ring-1 ring-white/[.06]">
            <Icon name="shield" size={14} className="text-sun" />
            <span className="text-zinc-300">{r.reference}</span>
            {!r.reference_verified && <span className="badge bg-sun/15 text-sun ring-1 ring-inset ring-sun/30" title="Awaiting human verification">unverified</span>}
            {r.source_url && <a className="ml-auto inline-flex items-center gap-0.5 text-violet-300 hover:text-violet-200" href={r.source_url} target="_blank" rel="noreferrer">Read source <Icon name="arrow-up-right" size={12} /></a>}
          </div>
          {r.ai?.explanation && (
            <div className="mt-3 rounded-2xl border border-violet-400/25 bg-gradient-to-br from-violet-500/15 to-transparent p-4 text-zinc-200">
              <span className="badge mb-2 bg-violet-500 text-white"><Icon name="sparkle" size={11} /> AI explanation</span>
              <p>{r.ai.explanation}</p>
            </div>
          )}
        </Block>

        <Block tone="bg-lime/15 text-lime" icon="check" label="04 · How" title={ok ? "Keep it this way" : "How to fix it"}>
          <p className="leading-relaxed">{r.remediation}</p>
          {r.fix_diff ? (
            <div className="mt-3"><div className="mb-2 text-xs text-zinc-500">Suggested change · template-generated — review before applying</div><Diff text={r.fix_diff} /></div>
          ) : r.ai && (r.ai.suggested_diff || r.ai.suggested_fix) ? (
            <div className="mt-3">
              <span className="badge mb-2 bg-violet-500/20 text-violet-200">AI-suggested — review before applying</span>
              {r.ai.suggested_fix && <p className="mb-2">{r.ai.suggested_fix}</p>}
              {r.ai.suggested_diff && <Diff text={r.ai.suggested_diff} />}
            </div>
          ) : null}
        </Block>
      </div>
    </article>
  );
}

// ------------------------------------------------------------------ framework tab
const FILTERS = ["all", "failed", "needs_review", "passed", "not_assessable"] as const;

function FrameworkView({ pack, results, selected, onSelect }: {
  pack: PackScore; results: RuleResult[]; selected: string | null; onSelect: (k: string) => void;
}) {
  const [filter, setFilter] = useState<(typeof FILTERS)[number]>("all");
  const [q, setQ] = useState("");
  const counts = useMemo(() => {
    const c: Record<Status, number> = { failed: 0, passed: 0, needs_review: 0, not_assessable: 0 };
    results.forEach((r) => { c[r.status] += 1; });
    return c;
  }, [results]);
  const list = useMemo(() => {
    const needle = q.trim().toLowerCase();
    return results.filter((r) => (filter === "all" || r.status === filter) && (!needle
      || r.title.toLowerCase().includes(needle) || r.rule_id.toLowerCase().includes(needle)
      || r.evidence.some((e) => e.file.toLowerCase().includes(needle))));
  }, [results, filter, q]);
  const current = results.find((r) => keyOf(r) === selected) ?? list[0] ?? null;
  const i = current ? list.findIndex((r) => keyOf(r) === keyOf(current)) : -1;
  const detail = current && (
    <FindingDetail r={current} packLabel={pack.short_name} pos={i >= 0 ? `${i + 1} / ${list.length}` : undefined}
      onPrev={i > 0 ? () => onSelect(keyOf(list[i - 1])) : undefined}
      onNext={i >= 0 && i < list.length - 1 ? () => onSelect(keyOf(list[i + 1])) : undefined} />
  );

  return (
    <div className="space-y-4">
      {/* framework header */}
      <div className="glass flex flex-wrap items-center gap-5 p-5 sm:p-6">
        <Gauge score={pack.score} size={104} stroke={9} label={pack.short_name} />
        <div className="min-w-0 flex-1">
          <span className="kicker">Framework</span>
          <h2 className="mt-1 font-display text-2xl font-semibold tracking-tight text-white sm:text-3xl">{pack.name}</h2>
          <div className="mt-3 flex h-2 max-w-md overflow-hidden rounded-full bg-white/[.06]">
            {(["failed", "needs_review", "passed", "not_assessable"] as Status[]).map((k) => <span key={k} className={ST_BAR[k]} style={{ flex: counts[k] }} />)}
          </div>
          <div className="mt-2 flex flex-wrap gap-x-4 gap-y-1 text-xs">
            <span className="text-rose-300"><b>{counts.failed}</b> failed</span><span className="text-sun"><b>{counts.needs_review}</b> needs review</span>
            <span className="text-lime"><b>{counts.passed}</b> passed</span><span className="text-zinc-500"><b>{counts.not_assessable}</b> not assessable</span>
          </div>
        </div>
        <div className="text-xs leading-relaxed text-zinc-500 sm:text-right">
          {pack.coverage.automated_checked}/{pack.coverage.total} checked automatically<br />{pack.coverage.manual_answered} answered manually
        </div>
      </div>

      {/* filters */}
      <div className="flex flex-wrap items-center gap-3">
        <div className="flex max-w-full overflow-x-auto rounded-full bg-ink-950/80 p-1 text-xs ring-1 ring-white/[.07]" role="tablist" aria-label="Filter findings">
          {FILTERS.map((f) => (
            <button key={f} role="tab" aria-selected={filter === f} onClick={() => setFilter(f)}
              className={`whitespace-nowrap rounded-full px-3 py-1.5 font-semibold capitalize transition ${filter === f ? "bg-white text-ink-950" : "text-zinc-400 hover:text-white"}`}>
              {f.replace("_", " ")} <span className="opacity-60">{f === "all" ? results.length : counts[f]}</span>
            </button>
          ))}
        </div>
        <label className="relative min-w-[200px] flex-1">
          <span className="sr-only">Search findings</span>
          <Icon name="scan" size={15} className="pointer-events-none absolute left-3.5 top-1/2 -translate-y-1/2 text-zinc-500" />
          <input value={q} onChange={(e) => setQ(e.target.value)} placeholder="Search by rule, title or file…" className="input h-10 rounded-full py-2 pl-10" />
        </label>
      </div>

      {/* list + detail */}
      <div className="grid gap-4 lg:grid-cols-[minmax(280px,360px)_1fr]">
        <ul className="space-y-1.5 lg:sticky lg:top-24 lg:max-h-[calc(100vh-7rem)] lg:self-start lg:overflow-y-auto lg:pr-1">
          {!list.length && <li className="glass-tile p-4 text-sm text-zinc-500">Nothing matches.</li>}
          {list.map((r) => {
            const active = current && keyOf(r) === keyOf(current);
            const files = new Set(r.evidence.map((e) => e.file).filter(Boolean));
            const first = r.evidence.find((e) => e.file);
            return (
              <li key={keyOf(r)}>
                <button onClick={() => onSelect(keyOf(r))} aria-current={active ? "true" : undefined}
                  className={`relative flex w-full gap-3 rounded-2xl border px-3.5 py-3 text-left transition ${active
                    ? "border-violet-400/40 bg-gradient-to-r from-violet-500/20 to-violet-500/[.04] shadow-glow"
                    : "border-white/[.05] bg-white/[.02] hover:border-white/10 hover:bg-white/[.04]"}`}>
                  <span className={`mt-1 h-9 w-1 shrink-0 rounded-full ${ST_BAR[r.status]}`} />
                  <span className="min-w-0 flex-1">
                    <span className="block text-sm font-medium leading-snug text-white">{r.title}</span>
                    <span className="mt-1.5 flex flex-wrap items-center gap-x-2 gap-y-1 text-[11px]">
                      <span className="flex items-center gap-1 capitalize text-zinc-400"><i className={`h-1.5 w-1.5 rounded-full ${SEV_DOT[r.severity]}`} />{r.severity}</span>
                      {first ? (
                        <span className="min-w-0 truncate font-mono text-violet-300/90">{splitPath(first.file)[1]}:{first.line}{r.evidence.length > 1 && <span className="text-zinc-500"> +{r.evidence.length - 1}</span>}</span>
                      ) : <span className="text-zinc-600">{r.check_type === "manual" ? "checklist" : "no location"}</span>}
                      {files.size > 1 && <span className="text-zinc-600">{files.size} files</span>}
                    </span>
                  </span>
                </button>
                {active && <div className="mt-2 lg:hidden">{detail}</div>}
              </li>
            );
          })}
        </ul>
        <div className="hidden lg:block">{detail}</div>
      </div>
    </div>
  );
}

// ------------------------------------------------------------------ sidebar
function NavItem({ active, onClick, children, badge }: { active: boolean; onClick: () => void; children: ReactNode; badge?: ReactNode }) {
  return (
    <button onClick={onClick} aria-current={active ? "page" : undefined}
      className={`relative flex shrink-0 items-center gap-3 rounded-2xl px-3 py-2.5 text-left text-sm transition lg:w-full ${active
        ? "bg-white/[.08] text-white ring-1 ring-white/10" : "text-zinc-400 hover:bg-white/[.04] hover:text-white"}`}>
      {active && <span className="absolute -left-[13px] top-1/2 hidden h-6 w-1 -translate-y-1/2 rounded-full bg-violet-400 shadow-[0_0_12px_2px_rgba(167,139,250,.8)] lg:block" />}
      {children}
      {badge && <span className="ml-auto pl-2">{badge}</span>}
    </button>
  );
}

// ------------------------------------------------------------------ report
export default function Report({ result, canRescan, onRescan, onUploadFixed, onNew }: {
  result: ScanResult;
  canRescan: boolean;
  onRescan: () => void;
  onUploadFixed: () => void;
  onNew: () => void;
}) {
  const [view, setView] = useState<View>("overview");
  const [selected, setSelected] = useState<string | null>(null);
  const contentRef = useRef<HTMLDivElement>(null);

  const byPack = useMemo(() => {
    const m: Record<string, RuleResult[]> = {};
    result.pack_scores.forEach((p) => { m[p.pack_id] = result.results.filter((r) => r.pack_id === p.pack_id).sort(byPriority); });
    return m;
  }, [result]);
  const spots = useHotspots(result.results);
  const packName = (id: string) => result.pack_scores.find((p) => p.pack_id === id)?.short_name ?? id;

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

  const go = (v: View, sel?: string | null) => {
    setView(v);
    if (sel !== undefined) setSelected(sel);
    else if (v.startsWith("pack:")) { const first = byPack[v.slice(5)]?.[0]; setSelected(first ? keyOf(first) : null); }
  };
  const openFinding = (r: RuleResult) => go(`pack:${r.pack_id}`, keyOf(r));

  // bring the content panel into view when switching tabs (matters on mobile, where the nav sits above it)
  const firstRender = useRef(true);
  useEffect(() => {
    if (firstRender.current) { firstRender.current = false; return; }
    const el = contentRef.current;
    if (el && el.getBoundingClientRect().top < 80) el.scrollIntoView({ behavior: "smooth", block: "start" });
  }, [view, selected]);

  const activePack = view.startsWith("pack:") ? result.pack_scores.find((p) => p.pack_id === view.slice(5)) : undefined;

  return (
    <div className="space-y-6">
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
          <a className="btn-violet" href={api.reportPdfUrl(result.scan_id)} download={`privtrace-${result.scan_id}.pdf`}><Icon name="file" size={15} /> PDF report</a>
          <a className="btn-ghost" href={api.reportHtmlUrl(result.scan_id, true)}><Icon name="download" size={15} /> HTML</a>
          <a className="btn-ghost" href={api.reportJsonUrl(result.scan_id)} download={`privtrace-${result.scan_id}.json`}><Icon name="download" size={15} /> JSON</a>
          <button className="btn-ghost" onClick={onNew}><Icon name="plus" size={15} /> New scan</button>
        </div>
      </div>

      <div className="flex items-start gap-3 rounded-2xl border border-sun/25 bg-sun/[.07] px-4 py-3 text-sm text-amber-100">
        <Icon name="shield" size={18} className="mt-0.5 shrink-0 text-sun" />
        <p><b className="text-sun">Not legal advice.</b> {result.disclaimer}</p>
      </div>

      <div className="grid gap-6 lg:grid-cols-[250px_1fr]">
        {/* sidebar tabs */}
        <aside className="lg:sticky lg:top-24 lg:self-start">
          <nav aria-label="Report sections" className="glass flex gap-1 overflow-x-auto p-2 lg:flex-col lg:overflow-visible lg:p-3">
            <span className="kicker hidden px-3 pb-1 pt-1 lg:block">Report</span>
            <NavItem active={view === "overview"} onClick={() => go("overview")}><Icon name="layers" size={17} />Overview</NavItem>
            <NavItem active={view === "hotspots"} onClick={() => go("hotspots")}
              badge={spots.length > 0 && <span className="rounded-full bg-rose-500/15 px-2 py-0.5 font-mono text-[10px] font-semibold text-rose-300">{spots.length}</span>}>
              <Icon name="file" size={17} />Where it breaks
            </NavItem>
            <NavItem active={view === "flow"} onClick={() => go("flow")}
              badge={s.risky_flows > 0 && <span className="rounded-full bg-rose-500/15 px-2 py-0.5 font-mono text-[10px] font-semibold text-rose-300">{s.risky_flows}</span>}>
              <Icon name="flow" size={17} />Data flow
            </NavItem>

            <span className="kicker hidden px-3 pb-1 pt-4 lg:block">Frameworks</span>
            <span className="mx-1 my-2 w-px shrink-0 bg-white/10 lg:hidden" />
            {result.pack_scores.map((p) => (
              <NavItem key={p.pack_id} active={view === `pack:${p.pack_id}`} onClick={() => go(`pack:${p.pack_id}`)}
                badge={p.failed > 0
                  ? <span className="rounded-full bg-rose-500 px-2 py-0.5 font-mono text-[10px] font-bold text-white">{p.failed}</span>
                  : <Icon name="check" size={14} className="text-lime" strokeWidth={2.6} />}>
                <span className="flex h-8 w-8 shrink-0 items-center justify-center rounded-xl bg-ink-950/80 font-display text-xs font-bold ring-1 ring-white/10" style={{ color: scoreColor(p.score) }}>
                  {p.score === null ? "–" : Math.round(p.score)}
                </span>
                <span className="whitespace-nowrap font-medium lg:truncate">{p.short_name}</span>
              </NavItem>
            ))}

            <span className="kicker hidden px-3 pb-1 pt-4 lg:block">More</span>
            <span className="mx-1 my-2 w-px shrink-0 bg-white/10 lg:hidden" />
            <NavItem active={view === "checklist"} onClick={() => go("checklist")}><Icon name="list" size={17} /><span className="whitespace-nowrap">Checklist</span></NavItem>
            <NavItem active={view === "coverage"} onClick={() => go("coverage")}><Icon name="eye" size={17} /><span className="whitespace-nowrap">Coverage</span></NavItem>
          </nav>

          <div className="glass mt-4 hidden p-4 lg:block">
            <span className="kicker">Overall</span>
            <div className="mt-2 flex items-center gap-3">
              <span className="font-display text-3xl font-bold" style={{ color: scoreColor(result.overall_score) }}>{result.overall_score === null ? "n/a" : Math.round(result.overall_score)}</span>
              <span className="text-xs text-zinc-400">Risk <b className="text-white">{result.risk_level}</b></span>
            </div>
            <div className="mt-3 flex h-1.5 overflow-hidden rounded-full bg-white/[.06]">
              {(["failed", "needs_review", "passed", "not_assessable"] as Status[]).map((k) => <span key={k} className={ST_BAR[k]} style={{ flex: counts[k] }} />)}
            </div>
            <div className="mt-2 text-[11px] text-zinc-500">{counts.failed} failed · {counts.needs_review} review · {counts.passed} passed</div>
          </div>
        </aside>

        {/* content */}
        <div ref={contentRef} key={view} className="min-w-0 scroll-mt-28 animate-fade-up">
          {view === "overview" && (
            <div className="space-y-4">
              <div className="grid gap-4 md:grid-cols-4">
                <div className="glass relative flex flex-col items-center justify-center overflow-hidden p-6 md:col-span-2 md:row-span-2">
                  <div className="dot-grid absolute inset-0 opacity-40 [mask-image:radial-gradient(circle,black,transparent_70%)]" aria-hidden="true" />
                  <div className="absolute left-1/2 top-1/2 h-64 w-64 -translate-x-1/2 -translate-y-1/2 rounded-full blur-[80px]" style={{ background: scoreColor(result.overall_score), opacity: 0.18 }} aria-hidden="true" />
                  <span className="kicker relative">Overall score</span>
                  <div className="relative mt-3"><Gauge score={result.overall_score} size={210} stroke={14} label="Overall" /></div>
                  <div className="relative mt-4 flex w-full max-w-sm gap-1.5" aria-label="Rule outcomes">
                    {(["failed", "needs_review", "passed", "not_assessable"] as Status[]).map((k) => counts[k] > 0 && (
                      <div key={k} className="min-w-0" style={{ flex: counts[k] }}>
                        <div className={`h-1.5 rounded-full ${ST_BAR[k]}`} />
                        <div className="mt-1.5 truncate text-[11px] text-zinc-400"><b className="text-white">{counts[k]}</b> {k.replace("_", " ")}</div>
                      </div>
                    ))}
                  </div>
                </div>
                <div className={`flex flex-col justify-between rounded-3xl p-5 ${RISK_CARD[result.risk_level]}`}>
                  <span className="text-sm font-semibold leading-tight">Risk<br />level</span>
                  <div className="mt-6 font-display text-4xl font-bold tracking-tight">{result.risk_level}</div>
                </div>
                <button onClick={() => go("hotspots")} className="group flex flex-col justify-between rounded-3xl bg-white p-5 text-left text-ink-950 shadow-lift transition hover:-translate-y-0.5">
                  <div className="flex w-full items-start justify-between"><span className="text-sm font-semibold leading-tight">Files<br />breaking</span><ArrowChip dark className="h-8 w-8" /></div>
                  <div className="mt-6"><div className="font-display text-5xl font-bold tracking-tight">{spots.filter((x) => x.failed).length}</div><div className="text-xs text-zinc-500">of {s.files_scanned} scanned</div></div>
                </button>
                <div className="flex flex-col justify-between rounded-3xl bg-sun p-5 text-ink-950 shadow-lift">
                  <span className="text-sm font-semibold leading-tight">Models holding<br />personal data</span>
                  <div className="mt-6 font-display text-5xl font-bold tracking-tight">{s.models_with_pii}</div>
                </div>
                <button onClick={() => go("flow")} className="glass group flex flex-col justify-between p-5 text-left transition hover:-translate-y-0.5">
                  <div className="flex w-full items-start justify-between text-white"><span className="text-sm font-semibold leading-tight">Personal data<br />reaching a sink</span><Icon name="database" className="text-violet-300" /></div>
                  <div className="mt-6 flex w-full items-end justify-between">
                    <div className="font-display text-5xl font-bold tracking-tight text-white">{s.pii_sinks}</div>
                    <div className="text-right"><div className="font-display text-2xl font-bold text-rose-400">{s.risky_flows}</div><div className="text-[11px] uppercase tracking-wide text-zinc-500">risky flows</div></div>
                  </div>
                </button>
              </div>

              {d && (
                <div className="overflow-hidden rounded-3xl border border-violet-400/25 bg-gradient-to-br from-violet-600/20 via-violet-500/[.06] to-transparent p-5 sm:p-6">
                  <div className="flex flex-wrap items-center justify-between gap-4">
                    <div>
                      <span className="kicker text-violet-300/80">Changes since last scan</span>
                      <div className="mt-2 flex flex-wrap items-center gap-3 font-display text-3xl font-bold text-white">
                        <span className="text-zinc-500">{d.overall_before ?? "n/a"}</span><Icon name="arrow-right" className="text-violet-300" /><span>{d.overall_after ?? "n/a"}</span><Delta v={d.overall_delta} />
                      </div>
                      <div className="mt-1 text-sm text-zinc-400">Risk {d.risk_before} → <b className="text-white">{d.risk_after}</b></div>
                    </div>
                    <div className="flex flex-wrap gap-2">
                      {d.packs.map((p) => (
                        <span key={p.pack_id} className="glass-tile flex items-center gap-2 px-3 py-2 text-xs text-zinc-300"><b className="text-white">{p.short_name}</b> {p.before ?? "n/a"} → {p.after ?? "n/a"} <Delta v={p.delta} /></span>
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

              <div className="glass p-5 sm:p-6">
                <SectionHead n="01" title="Frameworks" sub="Open a framework to see each rule — what failed, where, why and how to fix it." />
                <div className="grid gap-3 sm:grid-cols-2">
                  {result.pack_scores.map((p) => (
                    <button key={p.pack_id} onClick={() => go(`pack:${p.pack_id}`)} className="group flex items-center gap-4 rounded-2xl border border-white/[.06] bg-white/[.02] p-4 text-left transition hover:-translate-y-0.5 hover:border-violet-400/30 hover:bg-white/[.05]">
                      <Gauge score={p.score} size={76} stroke={7} label={p.short_name} />
                      <div className="min-w-0 flex-1">
                        <div className="font-display text-lg font-semibold text-white">{p.short_name}</div>
                        <div className="mt-1 flex flex-wrap gap-x-2 text-[11px] font-medium">
                          <span className="text-rose-300">{p.failed} failed</span><span className="text-sun">{p.needs_review} review</span><span className="text-lime">{p.passed} passed</span>
                        </div>
                      </div>
                      <Icon name="arrow-right" size={16} className="text-zinc-600 transition group-hover:translate-x-0.5 group-hover:text-white" />
                    </button>
                  ))}
                </div>
              </div>

              <div className="glass p-5 sm:p-6">
                <SectionHead n="02" title="Top fixes" sub="Highest-severity failures first — click to see exactly where and how to fix." />
                {top.length ? (
                  <ol className="grid gap-3 lg:grid-cols-2">
                    {top.map((t, i) => (
                      <li key={keyOf(t)} className={i === 0 ? "lg:col-span-2" : ""}>
                        <button onClick={() => openFinding(t)} className="group flex h-full w-full gap-4 rounded-2xl border border-white/[.06] bg-white/[.02] p-4 text-left transition hover:-translate-y-0.5 hover:border-violet-400/30 hover:bg-white/[.05]">
                          <span className="font-display text-3xl font-bold leading-none text-white/20 transition group-hover:text-lime">{String(i + 1).padStart(2, "0")}</span>
                          <div className="min-w-0 flex-1 text-sm">
                            <div className="flex flex-wrap items-center gap-2"><SeverityBadge s={t.severity} /><span className="font-medium text-white">{t.title}</span></div>
                            {t.evidence[0]?.file && <code className="mt-1 block truncate text-xs text-violet-300">{t.evidence[0].file}:{t.evidence[0].line}</code>}
                            <div className="mt-1.5 text-zinc-400">{t.remediation}</div>
                          </div>
                          <Icon name="arrow-up-right" size={16} className="shrink-0 text-zinc-600 transition group-hover:text-white" />
                        </button>
                      </li>
                    ))}
                  </ol>
                ) : <div className="flex items-center gap-3 rounded-2xl bg-lime/10 p-4 text-sm text-lime"><Icon name="check" strokeWidth={2.6} /> No failed rules.</div>}
              </div>
            </div>
          )}

          {view === "hotspots" && <HotspotsView spots={spots} packName={packName} onOpen={openFinding} />}

          {view === "flow" && (
            <section className="glass p-5 sm:p-6">
              <SectionHead n="◇" title="Data-flow map" sub="Where personal data enters, which functions carry it, and which stores or third parties it reaches." />
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
          )}

          {activePack && <FrameworkView pack={activePack} results={byPack[activePack.pack_id] ?? []} selected={selected} onSelect={setSelected} />}

          {view === "checklist" && (
            <section className="glass p-5 sm:p-6">
              <SectionHead n="✓" title="Manual checklist answers" />
              {manual.length ? (
                <div className="overflow-x-auto rounded-2xl border border-white/[.06]">
                  <table className="w-full text-sm">
                    <thead className="text-left"><tr className="border-b border-white/[.06]"><th className="kicker px-4 py-3 font-normal">Rule</th><th className="kicker px-4 py-3 font-normal">Question</th><th className="kicker px-4 py-3 font-normal">Answer</th><th className="kicker px-4 py-3 font-normal">Result</th></tr></thead>
                    <tbody>
                      {manual.map((m) => (
                        <tr key={keyOf(m)} onClick={() => openFinding(m)} className="cursor-pointer border-t border-white/[.04] align-top transition hover:bg-white/[.03]">
                          <td className="px-4 py-3"><code className="text-xs text-violet-300">{m.rule_id}</code><div className="text-[10px] text-zinc-600">{packName(m.pack_id)}</div></td>
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
          )}

          {view === "coverage" && (
            <div className="space-y-4">
              <section className="glass p-5 text-sm sm:p-6">
                <SectionHead n="◐" title="Coverage and limitations" />
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
              <section className="glass p-5 text-sm sm:p-6">
                <SectionHead n="§" title="Disclaimer" />
                <p className="text-zinc-400">{result.disclaimer}</p>
                <div className="mt-4 rounded-2xl bg-ink-950/60 p-4 text-xs text-zinc-400 ring-1 ring-white/[.05]"><b className="text-white">How the score is calculated.</b> {result.scoring_formula}</div>
              </section>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
