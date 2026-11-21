import { useEffect, useRef, useState, type ReactNode } from "react";
import { api } from "../api";
import type { Answer, ChecklistItem, PackSummary, ScanStatus } from "../types";
import { ArrowChip, Icon, SeverityBadge, Spinner } from "./ui";

export type Source = { kind: "github"; url: string } | { kind: "zip"; file: File };

function StepHeader({ n, title, accent, sub, right }: { n: string; title: string; accent: string; sub: string; right?: ReactNode }) {
  return (
    <div className="mb-8 flex flex-wrap items-end justify-between gap-4">
      <div>
        <span className="kicker">Step {n}</span>
        <h2 className="mt-2 font-display text-4xl font-semibold tracking-tight text-white sm:text-5xl">
          {title} <span className="font-serif font-normal italic text-violet-300">{accent}</span>
        </h2>
        <p className="mt-3 max-w-2xl text-sm text-zinc-400 sm:text-base">{sub}</p>
      </div>
      {right}
    </div>
  );
}

/** Floating action bar that sticks to the bottom of the viewport. */
function ActionBar({ children }: { children: ReactNode }) {
  return (
    <div className="sticky bottom-4 z-30 mt-8">
      <div className="flex items-center justify-between gap-3 rounded-full border border-white/[.08] bg-ink-900/80 p-2 pl-3 shadow-lift backdrop-blur-xl">
        {children}
      </div>
    </div>
  );
}

// ------------------------------------------------------------------ hero visual
function HeroVisual() {
  return (
    <div aria-hidden="true" className="relative mx-auto h-[340px] w-full max-w-[520px] sm:h-[460px]">
      {/* rings */}
      <div className="absolute left-1/2 top-1/2 h-[300px] w-[300px] -translate-x-1/2 -translate-y-1/2 sm:h-[400px] sm:w-[400px]">
        <div className="orb-ring absolute inset-0 animate-spin-slower rounded-full">
          <span className="absolute -top-1.5 left-1/2 h-3 w-3 -translate-x-1/2 rounded-full bg-lime shadow-[0_0_18px_4px_rgba(212,255,63,.7)]" />
        </div>
        <div className="orb-ring absolute inset-[14%] animate-spin-slow rounded-full [animation-direction:reverse]">
          <span className="absolute -bottom-1 left-[20%] h-2 w-2 rounded-full bg-violet-300 shadow-[0_0_14px_4px_rgba(167,139,250,.8)]" />
        </div>
      </div>
      {/* orb */}
      <div className="absolute left-1/2 top-1/2 -translate-x-1/2 -translate-y-1/2">
        <div className="orb h-40 w-40 animate-float rounded-full sm:h-56 sm:w-56" />
        <div className="mx-auto mt-6 h-4 w-32 rounded-[50%] bg-violet-500/30 blur-xl sm:w-44" />
      </div>

      {/* floating chips */}
      <div className="glass absolute left-0 top-6 hidden w-56 animate-float-slow rounded-2xl p-3.5 sm:block">
        <div className="flex items-center gap-2 text-[11px] font-medium text-rose-300"><span className="h-1.5 w-1.5 rounded-full bg-rose-400 shadow-[0_0_8px_2px_rgba(251,113,133,.8)]" /> Risky flow</div>
        <div className="mt-2 font-mono text-xs text-zinc-200">user.email <span className="text-zinc-500">→</span> <span className="text-violet-300">gemini.prompt</span></div>
        <div className="mt-1 font-mono text-[10px] text-zinc-500">app/llm.py:42</div>
      </div>

      <div className="absolute right-0 top-14 hidden w-40 animate-float rounded-2xl bg-lime p-4 text-ink-950 shadow-lime-glow [animation-delay:-2s] sm:block">
        <div className="flex items-start justify-between"><span className="text-xs font-semibold leading-tight">Overall<br />score</span><ArrowChip dark className="h-7 w-7" /></div>
        <div className="mt-3 font-display text-4xl font-bold tracking-tight">100</div>
        <div className="text-[11px] font-medium opacity-70">+94 after fixes</div>
      </div>

      <div className="glass absolute bottom-10 left-4 hidden animate-float rounded-2xl px-3.5 py-3 [animation-delay:-4s] sm:block">
        <div className="flex items-center gap-2">
          <span className="flex h-7 w-7 items-center justify-center rounded-full bg-lime/15 text-lime"><Icon name="check" size={14} strokeWidth={2.6} /></span>
          <div>
            <div className="text-xs font-semibold text-white">Aadhaar detected</div>
            <div className="font-mono text-[10px] text-zinc-500">Verhoeff checksum ✓</div>
          </div>
        </div>
      </div>

      <div className="absolute bottom-4 right-2 hidden w-48 animate-float-slow rounded-2xl bg-white p-3.5 text-ink-950 shadow-lift [animation-delay:-5s] sm:block">
        <div className="font-mono text-[10px] font-semibold uppercase tracking-wider text-zinc-500">DELETE /users/{"{id}"}</div>
        <div className="mt-1 flex items-end justify-between">
          <span className="font-display text-3xl font-bold">3</span>
          <span className="rounded-full bg-rose-500 px-2 py-0.5 text-[10px] font-bold uppercase text-white">stores missed</span>
        </div>
      </div>
    </div>
  );
}

function FeatureBento() {
  return (
    <div className="mt-16 grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
      <div className="group relative overflow-hidden rounded-3xl bg-lime p-6 text-ink-950 shadow-lime-glow sm:col-span-2 lg:row-span-2">
        <div className="flex items-start justify-between">
          <h3 className="font-display text-3xl font-bold leading-[1.05] tracking-tight sm:text-4xl">Personal<br />data-flow map</h3>
          <ArrowChip dark />
        </div>
        <p className="mt-4 max-w-sm text-sm font-medium text-ink-950/70">Follows names, emails, phone numbers and Indian IDs from request models into logs, LLM prompts, vector stores, caches and third-party APIs.</p>
        <div className="mt-6 flex flex-wrap gap-2">
          {["Postgres", "pgvector", "Redis", "Logs", "Gemini", "HTTP"].map((s) => (
            <span key={s} className="rounded-full bg-ink-950/90 px-3 py-1 font-mono text-[11px] text-lime">{s}</span>
          ))}
        </div>
        <svg viewBox="0 0 200 80" className="pointer-events-none absolute -bottom-2 right-0 w-64 opacity-25" aria-hidden="true">
          <path d="M0 60 C 50 60, 50 15, 100 15 S 150 60, 200 40" fill="none" stroke="#050409" strokeWidth="2" />
          <path d="M0 30 C 60 30, 70 70, 120 70 S 170 20, 200 20" fill="none" stroke="#050409" strokeWidth="2" strokeDasharray="4 5" />
        </svg>
      </div>
      <div className="rounded-3xl bg-white p-6 text-ink-950 shadow-lift">
        <div className="text-sm font-semibold leading-tight">Compliance<br />packs</div>
        <div className="mt-6 font-display text-6xl font-bold tracking-tight">5</div>
        <div className="mt-1 text-xs text-zinc-500">DPDP · IT Act · CERT-In · GDPR · Security</div>
      </div>
      <div className="rounded-3xl bg-sun p-6 text-ink-950 shadow-lift">
        <div className="flex items-start justify-between"><div className="text-sm font-semibold leading-tight">Evidence<br />on every finding</div><span className="text-lg leading-none">⋮</span></div>
        <div className="mt-6 font-mono text-3xl font-bold tracking-tight">file:line</div>
        <div className="mt-1 text-xs text-ink-950/60">Redacted snippets + suggested diffs</div>
      </div>
      <div className="group glass flex items-center justify-between gap-4 p-6 sm:col-span-2">
        <div>
          <div className="font-display text-lg font-bold uppercase leading-tight tracking-wide text-white">Scan. Fix.<br />Rescan. Diff.</div>
          <p className="mt-2 text-sm text-zinc-400">Upload the fixed version and see exactly which rules flipped to pass.</p>
        </div>
        <ArrowChip />
      </div>
    </div>
  );
}

// ------------------------------------------------------------------ 1. Connect
export function ConnectStep({ initial, baselineNote, onNext }: {
  initial: Source | null;
  baselineNote?: string;
  onNext: (s: Source) => void;
}) {
  const [tab, setTab] = useState<"github" | "zip">(initial?.kind ?? "github");
  const [url, setUrl] = useState(initial?.kind === "github" ? initial.url : "");
  const [file, setFile] = useState<File | null>(initial?.kind === "zip" ? initial.file : null);
  const [drag, setDrag] = useState(false);
  const urlOk = /^https:\/\/github\.com\/[\w.-]+\/[\w.-]+?(\.git)?\/?$/.test(url.trim());
  const ready = tab === "github" ? urlOk : !!file;
  const submit = () => { if (ready) onNext(tab === "github" ? { kind: "github", url: url.trim() } : { kind: "zip", file: file! }); };

  return (
    <div>
      <section className="grid items-center gap-10 lg:grid-cols-[1.08fr_.92fr]">
        <div>
          <span className="eyebrow">
            <span className="h-1.5 w-1.5 rounded-full bg-lime shadow-[0_0_10px_2px_rgba(212,255,63,.8)]" />
            Compliance exposure scanner for codebases
          </span>
          <h1 className="mt-6 font-display text-[44px] font-semibold leading-[1.02] tracking-[-0.035em] text-white sm:text-6xl lg:text-[76px]">
            Trace every byte of <span className="font-serif font-normal italic text-gradient">personal data</span> before it leaks.
          </h1>
          <p className="mt-6 max-w-xl text-base text-zinc-400 sm:text-lg">
            Scan your repo against India’s DPDP Act, IT Act/SPDI, CERT-In and GDPR. Get a scored report with file:line evidence and concrete fixes.
          </p>

          <div className="glass mt-8 p-5 sm:p-6">
            {baselineNote && (
              <p className="mb-4 flex items-start gap-2 rounded-2xl border border-violet-400/25 bg-violet-500/10 px-3.5 py-2.5 text-sm text-violet-100">
                <Icon name="refresh" size={16} className="mt-0.5 shrink-0 text-violet-300" />{baselineNote}
              </p>
            )}
            <div className="inline-flex rounded-full bg-ink-950/80 p-1 text-sm ring-1 ring-white/[.06]" role="tablist">
              {(["github", "zip"] as const).map((t) => (
                <button key={t} role="tab" aria-selected={tab === t} onClick={() => setTab(t)}
                  className={`inline-flex items-center gap-2 rounded-full px-4 py-1.5 font-medium transition ${tab === t ? "bg-white text-ink-950 shadow" : "text-zinc-400 hover:text-white"}`}>
                  <Icon name={t === "github" ? "github" : "upload"} size={15} />
                  {t === "github" ? "Public GitHub repo" : "Upload ZIP"}
                </button>
              ))}
            </div>

            <div className="mt-4">
              {tab === "github" ? (
                <form className="flex flex-col gap-3 sm:flex-row" onSubmit={(e) => { e.preventDefault(); submit(); }}>
                  <label className="relative flex-1">
                    <span className="sr-only">Repository URL</span>
                    <Icon name="github" size={18} className="pointer-events-none absolute left-4 top-1/2 -translate-y-1/2 text-zinc-500" />
                    <input className="input h-12 rounded-full pl-11" placeholder="https://github.com/owner/repo" value={url}
                      onChange={(e) => setUrl(e.target.value)} autoFocus spellCheck={false} autoComplete="off" />
                  </label>
                  <button type="submit" className="btn-primary h-12 px-6" disabled={!ready}>Continue <Icon name="arrow-right" size={16} /></button>
                </form>
              ) : (
                <div className="flex flex-col gap-3">
                  <label
                    onDragOver={(e) => { e.preventDefault(); setDrag(true); }}
                    onDragLeave={() => setDrag(false)}
                    onDrop={(e) => { e.preventDefault(); setDrag(false); const f = e.dataTransfer.files?.[0]; if (f) setFile(f); }}
                    className={`group flex cursor-pointer items-center gap-4 rounded-2xl border border-dashed px-5 py-5 transition ${drag ? "border-lime bg-lime/[.06]" : "border-white/15 bg-ink-950/50 hover:border-violet-400/60"}`}>
                    <input type="file" accept=".zip,application/zip" className="sr-only" onChange={(e) => setFile(e.target.files?.[0] ?? null)} />
                    <span className={`flex h-12 w-12 shrink-0 items-center justify-center rounded-2xl transition ${file ? "bg-lime text-ink-950" : "bg-violet-500/15 text-violet-300 group-hover:bg-violet-500/25"}`}>
                      <Icon name={file ? "check" : "upload"} size={20} strokeWidth={2.2} />
                    </span>
                    <span className="min-w-0">
                      <span className="block truncate text-sm font-medium text-white">{file ? file.name : "Drop a .zip of your repository, or browse"}</span>
                      <span className="mt-0.5 block text-xs text-zinc-500">{file ? `${(file.size / 1024).toFixed(0)} KB · ready to scan` : "Up to 50 MB"}</span>
                    </span>
                  </label>
                  <div className="flex justify-end"><button className="btn-primary h-11 px-6" disabled={!ready} onClick={submit}>Continue <Icon name="arrow-right" size={16} /></button></div>
                </div>
              )}
              {tab === "github" && url && !urlOk && <span className="mt-2 block pl-4 text-xs text-rose-300">Use a public https://github.com/owner/repo URL.</span>}
            </div>

            <div className="mt-5 flex items-center gap-2 overflow-x-auto rounded-xl bg-ink-950/70 px-3 py-2 font-mono text-[11px] text-zinc-500 ring-1 ring-white/[.05]">
              <Icon name="terminal" size={14} className="shrink-0 text-zinc-400" />
              <span className="whitespace-nowrap">Local folder? <span className="text-lime">$</span> <span className="text-zinc-300">privtrace scan ./repo --packs dpdp,security --out report.html</span></span>
            </div>
          </div>

          <ul className="mt-6 flex flex-wrap gap-x-6 gap-y-2 text-xs text-zinc-400">
            {([["lock", "Code deleted after every scan"], ["eye", "Only redacted snippets reach AI"], ["shield", "Never a legal verdict"]] as const).map(([i, t]) => (
              <li key={t} className="flex items-center gap-2"><Icon name={i} size={14} className="text-violet-300" />{t}</li>
            ))}
          </ul>
        </div>
        <HeroVisual />
      </section>
      {!baselineNote && <FeatureBento />}
    </div>
  );
}

// ------------------------------------------------------------------ 2. Packs
export function PacksStep({ selected, onBack, onNext }: {
  selected: string[];
  onBack: () => void;
  onNext: (ids: string[]) => void;
}) {
  const [packs, setPacks] = useState<PackSummary[] | null>(null);
  const [sel, setSel] = useState<Set<string>>(new Set(selected));
  const [err, setErr] = useState<string | null>(null);
  useEffect(() => {
    api.packs().then((p) => {
      setPacks(p);
      if (!selected.length) setSel(new Set(p.filter((x) => ["dpdp-2023", "security-baseline"].includes(x.id)).map((x) => x.id)));
    }).catch((e) => setErr(String(e.message ?? e)));
  }, [selected.length]);

  const toggle = (id: string) => setSel((s) => { const n = new Set(s); n.has(id) ? n.delete(id) : n.add(id); return n; });
  const ruleCount = packs?.filter((p) => sel.has(p.id)).reduce((a, p) => a + p.rule_count, 0) ?? 0;

  return (
    <div>
      <StepHeader n="02" title="Pick your" accent="frameworks"
        sub="Each pack is a set of rules. Automated rules are checked in code; manual ones come from a short checklist." />
      {err && <p className="mb-4 rounded-2xl border border-rose-400/30 bg-rose-500/10 px-4 py-3 text-sm text-rose-200">Could not load packs: {err}</p>}

      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
        {!packs && !err && Array.from({ length: 5 }, (_, i) => (
          <div key={i} className="glass h-56 animate-pulse" />
        ))}
        {packs?.map((p, i) => {
          const on = sel.has(p.id);
          const total = Math.max(1, p.automated + p.hybrid + p.manual);
          return (
            <button key={p.id} onClick={() => toggle(p.id)} aria-pressed={on}
              style={{ animationDelay: `${i * 60}ms` }}
              className={`group relative flex animate-fade-up flex-col overflow-hidden rounded-3xl p-5 text-left transition duration-300 hover:-translate-y-1 ${on
                ? "bg-lime text-ink-950 shadow-lime-glow"
                : "glass text-white hover:border-white/15"}`}>
              <div className="flex items-start justify-between gap-3">
                <div className="min-w-0">
                  <div className={`font-mono text-[10px] font-semibold uppercase tracking-[.16em] ${on ? "text-ink-950/60" : "text-zinc-500"}`}>{p.jurisdiction} · v{p.version}</div>
                  <div className="mt-2 font-display text-3xl font-bold leading-none tracking-tight">{p.short_name}</div>
                </div>
                <span className={`flex h-9 w-9 shrink-0 items-center justify-center rounded-full transition ${on ? "bg-ink-950 text-lime" : "bg-white/[.06] text-zinc-500 ring-1 ring-white/10 group-hover:text-white"}`}>
                  <Icon name={on ? "check" : "plus"} size={16} strokeWidth={2.6} />
                </span>
              </div>
              <div className={`mt-2 text-sm ${on ? "text-ink-950/75" : "text-zinc-400"}`}>{p.name}</div>

              <div className="mt-auto pt-6">
                <div className="flex items-end justify-between">
                  <div><span className="font-display text-4xl font-bold tracking-tight">{p.rule_count}</span> <span className={`text-xs font-medium ${on ? "text-ink-950/60" : "text-zinc-500"}`}>rules</span></div>
                </div>
                <div className={`mt-3 flex h-1.5 overflow-hidden rounded-full ${on ? "bg-ink-950/15" : "bg-white/[.06]"}`}>
                  <span style={{ width: `${(p.automated / total) * 100}%` }} className={on ? "bg-ink-950" : "bg-violet-400"} />
                  <span style={{ width: `${(p.hybrid / total) * 100}%` }} className={on ? "bg-ink-950/50" : "bg-violet-400/50"} />
                  <span style={{ width: `${(p.manual / total) * 100}%` }} className={on ? "bg-ink-950/20" : "bg-white/20"} />
                </div>
                <div className={`mt-2 flex flex-wrap gap-x-3 text-[11px] font-medium ${on ? "text-ink-950/70" : "text-zinc-500"}`}>
                  <span>{p.automated} automated</span><span>{p.hybrid} hybrid</span><span>{p.manual} manual</span>
                </div>
                {p.unverified_references > 0 && (
                  <div className={`mt-3 flex items-center gap-1.5 text-[11px] font-medium ${on ? "text-ink-950/80" : "text-amber-200/80"}`}>
                    <Icon name="alert" size={12} /> {p.unverified_references} legal reference(s) pending human verification
                  </div>
                )}
              </div>
            </button>
          );
        })}
      </div>

      <ActionBar>
        <button className="btn-ghost" onClick={onBack}><Icon name="arrow-left" size={16} /> <span className="hidden sm:inline">Back</span></button>
        <span className="truncate text-center text-xs text-zinc-400 sm:text-sm">
          <b className="text-white">{sel.size}</b> selected{packs && <> · <b className="text-white">{ruleCount}</b> rules</>}
        </span>
        <button className="btn-primary" disabled={!sel.size} onClick={() => onNext([...sel])}>Continue <Icon name="arrow-right" size={16} /></button>
      </ActionBar>
    </div>
  );
}

// ------------------------------------------------------------------ 3. Checklist
const ANSWER_STYLE: Record<Answer, string> = {
  yes: "bg-lime text-ink-950 shadow-[0_0_20px_-6px_rgba(212,255,63,.9)]",
  no: "bg-rose-500 text-white shadow-[0_0_20px_-6px_rgba(244,63,94,.9)]",
  not_sure: "bg-sun text-ink-950",
};

export function ChecklistStep({ packs, answers, aiAvailable, busy = false, onBack, onStart }: {
  packs: string[];
  answers: Record<string, Answer>;
  aiAvailable: boolean;
  busy?: boolean;
  onBack: () => void;
  onStart: (answers: Record<string, Answer>, useAi: boolean) => void;
}) {
  const [items, setItems] = useState<ChecklistItem[] | null>(null);
  const [ans, setAns] = useState<Record<string, Answer>>(answers);
  const [useAi, setUseAi] = useState(aiAvailable);
  useEffect(() => { api.checklist(packs).then(setItems).catch(() => setItems([])); }, [packs]);
  useEffect(() => { setUseAi(aiAvailable); }, [aiAvailable]);

  // One question can appear in several packs; ask it once.
  const unique = items ? Object.values(Object.fromEntries(items.map((i) => [i.rule_id, i]))) : [];
  const groups = unique.reduce<Record<string, ChecklistItem[]>>((g, i) => { (g[i.pack] ??= []).push(i); return g; }, {});
  const answered = unique.filter((i) => ans[i.rule_id]).length;
  const pct = unique.length ? (answered / unique.length) * 100 : 0;

  return (
    <div>
      <StepHeader n="03" title="Things code" accent="can’t show"
        sub="Answer what you can. “Not sure” and unanswered questions are listed as needs review and left out of the score."
        right={items && unique.length > 0 ? (
          <div className="glass-tile min-w-[200px] px-4 py-3">
            <div className="flex items-baseline justify-between text-xs text-zinc-400"><span>Answered</span><span className="font-mono text-white">{answered}/{unique.length}</span></div>
            <div className="mt-2 h-1.5 overflow-hidden rounded-full bg-white/[.06]">
              <div className="h-full rounded-full bg-gradient-to-r from-violet-400 to-lime transition-all duration-500" style={{ width: `${pct}%` }} />
            </div>
          </div>
        ) : undefined} />

      {!items && <div className="glass flex items-center gap-3 p-6 text-sm text-zinc-400"><Spinner /> Loading checklist…</div>}
      {items && !unique.length && <div className="glass p-6 text-sm text-zinc-400">No manual questions for these frameworks — you can run the scan straight away.</div>}

      <div className="space-y-6">
        {Object.entries(groups).map(([pack, qs]) => (
          <section key={pack} className="glass overflow-hidden">
            <div className="flex items-center justify-between border-b border-white/[.06] px-5 py-3.5">
              <h3 className="flex items-center gap-2 text-sm font-semibold text-white"><span className="h-2 w-2 rounded-full bg-violet-400 shadow-[0_0_10px_2px_rgba(167,139,250,.7)]" />{pack}</h3>
              <span className="font-mono text-[11px] text-zinc-500">{qs.filter((q) => ans[q.rule_id]).length}/{qs.length}</span>
            </div>
            <div className="divide-y divide-white/[.05]">
              {qs.map((q) => (
                <div key={q.rule_id} className="flex flex-col gap-3 px-5 py-4 transition hover:bg-white/[.02] md:flex-row md:items-center md:justify-between">
                  <div className="md:pr-6">
                    <div className="text-sm leading-relaxed text-zinc-100">{q.question}</div>
                    <div className="mt-2 flex flex-wrap items-center gap-2 text-xs text-zinc-500">
                      <SeverityBadge s={q.severity} /> <code className="text-zinc-400">{q.rule_id}</code>
                      {q.check_type === "hybrid" && <span className="inline-flex items-center gap-1 text-violet-300/80"><Icon name="scan" size={12} /> code evidence is checked too</span>}
                    </div>
                  </div>
                  <div className="inline-flex shrink-0 self-start rounded-full bg-ink-950/80 p-1 text-sm ring-1 ring-white/[.07] md:self-auto" role="radiogroup" aria-label={q.question}>
                    {(["yes", "no", "not_sure"] as Answer[]).map((a) => (
                      <button key={a} role="radio" aria-checked={ans[q.rule_id] === a} onClick={() => setAns((s) => ({ ...s, [q.rule_id]: a }))}
                        className={`rounded-full px-4 py-1.5 font-semibold transition ${ans[q.rule_id] === a ? ANSWER_STYLE[a] : "text-zinc-400 hover:text-white"}`}>
                        {a === "not_sure" ? "Not sure" : a[0].toUpperCase() + a.slice(1)}
                      </button>
                    ))}
                  </div>
                </div>
              ))}
            </div>
          </section>
        ))}
      </div>

      <label className={`mt-6 flex cursor-pointer items-center gap-4 rounded-3xl border p-5 transition ${aiAvailable
        ? useAi ? "border-violet-400/40 bg-gradient-to-r from-violet-600/20 via-violet-500/10 to-transparent shadow-glow" : "border-white/[.08] bg-white/[.03]"
        : "cursor-not-allowed border-white/[.06] bg-white/[.02] opacity-70"}`}>
        <span className={`flex h-11 w-11 shrink-0 items-center justify-center rounded-2xl ${useAi && aiAvailable ? "bg-violet-500 text-white" : "bg-white/[.06] text-zinc-400"}`}><Icon name="sparkle" size={20} /></span>
        <span className="flex-1 text-sm">
          <b className="text-white">Plain-language explanations with Gemini</b>
          <span className="mt-0.5 block text-xs text-zinc-400">
            {aiAvailable
              ? "Only small, redacted snippets (≤ 40 lines, identifiers masked) are sent. AI never changes a pass/fail result."
              : "Not configured on this server (set GEMINI_API_KEY and GEMINI_MODEL). The scan works fully without it."}
          </span>
        </span>
        <input type="checkbox" className="peer sr-only" checked={useAi && aiAvailable} disabled={!aiAvailable} onChange={(e) => setUseAi(e.target.checked)} />
        <span aria-hidden="true" className={`relative h-7 w-12 shrink-0 rounded-full transition peer-focus-visible:ring-2 peer-focus-visible:ring-lime ${useAi && aiAvailable ? "bg-violet-500" : "bg-white/10"}`}>
          <span className={`absolute top-1 h-5 w-5 rounded-full bg-white shadow transition-all ${useAi && aiAvailable ? "left-6" : "left-1"}`} />
        </span>
      </label>

      <ActionBar>
        <button className="btn-ghost" onClick={onBack}><Icon name="arrow-left" size={16} /> <span className="hidden sm:inline">Back</span></button>
        <span className="hidden text-sm text-zinc-400 sm:inline">{packs.length} framework{packs.length === 1 ? "" : "s"} · {answered} answered</span>
        <button className="btn-primary" disabled={!items || busy} onClick={() => onStart(ans, useAi && aiAvailable)}>
          {busy ? <Spinner className="border-ink-950/30 border-t-ink-950" /> : <Icon name="scan" size={16} />} Run scan
        </button>
      </ActionBar>
    </div>
  );
}

// ------------------------------------------------------------------ 4. Progress
const STAGES = [
  ["queued", "Queued", "Waiting for a worker"],
  ["fetching", "Fetching code", "Copying into a temporary sandbox"],
  ["analyzing", "Tracing personal data", "Parsing ASTs, following taint into sinks"],
  ["evaluating", "Running compliance rules", "Checking every selected pack"],
  ["explaining", "Writing AI explanations", "Redacted snippets only"],
  ["done", "Building report", "Scoring and assembling evidence"],
] as const;

function Scanner() {
  return (
    <div aria-hidden="true" className="relative mx-auto h-56 w-56 sm:h-64 sm:w-64">
      <div className="absolute inset-0 rounded-full border border-white/10" />
      <div className="absolute inset-[16%] rounded-full border border-white/[.07]" />
      <div className="absolute inset-[32%] rounded-full border border-white/[.05]" />
      <div className="absolute inset-0 animate-spin-slow rounded-full [animation-duration:3s]"
        style={{ background: "conic-gradient(from 0deg, transparent 0deg, rgba(167,139,250,0) 250deg, rgba(167,139,250,.45) 340deg, rgba(212,255,63,.9) 360deg)", maskImage: "radial-gradient(circle, black 69%, transparent 70%)", WebkitMaskImage: "radial-gradient(circle, black 69%, transparent 70%)" }} />
      <div className="orb absolute inset-[36%] animate-float rounded-full" />
      {[[18, 30], [70, 22], [78, 64], [28, 74], [52, 12]].map(([x, y], i) => (
        <span key={i} className="absolute h-1.5 w-1.5 rounded-full bg-lime" style={{ left: `${x}%`, top: `${y}%` }}>
          <span className="absolute inset-0 animate-pulse-ring rounded-full bg-lime" style={{ animationDelay: `${i * 0.35}s` }} />
        </span>
      ))}
    </div>
  );
}

export function ProgressStep({ scanId, onDone, onError }: {
  scanId: string;
  onDone: (s: ScanStatus) => void;
  onError: (msg: string) => void;
}) {
  const [st, setSt] = useState<ScanStatus | null>(null);
  const [elapsed, setElapsed] = useState(0);
  const done = useRef(false);
  useEffect(() => {
    done.current = false;
    const t = setInterval(async () => {
      if (done.current) return;
      try {
        const s = await api.scan(scanId);
        setSt(s);
        if (s.status === "done") { done.current = true; onDone(s); }
        if (s.status === "error") { done.current = true; onError(s.message); }
      } catch (e) {
        done.current = true;
        onError(String((e as Error).message ?? e));
      }
    }, 800);
    return () => clearInterval(t);
  }, [scanId, onDone, onError]);
  useEffect(() => {
    const t0 = Date.now();
    const t = setInterval(() => setElapsed((Date.now() - t0) / 1000), 100);
    return () => clearInterval(t);
  }, [scanId]);

  const idx = STAGES.findIndex(([k]) => k === (st?.stage ?? "queued"));
  const visible = STAGES.filter(([k]) => k !== "explaining" || st?.stage === "explaining");

  return (
    <div className="glass relative overflow-hidden p-6 sm:p-10">
      <div className="dot-grid absolute inset-0 opacity-60 [mask-image:radial-gradient(ellipse_at_center,black,transparent_75%)]" aria-hidden="true" />
      <div className="absolute inset-x-0 top-0 h-px shimmer-line" aria-hidden="true" />
      <div className="relative grid items-center gap-10 md:grid-cols-[1fr_1.1fr]">
        <div className="text-center md:text-left">
          <Scanner />
          <div className="mt-8 md:pl-2">
            <span className="kicker">Step 04 · Scan {scanId}</span>
            <h2 className="mt-2 font-display text-4xl font-semibold tracking-tight text-white">Scanning<span className="animate-pulse">…</span></h2>
            <p className="mt-2 truncate font-mono text-xs text-zinc-400" title={st?.source_ref}>{st?.source_ref ?? "Preparing"}</p>
            <p className="mt-4 font-mono text-3xl font-medium tabular-nums text-lime">{elapsed.toFixed(1)}<span className="text-base text-zinc-500">s</span></p>
          </div>
        </div>

        <ol className="relative space-y-3" aria-live="polite">
          {visible.map(([k, label, hint], vi) => {
            const i = STAGES.findIndex(([x]) => x === k);
            const state = i < idx ? "done" : i === idx ? "active" : "todo";
            return (
              <li key={k} className="relative">
                {vi < visible.length - 1 && (
                  <span aria-hidden="true" className={`absolute left-[27px] top-12 h-[calc(100%-24px)] w-px ${state === "done" ? "bg-gradient-to-b from-lime to-lime/30" : "bg-white/10"}`} />
                )}
                <div className={`relative flex items-center gap-4 rounded-2xl border px-3 py-3 transition duration-500 ${state === "active"
                  ? "border-violet-400/40 bg-gradient-to-r from-violet-500/20 to-violet-500/[.03] shadow-glow"
                  : state === "done" ? "border-white/[.06] bg-white/[.03]" : "border-white/[.04] bg-transparent"}`}>
                  <span className="relative flex h-8 w-8 shrink-0 items-center justify-center">
                    {state === "active" && <span className="absolute inset-0 animate-pulse-ring rounded-full bg-violet-400/60" />}
                    <span className={`relative flex h-8 w-8 items-center justify-center rounded-full ${state === "done" ? "bg-lime text-ink-950" : state === "active" ? "bg-violet-500 text-white" : "bg-white/[.05] text-zinc-600 ring-1 ring-white/10"}`}>
                      {state === "done" ? <Icon name="check" size={15} strokeWidth={3} /> : state === "active" ? <Spinner className="h-3.5 w-3.5 border-white/30 border-t-white" /> : <span className="text-[11px] font-bold">{vi + 1}</span>}
                    </span>
                  </span>
                  <div className="min-w-0">
                    <div className={`text-sm font-semibold ${state === "todo" ? "text-zinc-500" : "text-white"}`}>{label}</div>
                    <div className={`truncate text-xs ${state === "active" ? "text-violet-200/80" : "text-zinc-600"}`}>{state === "active" && st?.message ? st.message : hint}</div>
                  </div>
                </div>
              </li>
            );
          })}
        </ol>
      </div>
    </div>
  );
}
