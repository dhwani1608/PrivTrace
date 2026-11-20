import { useEffect, useRef, useState } from "react";
import { api } from "../api";
import type { Answer, ChecklistItem, PackSummary, ScanStatus } from "../types";
import { SeverityBadge, Spinner } from "./ui";

export type Source = { kind: "github"; url: string } | { kind: "zip"; file: File };

// ------------------------------------------------------------------ 1. Connect
export function ConnectStep({ initial, baselineNote, onNext }: {
  initial: Source | null;
  baselineNote?: string;
  onNext: (s: Source) => void;
}) {
  const [tab, setTab] = useState<"github" | "zip">(initial?.kind ?? "github");
  const [url, setUrl] = useState(initial?.kind === "github" ? initial.url : "");
  const [file, setFile] = useState<File | null>(initial?.kind === "zip" ? initial.file : null);
  const urlOk = /^https:\/\/github\.com\/[\w.-]+\/[\w.-]+?(\.git)?\/?$/.test(url.trim());
  const ready = tab === "github" ? urlOk : !!file;

  return (
    <div className="card p-6">
      <h2 className="text-lg font-semibold">Connect your code</h2>
      <p className="mt-1 text-sm text-slate-500">Code is copied to a temporary folder, scanned, and deleted when the scan finishes.</p>
      {baselineNote && <p className="mt-3 rounded-lg bg-indigo-50 px-3 py-2 text-sm text-indigo-800">{baselineNote}</p>}
      <div className="mt-5 inline-flex rounded-lg bg-slate-100 p-1 text-sm">
        {(["github", "zip"] as const).map((t) => (
          <button key={t} onClick={() => setTab(t)}
            className={`rounded-md px-4 py-1.5 font-medium ${tab === t ? "bg-white shadow-sm" : "text-slate-500"}`}>
            {t === "github" ? "Public GitHub repo" : "Upload ZIP"}
          </button>
        ))}
      </div>
      <div className="mt-4">
        {tab === "github" ? (
          <label className="block">
            <span className="text-sm font-medium">Repository URL</span>
            <input className="input mt-1" placeholder="https://github.com/owner/repo" value={url} onChange={(e) => setUrl(e.target.value)} />
            {url && !urlOk && <span className="mt-1 block text-xs text-red-600">Use a public https://github.com/owner/repo URL.</span>}
          </label>
        ) : (
          <label className="flex cursor-pointer flex-col items-center justify-center rounded-xl border-2 border-dashed border-slate-300 bg-slate-50 px-6 py-10 text-center hover:border-indigo-400">
            <input type="file" accept=".zip,application/zip" className="hidden" onChange={(e) => setFile(e.target.files?.[0] ?? null)} />
            <span className="text-sm font-medium">{file ? file.name : "Choose a .zip of your repository"}</span>
            <span className="mt-1 text-xs text-slate-500">{file ? `${(file.size / 1024).toFixed(0)} KB` : "Up to 50 MB"}</span>
          </label>
        )}
      </div>
      <p className="mt-4 text-xs text-slate-500">
        Scanning a local folder? Use the CLI: <code className="rounded bg-slate-100 px-1">privtrace scan ./repo --packs dpdp,security --out report.html</code>
      </p>
      <div className="mt-6 flex justify-end">
        <button className="btn-primary" disabled={!ready}
          onClick={() => onNext(tab === "github" ? { kind: "github", url: url.trim() } : { kind: "zip", file: file! })}>
          Continue
        </button>
      </div>
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

  return (
    <div className="card p-6">
      <h2 className="text-lg font-semibold">Pick compliance frameworks</h2>
      <p className="mt-1 text-sm text-slate-500">Each pack is a set of rules. Automated rules are checked in code; manual ones come from a short checklist.</p>
      {err && <p className="mt-4 text-sm text-red-600">Could not load packs: {err}</p>}
      {!packs && !err && <p className="mt-6 flex items-center gap-2 text-sm text-slate-500"><Spinner /> Loading packs…</p>}
      <div className="mt-5 grid gap-3 sm:grid-cols-2">
        {packs?.map((p) => {
          const on = sel.has(p.id);
          return (
            <button key={p.id} onClick={() => toggle(p.id)}
              className={`rounded-xl border p-4 text-left transition ${on ? "border-indigo-500 bg-indigo-50/60 ring-2 ring-indigo-200" : "border-slate-200 bg-white hover:border-slate-300"}`}>
              <div className="flex items-start justify-between gap-3">
                <div>
                  <div className="font-semibold">{p.short_name}</div>
                  <div className="text-sm text-slate-600">{p.name}</div>
                </div>
                <span className={`mt-0.5 h-5 w-5 shrink-0 rounded-md border-2 ${on ? "border-indigo-600 bg-indigo-600" : "border-slate-300"}`}>
                  {on && <svg viewBox="0 0 20 20" fill="white"><path d="M8 13.5 4.5 10l-1.4 1.4L8 16.3l9-9-1.4-1.4z" /></svg>}
                </span>
              </div>
              <div className="mt-3 flex flex-wrap gap-2 text-xs text-slate-500">
                <span className="badge bg-slate-100 text-slate-700">{p.jurisdiction}</span>
                <span className="badge bg-slate-100 text-slate-700">v{p.version}</span>
                <span>{p.automated} automated · {p.hybrid} hybrid · {p.manual} manual</span>
              </div>
              {p.unverified_references > 0 && (
                <div className="mt-2 text-xs text-amber-700">{p.unverified_references} legal reference(s) pending human verification</div>
              )}
            </button>
          );
        })}
      </div>
      <div className="mt-6 flex justify-between">
        <button className="btn-ghost" onClick={onBack}>Back</button>
        <button className="btn-primary" disabled={!sel.size} onClick={() => onNext([...sel])}>Continue</button>
      </div>
    </div>
  );
}

// ------------------------------------------------------------------ 3. Checklist
export function ChecklistStep({ packs, answers, aiAvailable, onBack, onStart }: {
  packs: string[];
  answers: Record<string, Answer>;
  aiAvailable: boolean;
  onBack: () => void;
  onStart: (answers: Record<string, Answer>, useAi: boolean) => void;
}) {
  const [items, setItems] = useState<ChecklistItem[] | null>(null);
  const [ans, setAns] = useState<Record<string, Answer>>(answers);
  const [useAi, setUseAi] = useState(aiAvailable);
  useEffect(() => { api.checklist(packs).then(setItems).catch(() => setItems([])); }, [packs]);

  // One question can appear in several packs; ask it once.
  const unique = items ? Object.values(Object.fromEntries(items.map((i) => [i.rule_id, i]))) : [];
  const groups = unique.reduce<Record<string, ChecklistItem[]>>((g, i) => { (g[i.pack] ??= []).push(i); return g; }, {});
  const answered = unique.filter((i) => ans[i.rule_id]).length;

  return (
    <div className="card p-6">
      <div className="flex flex-wrap items-baseline justify-between gap-2">
        <h2 className="text-lg font-semibold">Things code can’t show</h2>
        {items && <span className="text-sm text-slate-500">{answered} of {unique.length} answered</span>}
      </div>
      <p className="mt-1 text-sm text-slate-500">
        Answer what you can. “Not sure” and unanswered questions are listed as <i>needs review</i> and left out of the score.
      </p>
      {!items && <p className="mt-6 flex items-center gap-2 text-sm text-slate-500"><Spinner /> Loading checklist…</p>}
      {Object.entries(groups).map(([pack, qs]) => (
        <div key={pack} className="mt-6">
          <h3 className="mb-2 text-sm font-semibold uppercase tracking-wide text-slate-500">{pack}</h3>
          <div className="divide-y divide-slate-100 rounded-xl border border-slate-200">
            {qs.map((q) => (
              <div key={q.rule_id} className="flex flex-col gap-3 p-4 md:flex-row md:items-center md:justify-between">
                <div className="md:pr-6">
                  <div className="text-sm">{q.question}</div>
                  <div className="mt-1 flex flex-wrap items-center gap-2 text-xs text-slate-500">
                    <SeverityBadge s={q.severity} /> <code>{q.rule_id}</code>
                    {q.check_type === "hybrid" && <span>· code evidence is checked too</span>}
                  </div>
                </div>
                <div className="inline-flex shrink-0 rounded-lg border border-slate-200 p-0.5 text-sm">
                  {(["yes", "no", "not_sure"] as Answer[]).map((a) => (
                    <button key={a} onClick={() => setAns((s) => ({ ...s, [q.rule_id]: a }))}
                      className={`rounded-md px-3 py-1 font-medium ${ans[q.rule_id] === a
                        ? a === "yes" ? "bg-green-600 text-white" : a === "no" ? "bg-red-600 text-white" : "bg-amber-500 text-white"
                        : "text-slate-600 hover:bg-slate-50"}`}>
                      {a === "not_sure" ? "Not sure" : a[0].toUpperCase() + a.slice(1)}
                    </button>
                  ))}
                </div>
              </div>
            ))}
          </div>
        </div>
      ))}
      <label className={`mt-6 flex items-start gap-3 rounded-xl border p-4 text-sm ${aiAvailable ? "border-violet-200 bg-violet-50/50" : "border-slate-200 bg-slate-50 text-slate-500"}`}>
        <input type="checkbox" className="mt-0.5" checked={useAi} disabled={!aiAvailable} onChange={(e) => setUseAi(e.target.checked)} />
        <span>
          <b>Plain-language explanations with Gemini</b>
          <span className="block text-xs">
            {aiAvailable
              ? "Only small, redacted snippets (≤ 40 lines, identifiers masked) are sent. AI never changes a pass/fail result."
              : "Not configured on this server (set GEMINI_API_KEY and GEMINI_MODEL). The scan works fully without it."}
          </span>
        </span>
      </label>
      <div className="mt-6 flex justify-between">
        <button className="btn-ghost" onClick={onBack}>Back</button>
        <button className="btn-primary" disabled={!items} onClick={() => onStart(ans, useAi && aiAvailable)}>Run scan</button>
      </div>
    </div>
  );
}

// ------------------------------------------------------------------ 4. Progress
const STAGES = [
  ["queued", "Queued"],
  ["fetching", "Fetching code"],
  ["analyzing", "Parsing code and tracing personal data"],
  ["evaluating", "Running compliance rules"],
  ["explaining", "Writing AI explanations"],
  ["done", "Building report"],
] as const;

export function ProgressStep({ scanId, onDone, onError }: {
  scanId: string;
  onDone: (s: ScanStatus) => void;
  onError: (msg: string) => void;
}) {
  const [st, setSt] = useState<ScanStatus | null>(null);
  const done = useRef(false);
  useEffect(() => {
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

  const idx = STAGES.findIndex(([k]) => k === (st?.stage ?? "queued"));
  return (
    <div className="card p-6">
      <h2 className="text-lg font-semibold">Scanning…</h2>
      <p className="mt-1 text-sm text-slate-500">{st?.source_ref}</p>
      <ol className="mt-6 space-y-3">
        {STAGES.filter(([k]) => k !== "explaining" || st?.stage === "explaining").map(([k, label]) => {
          const i = STAGES.findIndex(([x]) => x === k);
          const state = i < idx ? "done" : i === idx ? "active" : "todo";
          return (
            <li key={k} className="flex items-center gap-3 text-sm">
              {state === "done" ? <span className="flex h-5 w-5 items-center justify-center rounded-full bg-green-600 text-xs text-white">✓</span>
                : state === "active" ? <Spinner /> : <span className="h-5 w-5 rounded-full border-2 border-slate-200" />}
              <span className={state === "todo" ? "text-slate-400" : ""}>{label}</span>
            </li>
          );
        })}
      </ol>
    </div>
  );
}
