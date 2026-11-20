import { useCallback, useEffect, useState } from "react";
import { api } from "./api";
import Report from "./components/Report";
import { ChecklistStep, ConnectStep, PacksStep, ProgressStep, type Source } from "./components/Steps";
import type { Answer, ScanResult, ScanStatus } from "./types";

type Step = "connect" | "packs" | "checklist" | "progress" | "report";
const STEPS: [Step, string][] = [["connect", "Connect"], ["packs", "Frameworks"], ["checklist", "Checklist"], ["progress", "Scan"], ["report", "Report"]];

export default function App() {
  const [step, setStep] = useState<Step>("connect");
  const [source, setSource] = useState<Source | null>(null);
  const [packs, setPacks] = useState<string[]>([]);
  const [answers, setAnswers] = useState<Record<string, Answer>>({});
  const [scanId, setScanId] = useState<string | null>(null);
  const [baselineId, setBaselineId] = useState<string | null>(null);
  const [result, setResult] = useState<ScanResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [aiAvailable, setAiAvailable] = useState(false);
  const [busy, setBusy] = useState(false);

  useEffect(() => { api.health().then((h) => setAiAvailable(h.ai_configured)).catch(() => setError("Cannot reach the PrivTrace API.")); }, []);

  const start = async (ans: Record<string, Answer>, useAi: boolean) => {
    if (!source) return;
    setAnswers(ans);
    setError(null);
    setBusy(true);
    try {
      const st = await api.startScan({
        packs, answers: ans, useAi,
        githubUrl: source.kind === "github" ? source.url : undefined,
        file: source.kind === "zip" ? source.file : undefined,
        baselineId: baselineId ?? undefined,
      });
      setScanId(st.scan_id);
      setStep("progress");
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  };

  const onDone = useCallback(async (s: ScanStatus) => {
    try {
      setResult(await api.report(s.scan_id));
      setStep("report");
      window.scrollTo({ top: 0 });
    } catch (e) {
      setError((e as Error).message);
    }
  }, []);
  const onError = useCallback((msg: string) => { setError(msg); setStep("checklist"); }, []);

  const rescan = async () => {
    if (!result) return;
    setError(null);
    try {
      const st = await api.rescan(result.scan_id);
      setScanId(st.scan_id);
      setStep("progress");
    } catch (e) {
      setError((e as Error).message);
    }
  };

  const reset = () => { setStep("connect"); setSource(null); setResult(null); setScanId(null); setBaselineId(null); setAnswers({}); };
  const idx = STEPS.findIndex(([k]) => k === step);

  return (
    <div className="min-h-screen">
      <header className="border-b border-slate-200 bg-white">
        <div className="mx-auto flex max-w-5xl items-center justify-between px-4 py-3">
          <div className="flex items-center gap-2">
            <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-indigo-600 font-bold text-white">P</div>
            <div>
              <div className="font-semibold leading-tight">PrivTrace</div>
              <div className="text-xs text-slate-500">Compliance exposure scanner · DPDP · IT Act · CERT-In · GDPR</div>
            </div>
          </div>
          {aiAvailable && <span className="badge bg-violet-100 text-violet-800">Gemini on</span>}
        </div>
      </header>

      <main className="mx-auto max-w-5xl px-4 py-8">
        {step !== "report" && (
          <ol className="mb-6 flex flex-wrap items-center gap-2 text-sm">
            {STEPS.map(([k, label], i) => (
              <li key={k} className="flex items-center gap-2">
                <span className={`flex h-6 w-6 items-center justify-center rounded-full text-xs font-bold ${i < idx ? "bg-indigo-600 text-white" : i === idx ? "bg-indigo-100 text-indigo-700 ring-2 ring-indigo-600" : "bg-slate-200 text-slate-500"}`}>{i + 1}</span>
                <span className={i === idx ? "font-semibold" : "text-slate-500"}>{label}</span>
                {i < STEPS.length - 1 && <span className="mx-1 text-slate-300">—</span>}
              </li>
            ))}
          </ol>
        )}

        {error && <div className="mb-4 rounded-xl border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-800">{error}</div>}

        {step === "connect" && (
          <ConnectStep initial={source}
            baselineNote={baselineId ? `Upload the fixed version — the report will show what changed since scan ${baselineId}.` : undefined}
            onNext={(s) => { setSource(s); setStep("packs"); }} />
        )}
        {step === "packs" && <PacksStep selected={packs} onBack={() => setStep("connect")} onNext={(p) => { setPacks(p); setStep("checklist"); }} />}
        {step === "checklist" && (
          <div className={busy ? "pointer-events-none opacity-60" : ""}>
            <ChecklistStep packs={packs} answers={answers} aiAvailable={aiAvailable} onBack={() => setStep("packs")} onStart={start} />
          </div>
        )}
        {step === "progress" && scanId && <ProgressStep scanId={scanId} onDone={onDone} onError={onError} />}
        {step === "report" && result && (
          <Report result={result} canRescan={source?.kind === "github"} onRescan={rescan}
            onUploadFixed={() => { setBaselineId(result.scan_id); setSource(null); setStep("connect"); }} onNew={reset} />
        )}
      </main>
      <footer className="pb-8 text-center text-xs text-slate-400">Findings are engineering evidence, not legal advice.</footer>
    </div>
  );
}
