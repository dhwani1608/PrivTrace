import { useCallback, useEffect, useState } from "react";
import { api } from "./api";
import Report from "./components/Report";
import { ChecklistStep, ConnectStep, PacksStep, ProgressStep, type Source } from "./components/Steps";
import { Icon } from "./components/ui";
import type { Answer, ScanResult, ScanStatus } from "./types";

type Step = "connect" | "packs" | "checklist" | "progress" | "report";
const STEPS: [Step, string][] = [["connect", "Connect"], ["packs", "Frameworks"], ["checklist", "Checklist"], ["progress", "Scan"], ["report", "Report"]];

function Logo() {
  return (
    <div className="flex items-center gap-2.5">
      <img src="/privtrace-icon.svg" alt="" className="h-9 w-9 rounded-xl shadow-glow" />
      <img src="/privtrace-wordmark.svg" alt="PrivTrace" className="h-6 w-auto" />
    </div>
  );
}

function Backdrop() {
  return (
    <div aria-hidden="true" className="pointer-events-none fixed inset-0 z-0 overflow-hidden">
      <div className="dot-grid absolute inset-0 [mask-image:radial-gradient(ellipse_at_top,black_30%,transparent_75%)]" />
      <div className="absolute -left-[10%] -top-[20%] h-[60vw] w-[60vw] animate-aurora rounded-full bg-violet-600/25 blur-[120px]" />
      <div className="absolute -right-[15%] top-[10%] h-[45vw] w-[45vw] animate-aurora rounded-full bg-fuchsia-700/15 blur-[140px] [animation-delay:-8s]" />
      <div className="absolute bottom-[-25%] left-[25%] h-[40vw] w-[40vw] animate-aurora rounded-full bg-lime/[.07] blur-[140px] [animation-delay:-14s]" />
    </div>
  );
}

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
  const [apiUp, setApiUp] = useState<boolean | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    api.health()
      .then((h) => { setAiAvailable(h.ai_configured); setApiUp(true); })
      .catch(() => { setApiUp(false); setError("Cannot reach the PrivTrace API."); });
  }, []);

  useEffect(() => { window.scrollTo({ top: 0, behavior: "smooth" }); }, [step]);

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

  const reset = () => { setStep("connect"); setSource(null); setResult(null); setScanId(null); setBaselineId(null); setAnswers({}); setError(null); };
  const idx = STEPS.findIndex(([k]) => k === step);

  return (
    <div className="noise relative min-h-screen">
      <Backdrop />

      <header className="sticky top-0 z-40 px-4 pt-4">
        <nav className="mx-auto flex max-w-6xl items-center justify-between gap-3 rounded-full border border-white/[.08] bg-ink-900/70 py-2 pl-4 pr-2 shadow-lift backdrop-blur-xl">
          <button onClick={reset} className="shrink-0 rounded-full" aria-label="PrivTrace home — start a new scan"><Logo /></button>

          <ol className="hidden items-center gap-1 md:flex" aria-label="Scan steps">
            {STEPS.map(([k, label], i) => {
              const state = i < idx ? "done" : i === idx ? "active" : "todo";
              return (
                <li key={k} aria-current={state === "active" ? "step" : undefined}
                  className={`relative flex items-center gap-2 rounded-full px-3.5 py-1.5 text-[13px] font-medium transition ${state === "active" ? "bg-white/[.08] text-white" : state === "done" ? "text-zinc-300" : "text-zinc-500"}`}>
                  <span className={`flex h-5 w-5 items-center justify-center rounded-full text-[10px] font-bold ${state === "done" ? "bg-lime text-ink-950" : state === "active" ? "bg-violet-500 text-white shadow-glow" : "bg-white/[.06] text-zinc-500"}`}>
                    {state === "done" ? <Icon name="check" size={12} strokeWidth={3} /> : i + 1}
                  </span>
                  {label}
                  {state === "active" && <span className="absolute -bottom-[9px] left-1/2 h-[2px] w-8 -translate-x-1/2 rounded-full bg-violet-400 shadow-[0_0_12px_2px_rgba(167,139,250,.8)]" />}
                </li>
              );
            })}
          </ol>

          <div className="flex shrink-0 items-center gap-2">
            <span className="md:hidden rounded-full bg-white/[.06] px-3 py-1 font-mono text-[11px] text-zinc-300">{idx + 1}/{STEPS.length} · {STEPS[idx][1]}</span>
            <span className={`hidden items-center gap-2 rounded-full px-3 py-1.5 text-xs font-medium sm:inline-flex ${aiAvailable ? "bg-violet-500/15 text-violet-200 ring-1 ring-violet-400/30" : "bg-white/[.04] text-zinc-400 ring-1 ring-white/10"}`}>
              <span className="relative flex h-2 w-2">
                {apiUp && <span className={`absolute inline-flex h-full w-full animate-ping rounded-full opacity-60 ${aiAvailable ? "bg-violet-400" : "bg-lime"}`} />}
                <span className={`relative inline-flex h-2 w-2 rounded-full ${apiUp === false ? "bg-rose-500" : aiAvailable ? "bg-violet-400" : "bg-lime"}`} />
              </span>
              {apiUp === false ? "API offline" : aiAvailable ? "Gemini on" : "Engine ready"}
            </span>
          </div>
        </nav>
      </header>

      <main className="relative z-10 mx-auto max-w-6xl px-4 pb-16 pt-8 sm:pt-12">
        {error && (
          <div role="alert" className="mb-6 flex animate-fade-up items-start gap-3 rounded-2xl border border-rose-400/30 bg-rose-500/10 px-4 py-3 text-sm text-rose-200 backdrop-blur">
            <Icon name="alert" className="mt-0.5 shrink-0 text-rose-400" />
            <span className="flex-1">{error}</span>
            <button onClick={() => setError(null)} className="text-rose-300/70 hover:text-rose-200" aria-label="Dismiss error">✕</button>
          </div>
        )}

        <div key={step} className="animate-fade-up">
          {step === "connect" && (
            <ConnectStep initial={source}
              baselineNote={baselineId ? `Upload the fixed version — the report will show what changed since scan ${baselineId}.` : undefined}
              onNext={(s) => { setSource(s); setStep("packs"); }} />
          )}
          {step === "packs" && <PacksStep selected={packs} onBack={() => setStep("connect")} onNext={(p) => { setPacks(p); setStep("checklist"); }} />}
          {step === "checklist" && (
            <div className={busy ? "pointer-events-none opacity-60" : ""}>
              <ChecklistStep packs={packs} answers={answers} aiAvailable={aiAvailable} busy={busy} onBack={() => setStep("packs")} onStart={start} />
            </div>
          )}
          {step === "progress" && scanId && <ProgressStep scanId={scanId} onDone={onDone} onError={onError} />}
          {step === "report" && result && (
            <Report result={result} canRescan={source?.kind === "github"} onRescan={rescan}
              onUploadFixed={() => { setBaselineId(result.scan_id); setSource(null); setStep("connect"); }} onNew={reset} />
          )}
        </div>
      </main>

      <footer className="relative z-10 border-t border-white/[.05] px-4 py-8">
        <div className="mx-auto flex max-w-6xl flex-wrap items-center justify-between gap-3 text-xs text-zinc-500">
          <span className="font-mono">© PrivTrace · DPDP · IT Act · CERT-In · GDPR</span>
          <span>Findings are engineering evidence, not legal advice.</span>
        </div>
      </footer>
    </div>
  );
}
