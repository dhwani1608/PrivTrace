import { useCallback, useEffect, useState } from "react";
import { api } from "./api";
import Report from "./components/Report";
import { ChecklistStep, ConnectStep, PacksStep, ProgressStep, type Source } from "./components/Steps";
import type { Answer, ScanResult, ScanStatus } from "./types";

type Step = "connect" | "packs" | "checklist" | "progress" | "report";
const STEPS: [Step, string][] = [
  ["connect", "Connect"],
  ["packs", "Frameworks"],
  ["checklist", "Checklist"],
  ["progress", "Scan"],
  ["report", "Report"],
];

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

  useEffect(() => {
    api.health()
      .then((h) => setAiAvailable(h.ai_configured))
      .catch(() => setError("Cannot reach the PrivTrace API."));
  }, []);

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

  const onError = useCallback((msg: string) => {
    setError(msg);
    setStep("checklist");
  }, []);

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

  const reset = () => {
    setStep("connect");
    setSource(null);
    setResult(null);
    setScanId(null);
    setBaselineId(null);
    setAnswers({});
  };

  const idx = STEPS.findIndex(([k]) => k === step);

  return (
    <div style={{ minHeight: "100vh", background: "var(--base)" }}>
      {/* Header */}
      <header style={{
        borderBottom: "1px solid var(--border)",
        background: "var(--surface)",
        position: "sticky",
        top: 0,
        zIndex: 50,
      }}>
        <div style={{
          maxWidth: 960,
          margin: "0 auto",
          padding: "0 24px",
          height: 56,
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
        }}>
          {/* Logo */}
          <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
            <svg width="28" height="28" viewBox="0 0 28 28" fill="none">
              <rect width="28" height="28" rx="6" fill="var(--teal)" fillOpacity="0.12" />
              <path d="M8 14 L14 8 L20 14 L14 20 Z" stroke="var(--teal)" strokeWidth="1.5" fill="none" />
              <circle cx="14" cy="14" r="2.5" fill="var(--teal)" />
              <path d="M14 8 L14 5" stroke="var(--teal)" strokeWidth="1.5" strokeOpacity="0.5" />
              <path d="M20 14 L23 14" stroke="var(--teal)" strokeWidth="1.5" strokeOpacity="0.5" />
              <path d="M14 20 L14 23" stroke="var(--teal)" strokeWidth="1.5" strokeOpacity="0.5" />
              <path d="M8 14 L5 14" stroke="var(--teal)" strokeWidth="1.5" strokeOpacity="0.5" />
            </svg>
            <div>
              <div style={{ fontFamily: "JetBrains Mono, monospace", fontWeight: 700, fontSize: 15, color: "var(--text)", letterSpacing: "-0.02em" }}>
                PrivTrace
              </div>
              <div style={{ fontSize: 10, color: "var(--subtle)", fontFamily: "JetBrains Mono, monospace", letterSpacing: "0.04em" }}>
                DPDP · IT Act · CERT-In · GDPR
              </div>
            </div>
          </div>

          {/* Right side */}
          <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
            {aiAvailable && (
              <span style={{
                display: "flex", alignItems: "center", gap: 5,
                fontSize: 11, color: "var(--violet)", fontFamily: "JetBrains Mono, monospace",
              }}>
                <span style={{ width: 6, height: 6, borderRadius: "50%", background: "var(--violet)", animation: "pulse-teal 2s infinite" }} />
                Gemini
              </span>
            )}
            {step === "report" && (
              <button className="btn-ghost" style={{ fontSize: 12, padding: "4px 10px" }} onClick={reset}>
                New scan
              </button>
            )}
          </div>
        </div>
      </header>

      <main style={{ maxWidth: 960, margin: "0 auto", padding: "32px 24px 64px" }}>
        {/* Step indicator */}
        {step !== "report" && (
          <div style={{ display: "flex", alignItems: "center", gap: 4, marginBottom: 28, flexWrap: "wrap" }}>
            {STEPS.map(([k, label], i) => {
              const state = i < idx ? "done" : i === idx ? "active" : "todo";
              return (
                <div key={k} style={{ display: "flex", alignItems: "center", gap: 4 }}>
                  <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
                    <span style={{
                      width: 20, height: 20, borderRadius: "50%", display: "flex", alignItems: "center", justifyContent: "center",
                      fontSize: 10, fontFamily: "JetBrains Mono, monospace", fontWeight: 700,
                      background: state === "done" ? "var(--teal)" : state === "active" ? "rgba(0,229,197,0.15)" : "var(--muted)",
                      color: state === "done" ? "var(--base)" : state === "active" ? "var(--teal)" : "var(--dim)",
                      border: state === "active" ? "1px solid var(--teal)" : "1px solid transparent",
                      transition: "all 0.2s",
                    }}>
                      {state === "done" ? "✓" : i + 1}
                    </span>
                    <span style={{
                      fontSize: 12,
                      fontFamily: "JetBrains Mono, monospace",
                      color: state === "active" ? "var(--text)" : state === "done" ? "var(--teal)" : "var(--dim)",
                      fontWeight: state === "active" ? 600 : 400,
                    }}>
                      {label}
                    </span>
                  </div>
                  {i < STEPS.length - 1 && (
                    <span style={{ color: "var(--muted)", fontSize: 12, margin: "0 2px" }}>›</span>
                  )}
                </div>
              );
            })}
          </div>
        )}

        {/* Error banner */}
        {error && (
          <div style={{
            marginBottom: 20,
            padding: "12px 16px",
            background: "rgba(255,77,106,0.08)",
            border: "1px solid rgba(255,77,106,0.3)",
            borderRadius: 8,
            color: "var(--red)",
            fontSize: 13,
            fontFamily: "JetBrains Mono, monospace",
            display: "flex",
            alignItems: "flex-start",
            gap: 8,
          }}>
            <span style={{ marginTop: 1 }}>⚠</span>
            <span>{error}</span>
          </div>
        )}

        {/* Steps */}
        <div style={{ animation: "fade-in 0.25s ease both" }}>
          {step === "connect" && (
            <ConnectStep
              initial={source}
              baselineNote={baselineId ? `Upload the fixed version — the report will show what changed since scan ${baselineId}.` : undefined}
              onNext={(s) => { setSource(s); setStep("packs"); }}
            />
          )}
          {step === "packs" && (
            <PacksStep selected={packs} onBack={() => setStep("connect")} onNext={(p) => { setPacks(p); setStep("checklist"); }} />
          )}
          {step === "checklist" && (
            <div style={busy ? { pointerEvents: "none", opacity: 0.6 } : {}}>
              <ChecklistStep packs={packs} answers={answers} aiAvailable={aiAvailable} onBack={() => setStep("packs")} onStart={start} />
            </div>
          )}
          {step === "progress" && scanId && (
            <ProgressStep scanId={scanId} onDone={onDone} onError={onError} />
          )}
          {step === "report" && result && (
            <Report
              result={result}
              canRescan={source?.kind === "github"}
              onRescan={rescan}
              onUploadFixed={() => { setBaselineId(result.scan_id); setSource(null); setStep("connect"); }}
              onNew={reset}
            />
          )}
        </div>
      </main>

      <footer style={{ textAlign: "center", paddingBottom: 32, fontSize: 11, color: "var(--dim)", fontFamily: "JetBrains Mono, monospace" }}>
        Findings are engineering evidence, not legal advice.
      </footer>
    </div>
  );
}
