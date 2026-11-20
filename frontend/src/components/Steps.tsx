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
    <div className="card" style={{ padding: 28 }}>
      <div style={{ marginBottom: 20 }}>
        <h2 style={{ fontSize: 18, fontWeight: 700, color: "var(--text)", marginBottom: 6 }}>Connect your code</h2>
        <p style={{ fontSize: 13, color: "var(--subtle)" }}>
          Code is copied to a temporary folder, scanned, and deleted when the scan finishes.
        </p>
      </div>

      {baselineNote && (
        <div style={{
          padding: "10px 14px", marginBottom: 20,
          background: "rgba(0,229,197,0.06)", border: "1px solid rgba(0,229,197,0.2)", borderRadius: 6,
          fontSize: 12, color: "var(--teal)", fontFamily: "JetBrains Mono, monospace",
        }}>
          {baselineNote}
        </div>
      )}

      {/* Tab switcher */}
      <div style={{
        display: "inline-flex", background: "var(--surface)", borderRadius: 6,
        border: "1px solid var(--border)", padding: 3, marginBottom: 20,
      }}>
        {(["github", "zip"] as const).map((t) => (
          <button key={t} onClick={() => setTab(t)} style={{
            padding: "6px 16px", borderRadius: 4, fontSize: 12, fontWeight: 600,
            fontFamily: "JetBrains Mono, monospace", cursor: "pointer", border: "none",
            background: tab === t ? "var(--card)" : "transparent",
            color: tab === t ? "var(--teal)" : "var(--dim)",
            boxShadow: tab === t ? "0 1px 3px rgba(0,0,0,0.3)" : "none",
            transition: "all 0.15s",
          }}>
            {t === "github" ? "GitHub repo" : "Upload ZIP"}
          </button>
        ))}
      </div>

      {tab === "github" ? (
        <div>
          <label style={{ display: "block", fontSize: 12, color: "var(--subtle)", marginBottom: 6, fontFamily: "JetBrains Mono, monospace" }}>
            Repository URL
          </label>
          <input
            className="input"
            placeholder="https://github.com/owner/repo"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
          />
          {url && !urlOk && (
            <span style={{ display: "block", marginTop: 6, fontSize: 11, color: "var(--red)", fontFamily: "JetBrains Mono, monospace" }}>
              Use a public https://github.com/owner/repo URL.
            </span>
          )}
        </div>
      ) : (
        <label style={{
          display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center",
          border: "2px dashed var(--border)", borderRadius: 8,
          background: "var(--surface)", padding: "36px 24px", textAlign: "center", cursor: "pointer",
          transition: "border-color 0.15s",
        }}
          onMouseEnter={(e) => (e.currentTarget.style.borderColor = "var(--teal)")}
          onMouseLeave={(e) => (e.currentTarget.style.borderColor = "var(--border)")}
        >
          <input type="file" accept=".zip,application/zip" style={{ display: "none" }} onChange={(e) => setFile(e.target.files?.[0] ?? null)} />
          <div style={{ fontSize: 24, marginBottom: 8 }}>⬆</div>
          <span style={{ fontSize: 13, fontWeight: 600, color: "var(--text)" }}>
            {file ? file.name : "Choose a .zip of your repository"}
          </span>
          <span style={{ marginTop: 4, fontSize: 11, color: "var(--subtle)", fontFamily: "JetBrains Mono, monospace" }}>
            {file ? `${(file.size / 1024).toFixed(0)} KB` : "Up to 50 MB"}
          </span>
        </label>
      )}

      <p style={{ marginTop: 16, fontSize: 11, color: "var(--dim)" }}>
        Scanning locally?{" "}
        <code style={{ fontFamily: "JetBrains Mono, monospace", background: "var(--muted)", padding: "1px 5px", borderRadius: 3 }}>
          privtrace scan ./repo --packs dpdp,security
        </code>
      </p>

      <div style={{ marginTop: 24, display: "flex", justifyContent: "flex-end" }}>
        <button className="btn-primary" disabled={!ready}
          onClick={() => onNext(tab === "github" ? { kind: "github", url: url.trim() } : { kind: "zip", file: file! })}>
          Continue →
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
    <div className="card" style={{ padding: 28 }}>
      <div style={{ marginBottom: 24 }}>
        <h2 style={{ fontSize: 18, fontWeight: 700, color: "var(--text)", marginBottom: 6 }}>Pick compliance frameworks</h2>
        <p style={{ fontSize: 13, color: "var(--subtle)" }}>
          Each pack is a set of rules. Automated rules are checked in code; manual ones come from a short checklist.
        </p>
      </div>

      {err && <p style={{ fontSize: 13, color: "var(--red)", marginBottom: 16 }}>Could not load packs: {err}</p>}
      {!packs && !err && (
        <div style={{ display: "flex", alignItems: "center", gap: 8, padding: "24px 0", color: "var(--subtle)", fontSize: 13 }}>
          <Spinner /> Loading packs…
        </div>
      )}

      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(260px, 1fr))", gap: 12 }}>
        {packs?.map((p) => {
          const on = sel.has(p.id);
          return (
            <button key={p.id} onClick={() => toggle(p.id)} style={{
              background: on ? "rgba(0,229,197,0.06)" : "var(--surface)",
              border: on ? "1px solid rgba(0,229,197,0.4)" : "1px solid var(--border)",
              borderRadius: 8, padding: 16, textAlign: "left", cursor: "pointer",
              transition: "all 0.15s", outline: "none",
              boxShadow: on ? "0 0 0 1px rgba(0,229,197,0.15)" : "none",
            }}>
              <div style={{ display: "flex", alignItems: "flex-start", justifyContent: "space-between", gap: 8, marginBottom: 10 }}>
                <div>
                  <div style={{ fontSize: 14, fontWeight: 700, color: on ? "var(--teal)" : "var(--text)", fontFamily: "JetBrains Mono, monospace" }}>
                    {p.short_name}
                  </div>
                  <div style={{ fontSize: 12, color: "var(--subtle)", marginTop: 2 }}>{p.name}</div>
                </div>
                <div style={{
                  width: 18, height: 18, borderRadius: 4, flexShrink: 0,
                  background: on ? "var(--teal)" : "transparent",
                  border: on ? "1px solid var(--teal)" : "1px solid var(--dim)",
                  display: "flex", alignItems: "center", justifyContent: "center",
                  transition: "all 0.15s",
                }}>
                  {on && <svg viewBox="0 0 12 12" width="10" height="10" fill="var(--base)"><path d="M2 6l3 3 5-5" stroke="var(--base)" strokeWidth="1.8" fill="none" strokeLinecap="round" /></svg>}
                </div>
              </div>
              <div style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
                <span style={{ fontSize: 10, fontFamily: "JetBrains Mono, monospace", color: "var(--dim)", background: "var(--muted)", borderRadius: 3, padding: "2px 6px" }}>
                  {p.jurisdiction}
                </span>
                <span style={{ fontSize: 10, fontFamily: "JetBrains Mono, monospace", color: "var(--dim)", background: "var(--muted)", borderRadius: 3, padding: "2px 6px" }}>
                  v{p.version}
                </span>
                <span style={{ fontSize: 10, color: "var(--subtle)" }}>
                  {p.automated}a · {p.hybrid}h · {p.manual}m
                </span>
              </div>
              {p.unverified_references > 0 && (
                <div style={{ marginTop: 8, fontSize: 10, color: "var(--amber)", fontFamily: "JetBrains Mono, monospace" }}>
                  ⚠ {p.unverified_references} ref(s) pending verification
                </div>
              )}
            </button>
          );
        })}
      </div>

      <div style={{ marginTop: 24, display: "flex", justifyContent: "space-between" }}>
        <button className="btn-ghost" onClick={onBack}>← Back</button>
        <button className="btn-primary" disabled={!sel.size} onClick={() => onNext([...sel])}>Continue →</button>
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

  const unique = items ? Object.values(Object.fromEntries(items.map((i) => [i.rule_id, i]))) : [];
  const groups = unique.reduce<Record<string, ChecklistItem[]>>((g, i) => { (g[i.pack] ??= []).push(i); return g; }, {});
  const answered = unique.filter((i) => ans[i.rule_id]).length;

  return (
    <div className="card" style={{ padding: 28 }}>
      <div style={{ display: "flex", alignItems: "baseline", justifyContent: "space-between", marginBottom: 8, flexWrap: "wrap", gap: 8 }}>
        <h2 style={{ fontSize: 18, fontWeight: 700, color: "var(--text)" }}>Things code can't show</h2>
        {items && (
          <span style={{ fontSize: 11, fontFamily: "JetBrains Mono, monospace", color: "var(--teal)" }}>
            {answered}/{unique.length} answered
          </span>
        )}
      </div>
      <p style={{ fontSize: 13, color: "var(--subtle)", marginBottom: 24 }}>
        Answer what you can. "Not sure" and unanswered questions are listed as <em>needs review</em> and left out of the score.
      </p>

      {!items && (
        <div style={{ display: "flex", alignItems: "center", gap: 8, padding: "24px 0", color: "var(--subtle)", fontSize: 13 }}>
          <Spinner /> Loading checklist…
        </div>
      )}

      {Object.entries(groups).map(([pack, qs]) => (
        <div key={pack} style={{ marginBottom: 24 }}>
          <div style={{
            fontSize: 10, fontFamily: "JetBrains Mono, monospace", color: "var(--teal)",
            letterSpacing: "0.1em", textTransform: "uppercase", marginBottom: 10,
            display: "flex", alignItems: "center", gap: 8,
          }}>
            <span style={{ flex: 1, borderBottom: "1px solid var(--border)", marginLeft: 8, height: 0, display: "inline-block" }} />
            {pack}
            <span style={{ flex: 1, borderBottom: "1px solid var(--border)", marginRight: 8, height: 0, display: "inline-block" }} />
          </div>
          <div style={{ borderRadius: 8, border: "1px solid var(--border)", overflow: "hidden" }}>
            {qs.map((q, qi) => (
              <div key={q.rule_id} style={{
                padding: "14px 16px",
                borderTop: qi > 0 ? "1px solid var(--border)" : "none",
                display: "flex", flexDirection: "column", gap: 10,
              }}>
                <div>
                  <div style={{ fontSize: 13, color: "var(--text)", lineHeight: 1.5 }}>{q.question}</div>
                  <div style={{ marginTop: 6, display: "flex", flexWrap: "wrap", alignItems: "center", gap: 8 }}>
                    <SeverityBadge s={q.severity} />
                    <code style={{ fontSize: 10, color: "var(--dim)", fontFamily: "JetBrains Mono, monospace" }}>{q.rule_id}</code>
                    {q.check_type === "hybrid" && (
                      <span style={{ fontSize: 10, color: "var(--subtle)" }}>· code evidence checked too</span>
                    )}
                  </div>
                </div>
                <div style={{ display: "inline-flex", borderRadius: 6, border: "1px solid var(--border)", overflow: "hidden", alignSelf: "flex-start" }}>
                  {(["yes", "no", "not_sure"] as Answer[]).map((a) => {
                    const active = ans[q.rule_id] === a;
                    const bg = active
                      ? a === "yes" ? "var(--green)" : a === "no" ? "var(--red)" : "var(--amber)"
                      : "transparent";
                    return (
                      <button key={a}
                        onClick={() => setAns((s) => ({ ...s, [q.rule_id]: a }))}
                        style={{
                          padding: "5px 14px", fontSize: 12, fontWeight: 600, cursor: "pointer",
                          fontFamily: "JetBrains Mono, monospace", border: "none",
                          background: bg,
                          color: active ? "var(--base)" : "var(--subtle)",
                          transition: "all 0.15s",
                          borderRight: a !== "not_sure" ? "1px solid var(--border)" : "none",
                        }}>
                        {a === "not_sure" ? "?" : a === "yes" ? "Yes" : "No"}
                      </button>
                    );
                  })}
                </div>
              </div>
            ))}
          </div>
        </div>
      ))}

      {/* Gemini toggle */}
      <label style={{
        display: "flex", alignItems: "flex-start", gap: 12, padding: 16, borderRadius: 8, cursor: "pointer",
        background: aiAvailable ? "rgba(167,139,250,0.06)" : "var(--surface)",
        border: `1px solid ${aiAvailable ? "rgba(167,139,250,0.2)" : "var(--border)"}`,
        marginTop: items ? 8 : 0,
        opacity: aiAvailable ? 1 : 0.6,
      }}>
        <input type="checkbox" checked={useAi} disabled={!aiAvailable}
          onChange={(e) => setUseAi(e.target.checked)}
          style={{ marginTop: 2, accentColor: "var(--violet)", width: 14, height: 14 }}
        />
        <div>
          <div style={{ fontSize: 13, fontWeight: 600, color: aiAvailable ? "var(--violet)" : "var(--dim)" }}>
            Gemini explanations
          </div>
          <div style={{ fontSize: 11, color: "var(--subtle)", marginTop: 3 }}>
            {aiAvailable
              ? "Only small, redacted snippets (≤ 40 lines, identifiers masked) are sent. AI never changes a pass/fail result."
              : "Not configured on this server (set GEMINI_API_KEY). The scan works fully without it."}
          </div>
        </div>
      </label>

      <div style={{ marginTop: 24, display: "flex", justifyContent: "space-between" }}>
        <button className="btn-ghost" onClick={onBack}>← Back</button>
        <button className="btn-primary" disabled={!items} onClick={() => onStart(ans, useAi && aiAvailable)}>
          Run scan →
        </button>
      </div>
    </div>
  );
}

// ------------------------------------------------------------------ 4. Progress
const STAGES = [
  ["queued",     "Queued"],
  ["fetching",   "Fetching code"],
  ["analyzing",  "Parsing code, tracing personal data"],
  ["evaluating", "Running compliance rules"],
  ["explaining", "Writing AI explanations"],
  ["done",       "Building report"],
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
        if (s.status === "done")  { done.current = true; onDone(s); }
        if (s.status === "error") { done.current = true; onError(s.message); }
      } catch (e) {
        done.current = true;
        onError(String((e as Error).message ?? e));
      }
    }, 800);
    return () => clearInterval(t);
  }, [scanId, onDone, onError]);

  const idx = STAGES.findIndex(([k]) => k === (st?.stage ?? "queued"));
  const pct = idx < 0 ? 0 : Math.round(((idx) / (STAGES.length - 1)) * 100);

  return (
    <div className="card" style={{ padding: 28 }}>
      <div style={{ marginBottom: 28 }}>
        <h2 style={{ fontSize: 18, fontWeight: 700, color: "var(--text)", marginBottom: 6 }}>Scanning</h2>
        {st?.source_ref && (
          <code style={{ fontSize: 12, color: "var(--teal)", fontFamily: "JetBrains Mono, monospace" }}>
            {st.source_ref}
          </code>
        )}
      </div>

      {/* Progress bar */}
      <div style={{ position: "relative", height: 3, background: "var(--muted)", borderRadius: 2, marginBottom: 28, overflow: "hidden" }}>
        <div style={{
          position: "absolute", left: 0, top: 0, height: "100%", borderRadius: 2,
          background: "var(--teal)", width: `${pct}%`, transition: "width 0.6s ease",
          boxShadow: "0 0 8px var(--teal)",
        }} />
        {/* animated glow sweep */}
        <div style={{
          position: "absolute", top: 0, width: 60, height: "100%",
          background: "linear-gradient(90deg, transparent, rgba(0,229,197,0.6), transparent)",
          animation: "scan-line 2s ease-in-out infinite",
        }} />
      </div>

      <ol style={{ listStyle: "none", padding: 0, margin: 0, display: "flex", flexDirection: "column", gap: 12 }}>
        {STAGES
          .filter(([k]) => k !== "explaining" || st?.stage === "explaining")
          .map(([k, label]) => {
            const i = STAGES.findIndex(([x]) => x === k);
            const state = i < idx ? "done" : i === idx ? "active" : "todo";
            return (
              <li key={k} style={{ display: "flex", alignItems: "center", gap: 12 }}>
                {state === "done" ? (
                  <span style={{
                    width: 20, height: 20, borderRadius: "50%", display: "flex", alignItems: "center", justifyContent: "center",
                    background: "rgba(61,220,132,0.15)", border: "1px solid var(--green)", flexShrink: 0,
                    fontSize: 10, color: "var(--green)",
                  }}>✓</span>
                ) : state === "active" ? (
                  <Spinner size={20} />
                ) : (
                  <span style={{ width: 20, height: 20, borderRadius: "50%", border: "1px solid var(--muted)", flexShrink: 0 }} />
                )}
                <span style={{
                  fontSize: 13, fontFamily: "JetBrains Mono, monospace",
                  color: state === "done" ? "var(--green)" : state === "active" ? "var(--text)" : "var(--dim)",
                  fontWeight: state === "active" ? 600 : 400,
                }}>
                  {label}
                </span>
                {state === "active" && (
                  <span style={{ marginLeft: "auto", fontSize: 10, color: "var(--teal)", fontFamily: "JetBrains Mono, monospace", animation: "pulse-teal 1.5s infinite" }}>
                    running…
                  </span>
                )}
              </li>
            );
          })}
      </ol>

      <div style={{ marginTop: 28, padding: "10px 14px", background: "var(--surface)", borderRadius: 6, border: "1px solid var(--border)" }}>
        <span style={{ fontSize: 10, color: "var(--dim)", fontFamily: "JetBrains Mono, monospace" }}>
          scan_id: {scanId}
        </span>
      </div>
    </div>
  );
}
