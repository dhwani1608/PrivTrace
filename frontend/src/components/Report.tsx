import { useMemo, useState } from "react";
import { api } from "../api";
import type { RuleResult, ScanResult, Status } from "../types";
import FlowMap from "./FlowMap";
import { Diff, Gauge, SeverityBadge, StatusBadge } from "./ui";

const SEV_ORDER = { critical: 0, high: 1, medium: 2, low: 3 };
const ST_ORDER: Record<Status, number> = { failed: 0, needs_review: 1, passed: 2, not_assessable: 3 };

function Delta({ v }: { v: number | null }) {
  if (v === null) return null;
  return (
    <span style={{ fontWeight: 700, fontFamily: "JetBrains Mono, monospace", color: v >= 0 ? "var(--green)" : "var(--red)" }}>
      {v >= 0 ? "+" : ""}{v.toFixed(1)}
    </span>
  );
}

function Finding({ r }: { r: RuleResult }) {
  const [open, setOpen] = useState(r.status === "failed");
  return (
    <div id={`${r.pack_id}-${r.rule_id}`} style={{
      border: `1px solid ${r.status === "failed" ? "rgba(255,77,106,0.25)" : "var(--border)"}`,
      borderLeft: `2px solid ${r.status === "failed" ? "var(--red)" : r.status === "passed" ? "var(--green)" : r.status === "needs_review" ? "var(--amber)" : "var(--muted)"}`,
      borderRadius: 8, overflow: "hidden", background: "var(--surface)",
    }}>
      <button onClick={() => setOpen(!open)} style={{
        display: "flex", width: "100%", flexWrap: "wrap", alignItems: "center", gap: 8,
        padding: "10px 14px", textAlign: "left", background: "transparent", border: "none", cursor: "pointer",
        transition: "background 0.1s",
      }}
        onMouseEnter={(e) => (e.currentTarget.style.background = "rgba(255,255,255,0.03)")}
        onMouseLeave={(e) => (e.currentTarget.style.background = "transparent")}
      >
        <StatusBadge s={r.status} />
        <SeverityBadge s={r.severity} />
        <span style={{ flex: 1, fontSize: 13, fontWeight: 500, color: "var(--text)", minWidth: 160 }}>{r.title}</span>
        <code style={{ fontSize: 10, color: "var(--dim)", fontFamily: "JetBrains Mono, monospace" }}>{r.rule_id}</code>
        <span style={{ color: "var(--dim)", fontSize: 12 }}>{open ? "▾" : "▸"}</span>
      </button>

      {open && (
        <div style={{ padding: "14px 16px", borderTop: "1px solid var(--border)", display: "flex", flexDirection: "column", gap: 14 }}>
          <p style={{ fontSize: 13, color: "var(--text)", lineHeight: 1.6 }}>{r.message}</p>

          <dl style={{ display: "grid", gridTemplateColumns: "140px 1fr", rowGap: 8, columnGap: 12, fontSize: 13 }}>
            <dt style={{ color: "var(--subtle)" }}>Legal ref</dt>
            <dd style={{ display: "flex", alignItems: "center", gap: 6, flexWrap: "wrap" }}>
              <span style={{ color: "var(--text)" }}>{r.reference}</span>
              {!r.reference_verified && (
                <span className="badge" style={{ background: "rgba(245,184,64,0.15)", color: "var(--amber)" }}>unverified</span>
              )}
              <a href={r.source_url} target="_blank" rel="noreferrer"
                style={{ color: "var(--teal)", fontSize: 11, fontFamily: "JetBrains Mono, monospace" }}>
                source ↗
              </a>
            </dd>
            <dt style={{ color: "var(--subtle)" }}>Why it matters</dt>
            <dd style={{ color: "var(--text)" }}>{r.why_it_matters}</dd>
            <dt style={{ color: "var(--subtle)" }}>How to fix</dt>
            <dd style={{ color: "var(--text)" }}>{r.remediation}</dd>
            {r.question && (
              <>
                <dt style={{ color: "var(--subtle)" }}>Checklist</dt>
                <dd style={{ color: "var(--text)" }}>{r.question} — <strong>{r.manual_answer?.replace("_", " ") ?? "not answered"}</strong></dd>
              </>
            )}
          </dl>

          {r.evidence.length > 0 && (
            <div style={{ overflow: "hidden", borderRadius: 6, border: "1px solid var(--border)" }}>
              <table style={{ width: "100%", fontSize: 11, fontFamily: "JetBrains Mono, monospace", borderCollapse: "collapse" }}>
                <thead>
                  <tr style={{ background: "var(--muted)" }}>
                    <th style={{ textAlign: "left", padding: "6px 12px", color: "var(--subtle)", fontWeight: 500 }}>Location</th>
                    <th style={{ textAlign: "left", padding: "6px 12px", color: "var(--subtle)", fontWeight: 500 }}>Evidence (redacted)</th>
                  </tr>
                </thead>
                <tbody>
                  {r.evidence.map((e, i) => (
                    <tr key={i} style={{ borderTop: "1px solid var(--border)", verticalAlign: "top" }}>
                      <td style={{ padding: "8px 12px", whiteSpace: "nowrap", color: "var(--teal)" }}>{e.file}:{e.line}</td>
                      <td style={{ padding: "8px 12px" }}>
                        {e.snippet && (
                          <code style={{ display: "block", background: "var(--base)", padding: "4px 8px", borderRadius: 4, wordBreak: "break-all", color: "var(--text)" }}>
                            {e.snippet}
                          </code>
                        )}
                        {e.detail && <span style={{ color: "var(--subtle)", fontSize: 11, marginTop: 2, display: "block" }}>{e.detail}</span>}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

          {r.ai?.explanation && (
            <div style={{ padding: "10px 14px", borderRadius: 6, background: "rgba(167,139,250,0.08)", border: "1px solid rgba(167,139,250,0.2)", fontSize: 13 }}>
              <span className="badge" style={{ background: "rgba(167,139,250,0.2)", color: "var(--violet)", marginRight: 8 }}>AI</span>
              {r.ai.explanation}
            </div>
          )}

          {r.fix_diff ? (
            <div>
              <div style={{ fontSize: 12, fontWeight: 600, marginBottom: 6, color: "var(--subtle)" }}>
                Suggested change <span style={{ fontWeight: 400 }}>(template-generated — review before applying)</span>
              </div>
              <Diff text={r.fix_diff} />
            </div>
          ) : r.ai && (r.ai.suggested_diff || r.ai.suggested_fix) ? (
            <div>
              <div style={{ fontSize: 12, fontWeight: 600, marginBottom: 6, display: "flex", alignItems: "center", gap: 8 }}>
                Suggested change
                <span className="badge" style={{ background: "rgba(167,139,250,0.2)", color: "var(--violet)" }}>AI — review before applying</span>
              </div>
              {r.ai.suggested_fix && <p style={{ fontSize: 13, marginBottom: 8, color: "var(--text)" }}>{r.ai.suggested_fix}</p>}
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

  const riskColor = {
    Critical: "var(--red)", High: "var(--orange)", Medium: "var(--amber)", Low: "var(--green)"
  }[result.risk_level] ?? "var(--subtle)";

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>

      {/* Header */}
      <div className="card" style={{ padding: 20, display: "flex", flexWrap: "wrap", alignItems: "center", justifyContent: "space-between", gap: 16 }}>
        <div>
          <div style={{ fontSize: 10, fontFamily: "JetBrains Mono, monospace", color: "var(--subtle)", marginBottom: 4 }}>
            scan:{result.scan_id} · {new Date(result.created_at).toLocaleString()}
          </div>
          <h2 style={{ fontSize: 20, fontWeight: 700, color: "var(--text)", fontFamily: "JetBrains Mono, monospace", letterSpacing: "-0.02em" }}>
            {result.target}
          </h2>
          {result.ai_used && (
            <span style={{ fontSize: 11, color: "var(--violet)", fontFamily: "JetBrains Mono, monospace" }}>+ {result.ai_model}</span>
          )}
        </div>
        <div style={{ display: "flex", flexWrap: "wrap", gap: 8 }}>
          {canRescan
            ? <button className="btn-primary" onClick={onRescan}>Rescan after fixes</button>
            : <button className="btn-primary" onClick={onUploadFixed}>Upload fixed version</button>
          }
          <a className="btn-ghost" href={api.reportHtmlUrl(result.scan_id, true)} style={{ textDecoration: "none" }}>HTML ↗</a>
          <a className="btn-ghost" href={api.reportJsonUrl(result.scan_id)} download={`privtrace-${result.scan_id}.json`} style={{ textDecoration: "none" }}>JSON ↓</a>
          <button className="btn-ghost" onClick={onNew}>New scan</button>
        </div>
      </div>

      {/* Legal disclaimer */}
      <div style={{
        padding: "10px 14px", borderRadius: 8, fontSize: 12,
        background: "rgba(245,184,64,0.06)", border: "1px solid rgba(245,184,64,0.2)", color: "var(--amber)",
        fontFamily: "JetBrains Mono, monospace",
      }}>
        <strong>Not legal advice.</strong> {result.disclaimer}
      </div>

      {/* 1. Summary */}
      <section className="card" style={{ padding: 20 }}>
        <div style={{ fontSize: 10, letterSpacing: "0.08em", color: "var(--teal)", fontFamily: "JetBrains Mono, monospace", marginBottom: 16 }}>
          SUMMARY
        </div>

        {/* Scores */}
        <div style={{ display: "flex", flexWrap: "wrap", gap: 12, marginBottom: 20 }}>
          {/* Overall */}
          <div style={{
            padding: "16px 20px", borderRadius: 8, border: "1px solid var(--border)",
            background: "var(--surface)", display: "flex", flexDirection: "column", alignItems: "center", minWidth: 140,
          }}>
            <Gauge score={result.overall_score} size={110} label="Overall" />
            <div style={{ marginTop: 8, fontSize: 11, color: "var(--subtle)", fontFamily: "JetBrains Mono, monospace" }}>Risk level</div>
            <div style={{ fontSize: 20, fontWeight: 800, color: riskColor, fontFamily: "JetBrains Mono, monospace" }}>{result.risk_level}</div>
          </div>

          {/* Per-pack scores */}
          {result.pack_scores.map((p) => (
            <div key={p.pack_id} style={{
              padding: "16px 20px", borderRadius: 8, border: "1px solid var(--border)",
              background: "var(--surface)", display: "flex", flexDirection: "column", alignItems: "center", minWidth: 150,
            }}>
              <Gauge score={p.score} label={p.short_name} />
              <div style={{ marginTop: 8, fontSize: 12, fontWeight: 700, color: "var(--text)", fontFamily: "JetBrains Mono, monospace" }}>{p.short_name}</div>
              <div style={{ marginTop: 4, fontSize: 10, color: "var(--subtle)", textAlign: "center", lineHeight: 1.5 }}>
                {p.coverage.automated_checked}/{p.coverage.total} auto · {p.coverage.manual_answered} manual · {p.coverage.not_assessable} n/a
              </div>
            </div>
          ))}
        </div>

        {/* Stat tiles */}
        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(180px, 1fr))", gap: 10 }}>
          {[
            [result.summary.files_scanned, `files scanned (${result.summary.python_files} Python)`, false],
            [result.summary.models_with_pii, "models holding personal data", false],
            [result.summary.pii_sinks, "personal data sinks", false],
            [result.summary.risky_flows, "risky flows", true],
          ].map(([v, l, danger], i) => (
            <div key={i} style={{
              padding: "12px 14px", borderRadius: 8,
              background: danger ? "rgba(255,77,106,0.06)" : "var(--surface)",
              border: `1px solid ${danger ? "rgba(255,77,106,0.2)" : "var(--border)"}`,
            }}>
              <div style={{ fontSize: 28, fontWeight: 800, fontFamily: "JetBrains Mono, monospace", color: danger ? "var(--red)" : "var(--teal)" }}>
                {v}
              </div>
              <div style={{ fontSize: 11, color: "var(--subtle)", marginTop: 2 }}>{l}</div>
            </div>
          ))}
        </div>

        {/* Diff */}
        {d && (
          <div style={{
            marginTop: 16, padding: 14, borderRadius: 8,
            background: "rgba(0,229,197,0.04)", border: "1px solid rgba(0,229,197,0.15)", fontSize: 13,
          }}>
            <div style={{ fontWeight: 600, color: "var(--teal)", fontFamily: "JetBrains Mono, monospace", fontSize: 11, marginBottom: 6 }}>
              CHANGES SINCE LAST SCAN
            </div>
            <div style={{ color: "var(--text)" }}>
              Overall {d.overall_before ?? "n/a"} → <strong>{d.overall_after ?? "n/a"}</strong> <Delta v={d.overall_delta} /> · Risk {d.risk_before} → <strong>{d.risk_after}</strong>
            </div>
            <div style={{ marginTop: 8, display: "flex", flexWrap: "wrap", gap: 10 }}>
              {d.packs.map((p) => (
                <span key={p.pack_id} style={{ fontSize: 11, fontFamily: "JetBrains Mono, monospace", color: "var(--subtle)" }}>
                  {p.short_name}: {p.before ?? "n/a"} → {p.after ?? "n/a"} <Delta v={p.delta} />
                </span>
              ))}
            </div>
            {d.fixed.length > 0 && (
              <div style={{ marginTop: 6, fontSize: 11, color: "var(--green)", fontFamily: "JetBrains Mono, monospace" }}>
                Fixed: {d.fixed.map((f) => f.rule_id).join(", ")}
              </div>
            )}
            {d.regressed.length > 0 && (
              <div style={{ marginTop: 4, fontSize: 11, color: "var(--red)", fontFamily: "JetBrains Mono, monospace" }}>
                New failures: {d.regressed.map((f) => f.rule_id).join(", ")}
              </div>
            )}
          </div>
        )}

        {/* Top fixes */}
        <div style={{ marginTop: 20 }}>
          <div style={{ fontSize: 10, letterSpacing: "0.08em", color: "var(--subtle)", fontFamily: "JetBrains Mono, monospace", marginBottom: 10 }}>
            TOP FIXES
          </div>
          {top.length ? (
            <ol style={{ listStyle: "none", padding: 0, margin: 0, display: "flex", flexDirection: "column", gap: 8 }}>
              {top.map((t, i) => (
                <li key={t.rule_id} style={{
                  display: "flex", gap: 12, padding: "10px 14px", borderRadius: 8,
                  background: "var(--surface)", border: "1px solid var(--border)",
                }}>
                  <span style={{ fontSize: 11, fontWeight: 800, color: "var(--dim)", fontFamily: "JetBrains Mono, monospace", width: 16, flexShrink: 0, paddingTop: 2 }}>
                    {i + 1}
                  </span>
                  <div style={{ flex: 1 }}>
                    <div style={{ display: "flex", flexWrap: "wrap", alignItems: "center", gap: 8 }}>
                      <SeverityBadge s={t.severity} />
                      <a href={`#${t.pack_id}-${t.rule_id}`} style={{ fontSize: 13, fontWeight: 600, color: "var(--text)", textDecoration: "none" }}
                        onMouseEnter={(e) => ((e.target as HTMLElement).style.color = "var(--teal)")}
                        onMouseLeave={(e) => ((e.target as HTMLElement).style.color = "var(--text)")}>
                        {t.title}
                      </a>
                      {t.evidence[0] && (
                        <code style={{ fontSize: 10, color: "var(--teal)", fontFamily: "JetBrains Mono, monospace" }}>
                          {t.evidence[0].file}:{t.evidence[0].line}
                        </code>
                      )}
                    </div>
                    <div style={{ marginTop: 4, fontSize: 12, color: "var(--subtle)" }}>{t.remediation}</div>
                  </div>
                </li>
              ))}
            </ol>
          ) : (
            <p style={{ fontSize: 13, color: "var(--dim)" }}>No failed rules.</p>
          )}
        </div>
      </section>

      {/* 2. Data flow */}
      <section className="card" style={{ padding: 20 }}>
        <div style={{ fontSize: 10, letterSpacing: "0.08em", color: "var(--teal)", fontFamily: "JetBrains Mono, monospace", marginBottom: 6 }}>DATA-FLOW MAP</div>
        <p style={{ fontSize: 13, color: "var(--subtle)", marginBottom: 16 }}>
          Where personal data enters, which functions carry it, and which stores or third parties it reaches.
        </p>
        <FlowMap nodes={result.data_flow.nodes} edges={result.data_flow.edges} />
        {result.ai_classifications.length > 0 && (
          <div style={{ marginTop: 14, fontSize: 13 }}>
            <div style={{ fontWeight: 600, marginBottom: 6, display: "flex", alignItems: "center", gap: 8, color: "var(--text)" }}>
              Possible personal data in generic fields
              <span className="badge" style={{ background: "rgba(167,139,250,0.2)", color: "var(--violet)" }}>AI — review</span>
            </div>
            <ul style={{ margin: 0, paddingLeft: 20, color: "var(--subtle)", lineHeight: 1.8 }}>
              {result.ai_classifications.map((c) => (
                <li key={c.name}>
                  <code style={{ color: "var(--teal)", fontFamily: "JetBrains Mono, monospace" }}>{c.name}</code>
                  {" "}({c.category}){c.file && <span style={{ fontSize: 11 }}> {c.file}:{c.line}</span>} — {c.reason}
                </li>
              ))}
            </ul>
          </div>
        )}
      </section>

      {/* 3. Findings */}
      <section className="card" style={{ padding: 20 }}>
        <div style={{ display: "flex", flexWrap: "wrap", alignItems: "center", justifyContent: "space-between", gap: 12, marginBottom: 16 }}>
          <div style={{ fontSize: 10, letterSpacing: "0.08em", color: "var(--teal)", fontFamily: "JetBrains Mono, monospace" }}>
            FINDINGS BY FRAMEWORK
          </div>
          <div style={{ display: "inline-flex", background: "var(--surface)", borderRadius: 6, border: "1px solid var(--border)", padding: 3 }}>
            {(["all", "failed", "needs_review", "passed", "not_assessable"] as const).map((f) => (
              <button key={f} onClick={() => setFilter(f)} style={{
                padding: "4px 10px", borderRadius: 4, fontSize: 11, fontFamily: "JetBrains Mono, monospace",
                cursor: "pointer", border: "none",
                background: filter === f ? "var(--card)" : "transparent",
                color: filter === f ? "var(--teal)" : "var(--dim)",
                fontWeight: filter === f ? 600 : 400,
                transition: "all 0.1s",
                boxShadow: filter === f ? "0 1px 3px rgba(0,0,0,0.3)" : "none",
              }}>
                {f.replace("_", " ")}
              </button>
            ))}
          </div>
        </div>

        {result.pack_scores.map((p) => {
          const rs = result.results
            .filter((r) => r.pack_id === p.pack_id && (filter === "all" || r.status === filter))
            .sort((a, b) => ST_ORDER[a.status] - ST_ORDER[b.status] || SEV_ORDER[a.severity] - SEV_ORDER[b.severity]);
          return (
            <div key={p.pack_id} style={{ marginBottom: 24 }}>
              <div style={{ display: "flex", flexWrap: "wrap", alignItems: "baseline", gap: 10, marginBottom: 8 }}>
                <h4 style={{ fontSize: 14, fontWeight: 700, color: "var(--text)", fontFamily: "JetBrains Mono, monospace" }}>{p.name}</h4>
                <span style={{ fontSize: 11, color: "var(--subtle)", fontFamily: "JetBrains Mono, monospace" }}>
                  {p.score === null ? "n/a" : `${Math.round(p.score)}/100`} · {p.passed}✓ {p.failed}✗ {p.needs_review}? {p.not_assessable}n/a
                </span>
              </div>
              <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
                {rs.map((r) => <Finding key={r.rule_id} r={r} />)}
                {!rs.length && <p style={{ fontSize: 13, color: "var(--dim)", fontFamily: "JetBrains Mono, monospace" }}>Nothing in this filter.</p>}
              </div>
            </div>
          );
        })}
      </section>

      {/* 4. Manual checklist */}
      <section className="card" style={{ padding: 20 }}>
        <div style={{ fontSize: 10, letterSpacing: "0.08em", color: "var(--teal)", fontFamily: "JetBrains Mono, monospace", marginBottom: 14 }}>
          MANUAL CHECKLIST ANSWERS
        </div>
        <div style={{ overflow: "hidden", borderRadius: 6, border: "1px solid var(--border)" }}>
          <table style={{ width: "100%", fontSize: 12, borderCollapse: "collapse", fontFamily: "JetBrains Mono, monospace" }}>
            <thead>
              <tr style={{ background: "var(--muted)" }}>
                {["Rule", "Question", "Answer", "Result"].map((h) => (
                  <th key={h} style={{ textAlign: "left", padding: "8px 12px", color: "var(--subtle)", fontWeight: 500 }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {manual.map((m) => (
                <tr key={m.pack_id + m.rule_id} style={{ borderTop: "1px solid var(--border)", verticalAlign: "top" }}>
                  <td style={{ padding: "8px 12px" }}><code style={{ color: "var(--teal)", fontSize: 10 }}>{m.rule_id}</code></td>
                  <td style={{ padding: "8px 12px", color: "var(--text)", maxWidth: 300 }}>{m.question}</td>
                  <td style={{ padding: "8px 12px", color: "var(--subtle)" }}>{m.manual_answer?.replace("_", " ") ?? "—"}</td>
                  <td style={{ padding: "8px 12px" }}><StatusBadge s={m.status} /></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      {/* 5. Coverage */}
      <section className="card" style={{ padding: 20, fontSize: 13 }}>
        <div style={{ fontSize: 10, letterSpacing: "0.08em", color: "var(--teal)", fontFamily: "JetBrains Mono, monospace", marginBottom: 10 }}>
          COVERAGE & LIMITATIONS
        </div>
        <ul style={{ margin: 0, paddingLeft: 18, color: "var(--subtle)", lineHeight: 1.9 }}>
          {result.pack_scores.map((p) => (
            <li key={p.pack_id}>
              <strong style={{ color: "var(--text)" }}>{p.short_name}</strong>: {p.coverage.automated_checked} of {p.coverage.total} rules checked automatically,
              {" "}{p.coverage.manual_answered} answered manually, {p.coverage.not_assessable} not assessable, {p.coverage.needs_review} need review.
            </li>
          ))}
          <li>Python is analysed in depth; other files get identifier, secret and configuration checks.</li>
          <li>Flow tracking is intra-function plus calls into repo modules; dynamic dispatch and infrastructure config are not followed.</li>
          <li>Consent, minimisation, children's data and third-party sharing are heuristics and never "fail" on their own.</li>
        </ul>
      </section>

      {/* 6. Disclaimer */}
      <section className="card" style={{ padding: 20, fontSize: 13, color: "var(--subtle)" }}>
        <div style={{ fontSize: 10, letterSpacing: "0.08em", color: "var(--dim)", fontFamily: "JetBrains Mono, monospace", marginBottom: 8 }}>
          DISCLAIMER
        </div>
        <p style={{ color: "var(--subtle)" }}>{result.disclaimer}</p>
        <p style={{ marginTop: 10, fontSize: 11, fontFamily: "JetBrains Mono, monospace", color: "var(--dim)" }}>
          <strong style={{ color: "var(--subtle)" }}>Score formula:</strong> {result.scoring_formula}
        </p>
      </section>
    </div>
  );
}
