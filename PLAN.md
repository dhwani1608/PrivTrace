# PrivTrace — Build Plan

Status: **approved 2026-11-20** — building phase by phase, pushing to https://github.com/dhwani1608/PrivTrace after each phase.

Decisions taken (defaults, change any time):
- Git repo initialised inside `PrivTrace/` (not the home folder).
- `backend/privtrace/` installable package; pack YAMLs in repo-root `packs/`.
- "TAD" stays a placeholder in `packs/README.md` until clarified.
- `GEMINI_MODEL` left for the user to set in `.env`; all AI features optional.
- FastAPI background tasks + Redis progress (no separate queue) for the MVP.
- `demo-app-fixed/` is a sibling folder. Docker images use Python 3.12.

This turns `privtrace_claude_code_prompt.md` into a concrete plan. The guiding rule throughout: **deterministic checks decide pass/fail; Gemini only classifies, explains and suggests.**

---

## 1. Architecture

```
            ┌────────────── inputs ──────────────┐
            │ GitHub URL │ ZIP upload │ local dir │
            └─────┬──────────────────────────────┘
                  ▼
        ┌──────────────────┐   workspace is a temp dir, always deleted
        │  Source fetcher  │   in a `finally` after the scan
        └────────┬─────────┘
                 ▼
        ┌──────────────────┐   ParsedModule per file (Python `ast` now;
        │  Parser layer    │   a `LanguageParser` protocol so a tree-sitter
        └────────┬─────────┘   JS/TS parser can be added later)
                 ▼
   ┌─────────────────────────────────────────────┐
   │ Detectors (registry, pure functions)        │
   │  • PII names / models (Pydantic, SQLA, dc)  │
   │  • Indian IDs (Aadhaar+Verhoeff, PAN, UPI,  │
   │    IFSC, mobile, passport, voter, GSTIN)    │
   │  • email, phone, card (Luhn), secrets       │
   │  • sinks: DB, log, LLM, vector, cache, HTTP,│
   │    file, analytics                          │
   │  • config: debug, CORS, TLS, logging, TTL   │
   └────────┬────────────────────────────────────┘
            ▼
   ┌──────────────────┐   intra-file taint + import following;
   │  Flow mapper     │   produces DataFlowGraph (source → path → sink)
   └────────┬─────────┘
            ▼
   ┌──────────────────┐   loads packs/*.yaml, runs each rule's
   │  Rule engine     │   registered check → PASS / FAIL / NEEDS_REVIEW /
   └────────┬─────────┘   NOT_ASSESSABLE; merges manual answers
            ▼
   ┌──────────────────┐   optional, can only ADD text, never change status;
   │  AI enrichment   │   redaction + ≤40-line snippets enforced at one choke point
   └────────┬─────────┘
            ▼
   ┌──────────────────┐   per-pack + overall score, risk level,
   │ Scoring + Report │   diff vs previous scan → JSON / HTML / UI
   └──────────────────┘
```

**Entry points share one function** `run_scan(ScanRequest) -> ScanResult`:
- **CLI** (Typer) calls it directly — no server, DB optional.
- **API** (FastAPI) runs it as a background task, stores progress in Redis and results in Postgres.
- **Cloud Run Job** (later) runs the CLI entry with a scan ID.

### Key design decisions
| Decision | Why |
|---|---|
| Rule status is an enum `passed / failed / needs_review / not_assessable`; never "compliant" | Hard rule #2 |
| `AIEnrichment` is a separate object attached to a finding, typed so it has no `status` field | Makes "Gemini can't flip a fail" structurally impossible, plus a test |
| All Gemini calls go through `ai/gateway.py`, which redacts, truncates to 40 lines and validates with Pydantic | Single choke point for the "no raw PII leaves" test |
| Logs use a redacting `logging.Filter` on the root logger | Never log raw PII snippets |
| Packs are YAML validated by a Pydantic `Pack` model at load time; unknown `detector` names fail loudly | Packs are data; typos are caught early |
| Fix diffs come from per-rule Jinja templates first; Gemini fix only if no template fits, labelled "AI-suggested" | Brief §7 |
| Scan history: Postgres via SQLAlchemy when running the API; CLI stores last result as JSON (`.privtrace/last.json`) for rescan diffs | Rescan diff works without a DB |

---

## 2. Folder structure

The brief suggests `privtrace/backend/app/...`. I'd adjust slightly: make the backend an installable package named `privtrace` so the CLI command is `privtrace` and imports are clean.

```
PrivTrace/                       ← repo root (this folder)
  backend/
    pyproject.toml               (deps, `privtrace` console script)
    privtrace/
      api/                       FastAPI routers: health, packs, scans, reports
      core/                      config (pydantic-settings), redaction, logging filter
      scanner/
        fetch.py                 git clone / zip extract / local copy → temp workspace
        parsers/                 base.py (LanguageParser protocol), python_ast.py
        detectors/               registry.py, pii_names.py, indian_ids.py,
                                 generic_pii.py, secrets.py, sinks.py, config_checks.py
        flow/                    taint.py, graph.py (DataFlowGraph)
      rules/                     engine.py, checks.py (rule-level check functions), registry.py
      packs/                     loader.py, schema.py   (YAML lives in /packs)
      ai/                        gateway.py, client.py (google-genai), prompts.py, schemas.py
      report/                    scoring.py, diff.py, json_report.py, html_report.py,
                                 fix_templates/, templates/report.html.j2
      models/                    Pydantic domain models (Finding, RuleResult, ScanResult…)
      db/                        SQLAlchemy models, session
      verify/                    (stretch) canary deletion tester — interface stubbed early
      cli.py                     Typer app
    tests/                       pytest; fixtures use obviously fake data only
  packs/                         dpdp-2023.yaml, it-act-spdi.yaml, certin-2022.yaml,
                                 gdpr-subset.yaml, security-baseline.yaml, README.md
  frontend/                      React + Vite + TS + Tailwind
  demo-app/                      deliberately non-compliant RAG chatbot
  demo-app-fixed/                same app, fixes applied
  docs/                          ARCHITECTURE.md, SCORING.md, LEGAL_REVIEW_TODO.md,
                                 DEPLOY_GCP.md, ADDING_A_PACK.md, DETECTION_LIMITS.md
  docker-compose.yml  .env.example  README.md  PLAN.md
```

---

## 3. Core data model (sketch)

```python
class Severity(StrEnum): critical, high, medium, low          # weights 10/6/3/1
class RuleStatus(StrEnum): passed, failed, needs_review, not_assessable
class Evidence: file, line, end_line, snippet_redacted, confidence, data_category
class RuleResult: rule_id, pack_id, status, severity, evidence[], reference,
                  reference_verified, source_url, why_it_matters, remediation,
                  fix_diff | None, ai: AIEnrichment | None
class AIEnrichment: explanation, suggested_fix, ai_generated=True   # no status field
class ManualAnswer: rule_id, answer: yes | no | not_sure
class ScanResult: scan_id, packs, rule_results[], flow_graph, scores, risk_level,
                  coverage, diff_vs_previous | None, disclaimer
```

Pack YAML follows the schema in the brief, plus:
- `detector_params:` (optional dict, e.g. `{min_days: 180}`) so one check can be reused across packs
- `applies_when:` (optional) e.g. "only if any PII sink found" → otherwise `not_assessable`

---

## 4. Rules per pack (initial list)

All references below will be entered with `reference_verified: false` unless I'm confident, and **every** one gets listed in `docs/LEGAL_REVIEW_TODO.md` for you to confirm anyway. I will not invent section numbers; where I don't know the exact DPDP Rules 2025 rule number I'll write the Act section only and flag it.

**DPDP Act 2023 + Rules 2025 (~14 rules)** — notice/consent fields at collection (hybrid → needs_review), purpose recorded, minimisation (unused PII fields collected), security safeguards (PII→LLM unredacted, PII in logs, plaintext passwords), erasure handler covers all PII stores, no TTL/retention on PII stores, breach-readiness (manual), children's data/age-gating (hybrid), processor contracts (manual), grievance/contact person (manual), cross-border transfer (manual).

**IT Act 43A + SPDI Rules 2011 (~9)** — SPDI (passwords, financial, biometric) stored unhashed/unencrypted, reasonable security practices (secrets, TLS, debug), privacy policy published (manual), consent for SPDI collection (hybrid), disclosure to third parties (HTTP/LLM sinks), ISO 27001-or-equivalent (manual).

**CERT-In Directions, 28 Apr 2022 (~8)** — logging configured, log retention ≥ 180 days in config, logs stored in India (manual), NTP/time sync configured (config check where visible, else manual), incident reporting within 6 h process (manual), point of contact (manual).

**GDPR subset (~10)** — Art. 17 erasure coverage, Art. 5(1)(c) minimisation, Art. 5(1)(e) storage limitation (TTL), Art. 32 security, Art. 25 by design (PII→LLM unredacted), Art. 44+ international transfers via third-party APIs (hybrid), Art. 28 processor agreements (manual), Art. 33 breach 72 h (manual), Art. 30 records (manual), Art. 37 DPO (manual).

**Security baseline (OWASP-style, ~10)** — hardcoded secrets, committed `.env`, plaintext passwords, weak hashing (md5/sha1 for passwords), SQL via string concat/f-string, debug on, CORS `*`, `http://` external calls, `verify=False` on requests, missing auth on delete endpoints (heuristic → needs_review).

Each automated rule ships with ≥1 passing + ≥1 failing test fixture.

---

## 5. Milestones (commit after each)

| # | Milestone | Done when |
|---|---|---|
| 1 | Skeleton: pyproject, FastAPI `/health`, pack schema + loader, CLI stub, docker-compose (api, postgres+pgvector, redis, frontend), `.env.example` | `pytest` green, `privtrace packs list` works, `docker compose up` serves `/health` |
| 2 | Detectors: PII names, Indian IDs w/ Verhoeff/Luhn, generic PII, secrets + redaction utility | detector tests pass (pass+fail case each) |
| 3 | Python AST parser, sink detection, intra-file taint + import following, DataFlowGraph | flow tests on small fixtures |
| 4 | Rule engine, DPDP + Security packs, manual answers, scoring (+ `docs/SCORING.md`) | rule tests pass, scores match hand-computed examples |
| 5 | Reports: JSON, Jinja HTML, rich CLI output, rescan diff | `privtrace scan … --out report.html` works |
| 6 | Gemini gateway: classification, explanations, fix suggestions, structured output, graceful fallback | payload-inspection test proves no raw PII sent |
| 7 | Frontend: connect → packs → checklist → progress → report | flow works in browser against local API |
| 8 | IT Act/SPDI, CERT-In, GDPR packs + `LEGAL_REVIEW_TODO.md` | all packs load + tested |
| 9 | `demo-app`, `demo-app-fixed`, end-to-end test (score improves) | E2E test green; README quickstart |
| 10 | Stretch: Verify module (canary deletion test across Postgres/pgvector/Redis/logs) | PASS/FAIL per store |

Docs (`ARCHITECTURE.md`, `DEPLOY_GCP.md`, `ADDING_A_PACK.md`, `DETECTION_LIMITS.md`) are written alongside the milestone they describe.

---

## 6. Known limits (will be documented)

- Python only for the MVP; JS/TS parser slot exists but is empty.
- Taint tracking is intra-file plus direct imports; no full interprocedural or dynamic-dispatch analysis. Flows through `**kwargs`, `getattr`, or ORMs configured by strings may be missed.
- "Consent/notice" and "minimisation" are heuristics → they produce `needs_review`, never `failed`.
- Scores measure engineering evidence, not legal compliance.

---

## 7. Questions for you

1. **"TAD"** — which framework did you mean? I'll add a placeholder in `packs/README.md` until you tell me. (Guesses, none of which I'll assume: a sectoral guideline such as RBI/SEBI/IRDAI data rules, or something else entirely.)
2. **Git repo location.** The current git repository root is your whole home folder (`C:\Users\DHWANI`), not this project. I'd like to run `git init` **inside `PrivTrace/`** so commits only contain project files. OK?
3. **Package layout.** OK to use `backend/privtrace/` (installable package, CLI = `privtrace`) instead of `backend/app/` + separate `cli/`?
4. **Packs location.** OK to keep pack YAMLs at repo-root `packs/` (data) rather than inside the backend package?
5. **Gemini.** Do you have a `GEMINI_API_KEY` to test with? I'll make every AI feature optional so tests and the demo run without one. Any preferred default for `GEMINI_MODEL` in `.env.example`, or leave it blank for you to fill?
6. **Background jobs.** For the MVP I plan FastAPI background tasks + Redis for progress (no separate worker queue), with the scan function also runnable as a Cloud Run Job. Fine, or do you want a real queue (RQ/Celery) now?
7. **demo-app-fixed** as a sibling folder (not a git branch) — simpler for the demo. OK?
8. **Local Python** is 3.13.5 (brief says 3.11+); Docker images will use 3.12-slim. OK?

Reply with "OK" (plus any answers/changes) and I'll start Milestone 1.
