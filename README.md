# PrivTrace

**Multi-framework compliance scanner for codebases.** PrivTrace scans your code against the compliance packs you pick (India's DPDP Act 2023, IT Act/SPDI Rules, CERT-In Directions, a GDPR subset, an OWASP-style security baseline), traces where personal data flows (DB, logs, LLM prompts, vector stores, caches, third-party APIs), and produces a scored report with file:line evidence and concrete fixes.

> PrivTrace findings are engineering evidence, **not legal advice**. Rule results are "passed / failed / needs review", never a legal verdict.

## Quickstart

```bash
cp .env.example .env            # optionally add GEMINI_API_KEY + GEMINI_MODEL
docker compose up --build       # UI on http://localhost:5173, API on :8000
open http://localhost:5173      # connect a repo -> pick frameworks -> checklist -> report
```

### Local development (no Docker)

```bash
cd backend
python -m venv .venv && .venv/Scripts/activate   # or source .venv/bin/activate
pip install -e ".[dev]"
pytest
privtrace packs list
privtrace scan ./some-repo --packs dpdp,security --out report.html --out report.json
uvicorn privtrace.api.main:app --reload       # API for the UI

cd ../frontend && npm install && npm run dev   # UI on :5173, proxies /api to :8000
```

Ports clash? Set `PRIVTRACE_API_PORT` / `PRIVTRACE_UI_PORT` in `.env`.

## Build status

Built milestone by milestone (see [PLAN.md](PLAN.md)).

| # | Milestone | Status |
|---|---|---|
| 1 | Skeleton: FastAPI health, pack schema + loader, CLI stub, docker-compose | ✅ |
| 2 | Detectors: PII names, Indian IDs (Verhoeff, Luhn, GSTIN), secrets, redaction | ✅ |
| 3 | AST parsing, sinks, taint flow (cross-file), data-flow map | ✅ |
| 4 | Rule engine, DPDP + Security packs, manual checklist, scoring | ✅ |
| 5 | HTML/JSON reports, fix diffs, rescan diff, CLI output | ✅ |
| 6 | Gemini: classification, explanations, fixes (structured output, redacted) | ✅ |
| 7 | Scan API + React UI: connect → packs → checklist → progress → report | ✅ |
| 8 | IT Act/SPDI, CERT-In, GDPR packs | ✅ |
| 9 | Demo app + fixed version + E2E | ⏳ |
| 10 | Stretch: Verify (canary deletion test) | ⏳ |

## Repo layout

```
backend/privtrace/   scanner, rule engine, AI gateway, reports, API, CLI
packs/               compliance packs (YAML data)
frontend/            React + Vite + TS + Tailwind UI
demo-app/            deliberately non-compliant RAG chatbot (fake data only)
demo-app-fixed/      the same app with fixes applied
docs/                architecture, scoring, legal review TODO, deploy guide
```
