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

## Demo

```bash
cd backend
privtrace scan ../demo-app       --packs dpdp,security --out demo.html  --out demo.json
privtrace scan ../demo-app-fixed --packs dpdp,security --out fixed.html --baseline demo.json
```

`demo-app` (a deliberately non-compliant FastAPI RAG chatbot) scores **6/100, risk Critical**: PII in Gemini prompts, request bodies logged, plaintext passwords, a delete endpoint that misses pgvector and Redis, a hardcoded key and more — each with file:line evidence and a suggested diff. `demo-app-fixed` scores **100/100 on automated checks, risk Low**, and the report lists what was fixed. Organisational checklist items stay "needs review" until answered.

### Verify: prove deletion actually works (runtime)

Static analysis says `DELETE /users/{id}` misses stores; **Verify** proves it. It signs up a fake user carrying a unique canary value, chats so the data spreads, calls the delete endpoint, then searches Postgres (incl. pgvector tables), Redis and the logs for the canary.

```bash
docker compose -f demo/docker-compose.yml up -d --build    # both demo apps, offline (no Gemini calls)
cd backend
privtrace verify --config ../demo/verify-demo-app.yaml        # FAIL: memories, redis profile, logs keep the canary
privtrace verify --config ../demo/verify-demo-app-fixed.yaml  # PASS on every store
```

| Store | demo-app | demo-app-fixed |
|---|---|---|
| Postgres + pgvector | ❌ FAIL — `memories.content` still holds it | ✅ PASS |
| Redis | ❌ FAIL — `profile:<id>` still cached | ✅ PASS |
| Logs | ❌ FAIL — request bodies logged | ✅ PASS (never logged) |

Only run Verify against local/test deployments you own: it writes test data.

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
| 9 | Demo app (score 6) + fixed version (score 100) + E2E test | ✅ |
| 10 | Stretch: Verify (canary deletion test across Postgres/pgvector, Redis, logs) | ✅ |

## Repo layout

```
backend/privtrace/   scanner, rule engine, AI gateway, reports, API, CLI
packs/               compliance packs (YAML data)
frontend/            React + Vite + TS + Tailwind UI
demo-app/            deliberately non-compliant RAG chatbot (fake data only)
demo-app-fixed/      the same app with fixes applied
demo/                docker-compose + Verify configs for the demo apps
docs/                ARCHITECTURE, SCORING, LEGAL_REVIEW_TODO, DEPLOY_GCP, ADDING_A_PACK, DETECTION_LIMITS
```
