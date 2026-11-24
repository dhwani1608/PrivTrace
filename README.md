# PrivTrace

**Multi-framework compliance scanner for codebases.** PrivTrace scans your code against the compliance packs you pick (India's DPDP Act 2023, IT Act/SPDI Rules, CERT-In Directions, a GDPR subset, an OWASP-style security baseline), traces where personal data flows (DB, logs, LLM prompts, vector stores, caches, third-party APIs), and produces a scored report with file:line evidence and concrete fixes.

**Live app:** [privtrace-836138728232.asia-south1.run.app](https://privtrace-836138728232.asia-south1.run.app) · **CI demo:** [acme-chatbot-demo](https://github.com/dhwani1608/acme-chatbot-demo) (a PR blocked by the gate, with fix prompts)

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
privtrace scan ./some-repo --packs dpdp,security --out report.html --out report.pdf --out report.json
uvicorn privtrace.api.main:app --reload       # API for the UI

cd ../frontend && npm install && npm run dev   # UI on :5173, proxies /api to :8000
```

Ports clash? Set `PRIVTRACE_API_PORT` / `PRIVTRACE_UI_PORT` in `.env`.

## Deploy (free, Render)

The root `Dockerfile` builds one image that serves the React UI and the API on a single port.

1. Sign in at [render.com](https://render.com) with GitHub.
2. **New → Blueprint** → choose this repo. Render reads `render.yaml`.
3. Optional: set `GEMINI_API_KEY` and `GEMINI_MODEL` in the service's Environment tab.
4. Deploy. The app is at `https://<service-name>.onrender.com`.

Free services sleep when idle (first request after that takes ~30–60 s) and scan history (SQLite in `/tmp`) resets on restart. Set `DATABASE_URL` to a Postgres URL to keep it.

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

## Use in CI

See it live: [acme-chatbot-demo](https://github.com/dhwani1608/acme-chatbot-demo): a harmless PR passes, [a PR that leaks PII](https://github.com/dhwani1608/acme-chatbot-demo/pull/2) is blocked, and [the fixed version](https://github.com/dhwani1608/acme-chatbot-demo/pull/3) passes.

Block pull requests that introduce personal-data problems, with a sticky PR comment that has a
copy-paste AI fix prompt for every new finding:

```yaml
- uses: actions/checkout@v4
  with: { fetch-depth: 0 }
- uses: dhwani1608/PrivTrace@main     # reads .privtrace.yml (create it with `privtrace init`)
- uses: github/codeql-action/upload-sarif@v3
  if: always()
  with: { sarif_file: privtrace-report/privtrace.sarif }
```

`privtrace ci --base origin/main` exits **0** (passed), **1** (gate failed) or **2** (config/scan
error). Pass/fail is deterministic; with AI off (the default) no code leaves the runner. Full
workflow: [`examples/github/privtrace.yml`](examples/github/privtrace.yml). Docs:
[CI integration](docs/CI_INTEGRATION.md) · [AI fix prompts](docs/FIX_PROMPTS.md) ·
[2-minute CI demo](docs/DEMO_SCRIPT_CI.md) (`bash scripts/demo_ci.sh`).

To track scores over time in the live app's **CI history** view, add `upload-url: https://privtrace-836138728232.asia-south1.run.app` and
`upload-token: ${{ secrets.PRIVTRACE_TOKEN }}` to the action (or pass `--upload` / `--token` to `privtrace ci`).

```bash
privtrace prompt DPDP-SEC-02            # AI fix prompt for one rule (or a finding id)
privtrace prompt --file app/main.py     # every finding in one file
privtrace prompt --all --top 10         # batch prompt, by severity
```

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
| v2 | AI fix prompts + CI compliance gate (see [PLAN-v2.md](PLAN-v2.md)) | ✅ |

## Repo layout

```
backend/privtrace/   scanner, rule engine, AI gateway, reports, API, CLI
packs/               compliance packs (YAML data)
frontend/            React + Vite + TS + Tailwind UI
demo-app/            deliberately non-compliant RAG chatbot (fake data only)
demo-app-fixed/      the same app with fixes applied
demo/                docker-compose + Verify configs for the demo apps
demo-repos/          acme-chatbot: CI demo repo (.privtrace.yml + workflow)
examples/            CI templates: GitHub Actions, GitLab, generic shell
scripts/             demo_ci.sh + the demo's change patches
action.yml           the GitHub Action (composite)
docs/                ARCHITECTURE, SCORING, LEGAL_REVIEW_TODO, DEPLOY_GCP, ADDING_A_PACK, DETECTION_LIMITS,
                     CI_INTEGRATION, FIX_PROMPTS, DEMO_SCRIPT_CI
```
