# Build PrivTrace — multi-framework compliance scanner for codebases

You are helping me build **PrivTrace**, a developer tool that scans a company's codebase against the compliance frameworks the company selects (India's DPDP Act, IT Act, CERT-In, GDPR and so on). It then produces a report showing how exposed the code is and exactly what to fix. This is for a hackathon (Startup Buildathon India 2026, Google track), so it must be a **working, demo-able MVP**. Correctness and a clean demo matter more than breadth.

**Before writing code:** read this whole brief, then write `PLAN.md` with your architecture, folder structure, milestones and any questions. Stop and wait for my OK. After that, build milestone by milestone and commit after each one.

---

## 1. What the product does (user flow)

1. **Connect code.** The user gives a public GitHub URL, uploads a ZIP, or points the CLI at a local folder.
2. **Pick frameworks.** The user sees a list of compliance packs (DPDP, IT Act/SPDI, CERT-In, GDPR, OWASP security baseline, …) and selects one or more. Each pack shows its name, jurisdiction, version and how many rules are automated vs manual.
3. **Answer the manual checklist.** Some obligations can't be seen in code ("Do you have a Data Protection Officer?", "Do you have a signed processor agreement with your LLM vendor?"). For the selected packs, the tool shows these as a short yes / no / not-sure questionnaire. The answers feed the score.
4. **Scan.** The tool parses the code, detects personal data and where it flows (DB, logs, LLM prompts, vector store, cache, third-party APIs), and runs every automated rule in the selected packs.
5. **Report.** The output has:
   - An overall exposure score, plus a score per framework (0–100, higher = more compliant)
   - Findings grouped by framework → rule, each with severity, file:line, a redacted evidence snippet, the legal reference, why it matters in plain language, and a concrete fix (suggested code diff where possible)
   - A coverage line per framework: "X of Y rules checked automatically, Z answered manually, W not assessable from code"
   - The data-flow map (sources → code paths → stores/sinks)
   - Export as HTML and JSON (PDF is a stretch goal)
6. **Rescan after fixes.** The score updates, and the report shows what changed since the last scan.

## 2. Hard rules (do not break these)

- **Never invent legal citations.** Every rule in a pack must have a `reference` field (act, section/rule number) and a `source_url` to the official text. If you are not certain of a section number, set `reference_verified: false` and add it to `docs/LEGAL_REVIEW_TODO.md`. Do not guess. I will verify these myself.
- **Findings are engineering evidence, not legal advice.** Every report must carry that disclaimer. Never output "compliant" or "non-compliant" as a legal verdict. Use "rule passed / failed / needs review".
- **Deterministic first, AI second.** Rule results come from deterministic checks (AST, regex, config parsing). Gemini only does three things: (a) classify ambiguous fields as personal data or not, (b) explain findings in plain language, (c) suggest fixes. Gemini output can never flip a rule from fail to pass.
- **Protect customer code.**
  - Before anything goes to Gemini, redact detected identifiers (Aadhaar, PAN, emails, phones, secrets) and send only small snippets (≤ 40 lines), never whole files or repos.
  - Delete uploaded/cloned code after the scan finishes.
  - Never log raw snippets that contain PII.
- **No real personal data anywhere** in tests, fixtures or the demo app. Use obviously fake values, and make Aadhaar-like numbers pass Verhoeff only when a test needs it.

## 3. Tech stack

- **Backend:** Python 3.11+, FastAPI, Pydantic v2, SQLAlchemy 2, PostgreSQL 16 (+ pgvector for the demo app), Redis
- **Scanner:** Python's built-in `ast` for Python code (MVP language). Structure the parser layer so JS/TS can be added later via tree-sitter, but don't build JS/TS now.
- **AI:** Gemini API via the official `google-genai` Python SDK, using **structured output (JSON schema)** for every call. Put the model name in config (`GEMINI_MODEL`). Don't hardcode a model ID. Validate every response with Pydantic, and fall back gracefully if the call fails (the scan still completes without AI explanations).
- **CLI:** Typer (`privtrace scan ./repo --packs dpdp,certin --out report.html`)
- **Frontend:** React + Vite + TypeScript + Tailwind. Keep it simple: upload/connect → pick packs → checklist → progress → report.
- **Infra:** Docker + docker-compose for local. Write a deploy guide for Google Cloud Run (API) and Cloud Run Jobs (scans), with Cloud SQL and Memorystore. No need to deploy yet.
- **Tests:** pytest. Every detector and every automated rule needs at least one passing and one failing test case.

## 4. Compliance packs (the core of the product)

Packs are **data, not code**: one YAML file per framework in `packs/`, loaded at runtime, so new frameworks can be added without touching the engine.

### Pack schema (design it properly, something like):

```yaml
id: dpdp-2023
name: Digital Personal Data Protection Act, 2023 + DPDP Rules, 2025
jurisdiction: IN
version: "2025-11"
source_url: <official link>
rules:
  - id: DPDP-SEC-01
    title: Personal data sent to third-party AI without safeguards
    reference: "<Section/Rule number>"
    reference_verified: false
    source_url: <link>
    severity: high          # critical | high | medium | low
    check_type: automated   # automated | manual | hybrid
    detector: pii_to_llm_sink   # name of a registered check function, for automated
    question: null          # for manual: the yes/no question shown to the user
    why_it_matters: <plain-language explanation>
    remediation: <what to change>
    tags: [ai, third-party, security]
```

### Packs to ship in the MVP:

1. **DPDP Act 2023 + DPDP Rules 2025 (India)**: the most complete pack. It covers notice/consent capture, purpose limitation, data minimisation, security safeguards, erasure on withdrawal/request, retention limits, breach readiness, children's data, processors/third parties.
2. **IT Act 2000, Sec 43A + SPDI Rules 2011 (India)**: reasonable security practices, sensitive personal data handling.
3. **CERT-In Directions (April 2022, India)**: log retention and availability, time sync, incident reporting readiness. These are code/config checkable.
4. **GDPR (EU) subset**: the rules that overlap with code: erasure, minimisation, security, international transfers.
5. **Security baseline (OWASP-style)**: hardcoded secrets, plaintext passwords, missing TLS, debug mode on, SQL built by string concatenation.

> I also mentioned "TAD" as a framework. I'm not sure which act that is. Add a placeholder entry in `packs/README.md` and ask me in `PLAN.md`.

Aim for **8–15 well-built rules per pack** rather than many shallow ones. For each pack, include manual-checklist rules for obligations code can't show.

## 5. Scanner and detectors (automated checks)

Build a detector registry. Each detector returns findings with file, line, snippet (redacted), confidence and data category.

### Personal data detection
- **Field/variable names:** a dictionary of PII-ish names (email, phone, mobile, dob, address, aadhaar, pan, upi, ifsc, passport, ip_address, location…), plus Gemini classification for ambiguous names (`meta`, `ctx`, `payload`, `user_data`).
- **Pydantic/SQLAlchemy/dataclass models:** find PII-holding fields.
- **Indian identifier patterns in code, fixtures, configs and sample data:**
  - **Aadhaar:** 12 digits plus Verhoeff checksum validation
  - **PAN:** `[A-Z]{5}[0-9]{4}[A-Z]`
  - **UPI ID**
  - **IFSC**
  - **Indian mobile numbers**
  - **Passport, voter ID, GSTIN**
- **Email, phone, card numbers** (Luhn check), and secrets/API keys.

### Data-flow mapping (sources → sinks)
- **Sources:** request bodies, form models, function parameters carrying PII fields.
- **Sinks to detect:**
  - **DB writes:** SQLAlchemy, raw SQL
  - **Logging:** `logging`, `print`, structlog
  - **LLM SDK calls:** google-genai, openai, anthropic, langchain
  - **Embeddings / vector stores:** pgvector, Pinecone, Chroma, FAISS
  - **Cache:** redis
  - **HTTP calls to third parties:** requests, httpx
  - **File writes**
  - **Analytics SDKs**
- **Flow tracking:** a simple intra-file + import-following taint pass is enough for the MVP. Mark which sink each PII field reaches. Don't over-engineer full interprocedural analysis. Document the limits.

### Example automated rules to implement (map each to the right pack)
- PII or Indian identifiers flow into an LLM prompt without redaction
- PII written to logs
- Personal data stored in cache/vector store with no corresponding delete path
- The delete-user / erasure handler doesn't touch every store that holds that user's data (compare the data-flow map against what the delete function touches)
- No retention/TTL on stores holding personal data
- Passwords stored without hashing (bcrypt/argon2 not used)
- Secrets hardcoded in code or committed `.env`
- Debug mode enabled, CORS `*`, HTTP (not HTTPS) endpoints for external calls
- Logging config missing, or retention set below what CERT-In requires (check the exact requirement and cite it)
- No consent/notice field captured where personal data is collected (heuristic: signup models without consent/purpose fields → "needs review", not "fail")

## 6. Scoring

- Each rule has a severity weight: critical 10, high 6, medium 3, low 1.
- **Per framework:** `score = 100 × (weight of passed rules) / (weight of all assessed rules)`, where:
  - Manual "yes" = passed
  - "no" = failed
  - "not sure" = needs review, excluded from the score but listed
  - Rules that couldn't be assessed are excluded and shown in coverage
- **Overall score:** weighted average across the selected frameworks.
- Also show a **risk level** (Low / Medium / High / Critical), based on the highest-severity failed rule.
- Put the formula in `docs/SCORING.md` and show it in the report footer, so judges and users can see how it's calculated.

## 7. The report

- An **HTML report** (Jinja2 template, clean and printable), the same view in the React UI, and **JSON** for CI.
- **Sections:**
  1. Summary: score gauges per framework, risk level, top 5 fixes
  2. Data-flow map: a simple graph of sources → code paths → stores/sinks, with risky edges highlighted
  3. Findings by framework → rule: severity, location, redacted evidence, reference + link, why it matters, how to fix, suggested diff
  4. Manual checklist answers
  5. Coverage and limitations
  6. Disclaimer
- **Fix suggestions:** where possible, a unified diff generated by rule templates first. Use Gemini only if no template fits, and label those clearly as "AI-suggested, review before applying".

## 8. Demo app (needed for the pitch)

Create `demo-app/`: a small FastAPI RAG chatbot that is deliberately non-compliant. It should:
- Have signup with name/email/phone/PAN
- Send chat messages containing PII straight into a Gemini prompt
- Log the full request body
- Store embeddings in pgvector and cache user profiles in Redis
- Have a `DELETE /users/{id}` endpoint that only deletes the Postgres row
- Contain a hardcoded API key and plaintext password storage

Include a `demo-app-fixed/` branch or folder with the fixes applied. The demo must show the score going from low to high after fixes.

**Stretch goal (only after everything above works):** a "Verify" module that spins up `demo-app` in docker-compose, creates a fake user with a unique canary value, calls the delete endpoint, then searches Postgres, pgvector, Redis and the logs for the canary, and reports PASS/FAIL per store. This is our strongest differentiator, so design the code so it can slot in.

## 9. Repo structure (suggested — improve it in PLAN.md if needed)

```
privtrace/
  backend/app/        api/, core/ (config, security), scanner/ (parsers, detectors, flow), rules/ (engine, registry), packs/ (yaml), ai/ (gemini client, prompts, schemas), report/ (scoring, templates), models/, db/
  cli/
  frontend/
  demo-app/  demo-app-fixed/
  tests/
  docs/  (ARCHITECTURE.md, SCORING.md, LEGAL_REVIEW_TODO.md, DEPLOY_GCP.md, ADDING_A_PACK.md)
  docker-compose.yml  .env.example  README.md
```

## 10. Milestones

1. Skeleton: repo, docker-compose, FastAPI health check, pack loader + schema validation, CLI stub
2. Detectors: PII names, Indian IDs with checksums, secrets, plus tests
3. AST parsing + sink detection + simple data-flow map
4. Rule engine + DPDP and Security packs (automated + manual rules) + scoring
5. Report: HTML + JSON + CLI output
6. Gemini integration: classification, explanations and fix suggestions, with structured output and redaction
7. Frontend: connect → pick packs → checklist → scan → report
8. Remaining packs (IT Act/SPDI, CERT-In, GDPR subset)
9. Demo app + fixed version + end-to-end test showing the score improve
10. Stretch: Verify (deletion test)

## 11. Done means

- `docker compose up` starts everything; the README has a 3-command quickstart
- `privtrace scan ./demo-app --packs dpdp,security` produces an HTML report with a low score and specific findings with file:line
- The same scan on `demo-app-fixed` scores clearly higher
- The UI flow works end to end in the browser
- All tests pass; each detector and automated rule has tests
- Every rule has a reference, and any unverified one appears in `LEGAL_REVIEW_TODO.md`
- No raw PII leaves the machine in Gemini calls (add a test that inspects the outgoing payload)

Keep code clean, typed and commented where it isn't obvious. When you're unsure about a legal requirement, don't guess. Flag it and move on.
