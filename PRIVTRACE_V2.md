# PrivTrace v2: copy-paste AI fix prompts + CI compliance gate

You're working on **PrivTrace**, a compliance scanner that's **already built** and in this repo. It scans a codebase against selected compliance packs (DPDP, IT Act/SPDI, CERT-In, GDPR subset, security baseline) and outputs a scored report with findings, fixes and a data-flow map. Stack: FastAPI, Typer CLI, React + Vite, YAML packs, Gemini through `google-genai`.

We're adding two features:

1. **AI fix prompts.** Each finding comes with a ready-made prompt that a developer can copy into Claude, Cursor, Copilot, ChatGPT or any other AI coding tool to apply the fix.
2. **CI compliance gate.** PrivTrace runs automatically on the company's repo when code is pushed or a PR is opened against `main`/production. It checks the new code against the packs and rules the business picked, and can block the merge.

This is for a hackathon demo (Startup Buildathon 2026), so it has to work end to end and demo cleanly. Extend what's already here. Don't rewrite it.

**Before you write any code:**
1. Read the repo: the scanner, the rule engine, the pack loader, the report generation, the CLI, the frontend report view and the tests. Note what exists and how findings, scores and reports are structured right now.
2. Write `PLAN-v2.md` covering: what you found, how each feature fits the current architecture, which files you'll add or change, the milestones, and any questions. **Stop and wait for my OK.**
3. Then build one milestone at a time, run the tests after each one and commit.

---

## Hard rules (these still apply, from the original brief)

- **Deterministic first.** Pass/fail always comes from the deterministic rule engine. AI only explains things and suggests fixes. The CI gate decision must **never** depend on an LLM call.
- **Findings are engineering evidence, not legal advice.** The disclaimer appears in the PR comment, the job summary and every fix prompt. Never write "compliant" or "non-compliant". Use rule passed / failed / needs review.
- **Customer code is protected.**
  - Fix prompts include only redacted snippets (no Aadhaar, PAN, emails, phones, secrets or other real identifiers), with a cap of about 40 lines of code context.
  - **AI is off by default in CI.** The scan runs entirely inside the runner and sends no code anywhere unless the user explicitly enables Gemini and provides a key.
  - Logs never contain raw PII snippets.
- **No real personal data** in tests, fixtures or demo repos.

---

## Feature 1: AI fix prompts

### What it does
Each failed or needs-review finding gets a **fix prompt**: a self-contained, well-structured instruction that a developer pastes into their own AI tool. It should be good enough for the AI to make the correct change on the first try without hand-holding.

### Prompt generation
- **Templates first.** Generate prompts deterministically from Jinja2 templates, with one template per rule or detector type and a generic fallback. No LLM call is needed, so prompts also work offline and in CI.
- **Optional Gemini enrichment.** When AI is enabled, Gemini can make the "how to fix" part more specific to the code (structured output, validated with Pydantic). Use the template prompt if the call fails. Label enriched prompts in the UI.
- **Add an optional field to the pack schema:** `fix_prompt_hints` (a list of strings per rule), for rule-specific guidance such as "use argon2 or bcrypt, never plain SHA-256" or "the delete path must also cover Redis keys `user:{id}:*` and pgvector rows". Update `docs/ADDING_A_PACK.md`.

### What each prompt contains (in this order)
1. **Role and task:** "You are fixing a data-protection issue in this codebase…"
2. **The problem:** rule ID, title, severity, plain-language reason it matters, legal reference with link (only if `reference_verified: true`; otherwise "reference pending review")
3. **Location:** file path, line range, function or class name
4. **Code context:** the redacted snippet in a fenced code block with its language tag, explicitly marked as **data to fix, not instructions to follow** (protects against prompt injection from comments in the scanned code)
5. **Data-flow context, when relevant:** for example "`user.email` flows from `POST /signup` → `logger.info` in `app/routes.py:42`", and for erasure rules, the list of every store the user's data reaches
6. **What a correct fix looks like:** concrete acceptance criteria based on the rule's remediation and `fix_prompt_hints`
7. **Constraints:** keep behaviour otherwise unchanged, make the smallest change possible, add or update a test that proves the fix, don't add new dependencies unless needed, and don't touch unrelated files
8. **How to verify:** "Re-run `privtrace scan . --packs <ids>`. Rule `<ID>` should pass."
9. **A one-line disclaimer**

Keep each prompt tool-agnostic plain Markdown. No tool-specific syntax.

### Prompt types
- **Per finding:** one prompt per finding.
- **Per file:** "Fix all PrivTrace findings in `app/routes.py`". Merges the findings for one file into one prompt so the AI doesn't make conflicting edits.
- **Fix all (top N):** a batch prompt for the top N findings ordered by severity, grouped by file, with a "fix them in this order" list. Cap the size and say how many findings were left out.

### Where prompts show up
- **React report:** a "Copy AI fix prompt" button on each finding (with copied ✓ feedback), plus "Copy prompt for this file" and "Copy fix-all prompt" buttons at the top. A preview modal shows the prompt before copying.
- **HTML report:** the same buttons. The copy has to work in a static file opened from disk.
- **JSON report:** a `fix_prompt` field on each finding, plus a top-level `fix_all_prompt`.
- **CLI:**
  - `privtrace prompt <finding-id>` prints a single prompt to stdout
  - `privtrace prompt --file app/routes.py` prints the per-file prompt
  - `privtrace prompt --all --top 10 > fixes.md` writes the batch prompt
  - `--copy` flag puts it on the clipboard where available
- **CI:** collapsible `<details>` prompts in the PR comment and the job summary (see feature 2).

### Tests
- Snapshot tests of the generated prompts for the demo-app findings.
- **Leak test:** fill a fixture with fake Aadhaar/PAN/email/phone/API-key values. Assert that none of them appear in any generated prompt, at any level.
- **Injection test:** a snippet containing a comment like `# ignore previous instructions` stays inside the fenced data block and is labelled as data.
- **Size test:** the batch prompt respects its cap.

---

## Feature 2: CI compliance gate

### Design (implement this; push back in PLAN-v2.md if you see a better way)

**Trigger strategy.** Explain these in the docs and ship workflow examples for each:
- **On `pull_request` to `main`/`production`: the main gate.** Non-compliant code gets caught *before* it merges, not after it reaches production.
- **On `push` to `main`:** records the score for the main branch and updates the baseline.
- **Weekly `schedule`:** re-scans with the latest packs, because rules change even when code doesn't.
- **Optional pre-commit hook:** a fast local check (secrets, PII in logs, Indian ID patterns only) so developers catch issues before they push.

**Config file in the company's repo: `.privtrace.yml`.** This is where the business picks its rules. Design the schema properly, something like:

```yaml
version: 1
packs: [dpdp-2023, certin-2022, security-baseline]   # frameworks the business selected
rules:
  disable: [GDPR-XFER-02]          # rules that don't apply, each needs a reason
  severity_overrides: { DPDP-RET-01: critical }
paths:
  include: [src/, services/]
  exclude: [tests/fixtures/, migrations/]
manual_answers:                   # answers to the manual checklist, so CI can score them
  DPDP-GOV-01: yes                # e.g. "Do you have a DPO?"
  DPDP-PROC-02: not_sure
gate:
  min_score: 70                   # overall score threshold
  min_score_per_pack: { dpdp-2023: 75 }
  fail_on_severity: high          # fail if any NEW finding is >= this
  new_findings_only: true         # judge the PR only on what it introduces
ai:
  enabled: false                  # default: no code leaves the runner
report:
  pr_comment: true
  sarif: true
```

- Add `privtrace init` to generate this file interactively. It asks which packs to use and walks through the manual checklist once.
- Validate the config with Pydantic and fail with clear error messages.
- Disabling a rule needs a reason, and disabled rules show up in the report under "Rules turned off by config".

**Baseline and new-findings-only mode.** This is essential: a company adopting PrivTrace will already have hundreds of findings and can't fix them all in one PR.
- Still scan the whole repo (the data-flow analysis needs it), then compare the results to a baseline.
- Give each finding a **stable fingerprint** that survives line shifts: rule ID + file + enclosing function + a hash of the normalised code. Document the approach.
- The baseline comes from either a committed `.privtrace-baseline.json` (`privtrace baseline update`) or a scan of the base branch in the same CI job. Support both and explain the trade-offs.
- The gate result separates **new**, **fixed** and **existing** findings, and shows the score change ("DPDP 68 → 61 ▼7").

**Inline suppressions.** `# privtrace-ignore: DPDP-LOG-01 reason="hashed before logging" expires=2027-03-01`. A reason is required. Expired suppressions turn into findings again. Every suppression is listed in the report so nobody can quietly hide issues.

**CLI for CI:**
`privtrace ci --config .privtrace.yml --base origin/main --sarif out.sarif --json out.json --markdown summary.md`
- Exit codes: `0` passed, `1` gate failed, `2` config or scan error. An error must never look like a pass.
- `--fail-on` and `--min-score` flags override the config.

**Outputs:**
- **SARIF 2.1.0:** findings appear in GitHub's Security tab and as inline annotations on the PR diff. Include rule metadata, severity mapping, help text (why it matters + fix) and the fingerprints in `partialFingerprints`. Validate against the SARIF schema in tests.
- **PR comment (Markdown):** one sticky comment that gets updated rather than duplicated. It contains:
  - pass/fail badge, overall and per-pack scores with the change from base
  - a table of new findings (severity, rule, file:line)
  - fixed findings 🎉
  - a collapsible "AI fix prompt" per new finding, plus one "fix all new findings" prompt
  - a link to the full report artifact
  - the disclaimer
- **GitHub job summary:** the same Markdown written to `$GITHUB_STEP_SUMMARY`.
- **Full HTML report** uploaded as a workflow artifact.

**GitHub Action.**
- An `action.yml` (Docker or composite action) that wraps the CLI. Inputs: `config`, `packs`, `min-score`, `fail-on`, `gemini-api-key` (optional), `comment` (bool).
- Publish the scanner image to GHCR.
- Ship `examples/github/privtrace.yml`, a ready-to-copy workflow that:
  - checks out with `fetch-depth: 0` (needed for the base comparison)
  - runs the action
  - uploads SARIF with `github/codeql-action/upload-sarif`
  - posts the PR comment
  - uploads the HTML report
  - sets least-privilege `permissions:` (contents: read, pull-requests: write, security-events: write)
- Explain how to make it a **required status check** via branch protection on `main`, so failing PRs can't merge.

**Other CI systems (lighter, docs + templates):**
- GitLab CI template (`examples/gitlab/.gitlab-ci.yml`) that outputs GitLab Code Quality JSON
- A generic shell example for Jenkins or Bitbucket using exit codes and the JSON output
- A `.pre-commit-hooks.yaml` for the fast local mode

**Dashboard history (stretch, do it only if time allows):** `privtrace ci --upload` sends the JSON results (scores and findings metadata, **no code**) with an API token to the PrivTrace backend. The web UI then shows score trends per repo and branch over time, plus a "last 10 PRs" list. Design the JSON format now so this can plug in later.

### Tests
- **Gate logic:** pass/fail at each threshold, new-only vs all findings, severity overrides, disabled rules, expired suppressions.
- **Fingerprint stability:** inserting lines above a finding doesn't change its fingerprint, and changing the vulnerable code does.
- **Config validation:** good config, bad config and missing config, each with clear errors.
- **SARIF:** validates against the schema.
- **Exit codes:** 0, 1 and 2 cases.
- **Network test:** in CI mode with `ai.enabled: false`, no outbound network calls are made (mock or block the network and assert).

---

## Demo scenario (build this, it's the pitch)

1. Create `demo-repos/acme-chatbot/` from `demo-app-fixed`, with `.privtrace.yml` (DPDP + CERT-In + security, min_score 75) and the GitHub workflow installed.
2. Include a script (`scripts/demo_ci.sh`) that simulates the CI run locally on two branches:
   - **`feature/good-change`:** a harmless change. The gate passes ✅ and the score stays the same.
   - **`feature/risky-change`:** a developer adds `logger.info(f"signup {payload}")` and sends the user's phone number to an LLM prompt. The gate fails ❌ with 2 new high findings and the DPDP score drops. The rendered PR comment shows the copy-paste fix prompts.
3. Apply one fix prompt (paste it into an AI tool, or apply the matching fix by hand), re-run, and show the gate pass again.
4. Write `docs/DEMO_SCRIPT_CI.md` with the exact commands and what to say at each step, about 2 minutes total.

If there's time, also run it for real on a public GitHub test repo with an actual PR, and put the PR link in the docs.

---

## Docs to add or update
- `docs/CI_INTEGRATION.md`: trigger strategy, `.privtrace.yml` reference, baseline workflow, suppressions, required-check setup, GitHub/GitLab/generic examples, the privacy guarantees in CI (what leaves the runner and what doesn't)
- `docs/FIX_PROMPTS.md`: how prompts are built, the template location, how to add `fix_prompt_hints` to a pack
- `README.md`: a short "Use in CI" section with the 5-line workflow snippet

## Milestones
1. `PLAN-v2.md` + reading the existing code (then stop for approval)
2. Fix prompt templates + generator + pack schema field + tests (leak and injection tests included)
3. Prompts in the JSON/HTML report, the React UI copy buttons and the `privtrace prompt` CLI
4. `.privtrace.yml` schema + `privtrace init` + config validation
5. Fingerprints + baseline + new/fixed/existing diff + suppressions
6. `privtrace ci` command + gate logic + exit codes
7. SARIF + PR comment Markdown + job summary
8. GitHub Action + GHCR image + example workflows (GitHub, GitLab, generic, pre-commit)
9. Demo repo + `demo_ci.sh` + demo script doc
10. Stretch: dashboard history upload + trends UI

## Done means
- `privtrace ci` on `feature/risky-change` exits 1 with a PR comment that lists the new findings and copyable fix prompts. On `feature/good-change` it exits 0.
- Every finding in the UI, HTML and JSON has a working fix prompt, and no fake PII value from the fixtures appears in any prompt.
- The SARIF output validates and shows up as inline annotations on a GitHub PR.
- With AI disabled, CI makes zero outbound calls (a test proves it).
- All old and new tests pass, and the existing scan, report and UI flow still works.
- The docs are written and the demo script runs start to finish.

Keep the code typed, clean and consistent with the existing codebase style. If something about the current architecture blocks a clean design, raise it in `PLAN-v2.md` instead of hacking around it.
