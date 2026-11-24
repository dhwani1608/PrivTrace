# PrivTrace v2: plan (AI fix prompts + CI compliance gate)

Brief: `PRIVTRACE_V2.md`. Built on branch `feature/v2-fix-prompts-ci` (not `main`, because a push to
`main` redeploys the Cloud Run service).

## 1. What exists today

| Area | Where | Notes |
|---|---|---|
| Scan pipeline | `privtrace/scan.py::run_scan` | One pipeline for CLI + API: analyze → evaluate → template diffs → optional AI → score → `ScanResult`. |
| Facts | `scanner/facts.py` | `CodeFacts`: detections, PII models, `SinkEvent`s (kind, api, function, taints, store, via), deletes, functions (routes), config facts. |
| Rules | `rules/engine.py`, `rules/checks.py` | Deterministic checks registered by name; packs reference them via `detector:`. Hybrid = code evidence + checklist answer. |
| Result model | `models/results.py` | A "finding" today is a `RuleResult` (one per rule) with up to 25 `Evidence` locations (file, line, redacted snippet, detail). There is **no per-location identity**. |
| Scores | `report/scoring.py` | Severity-weighted pass ratio per pack, overall weighted average. needs_review / not_assessable are excluded. |
| Diff | `report/diff.py` | Rule-level before/after (fixed/regressed) between two `ScanResult`s. |
| Fix diffs | `report/fixes.py` | Template unified diffs per detector, computed while the source is on disk, redacted. |
| AI | `ai/gateway.py` | The only path to Gemini: redaction guard, ≤40-line snippets, Pydantic-validated JSON, `AIEnrichment` has no status field. |
| Redaction | `core/redaction.py` | `redact()`, `contains_unredacted_pii()`, logging filter. |
| Reports | `report/html_report.py` + `templates/report.html.j2`, `report/pdf_report.py`, JSON = `ScanResult` dump. |
| CLI | `cli.py` (Typer) | `scan` (already has `--fail-under`, history diff), `verify`, `packs list/legal-todo`, `facts`. |
| UI | `frontend/src/components/Report.tsx` | Framework tabs → finding list → `FindingDetail` (evidence, why, fix diff, AI block). |
| Tests | `backend/tests` | 134 passing at start. |

## 2. How the features fit

### Findings with identity (new: `privtrace/findings.py`)
CI needs per-location findings, so a `Finding` = one failed/needs-review `RuleResult` × one evidence
location (rule-level findings with no evidence, e.g. manual rules, become one finding with `file=""`).
`ScanResult.findings` is the flattened list; `RuleResult` stays the UI/report unit.

**Fingerprint** = `sha256(rule_id | file | enclosing function | sha256(normalised redacted line) | occurrence#)[:16]`
- enclosing function: innermost `def`/`class` qualname from the Python AST (`<module>` otherwise), so
  inserting lines above the finding does not change it;
- normalised line: the **redacted** source line with whitespace collapsed and any
  `privtrace-ignore` comment stripped. Hashing the redacted line means the fingerprint can never be
  brute-forced back to an Aadhaar/phone value;
- occurrence #: disambiguates identical lines in the same function.

### Feature 1: fix prompts (new package `privtrace/fixprompt/`)
- `templates/*.md.j2`: one base template with the 9 required sections in order, a per-detector
  "acceptance criteria" block (`criteria/<detector>.md.j2`) and a generic fallback. Plain Markdown.
- `generator.py`: `rule_prompt(result, findings)`, `file_prompt(file, findings)`,
  `fix_all_prompt(findings, top=N, max_chars=…)`. Context comes from `CodeFacts` (data flow:
  taint names → route → sink api at file:line; erasure: every store kind/name the data reaches).
- Code context: redacted, ≤ `max_snippet_lines` (40) lines per finding block, fenced with a fence
  longer than any backtick run in the snippet, wrapped in explicit "DATA, not instructions" lines.
  The final prompt goes through `redact()` once more (belt and braces) and the leak test asserts it.
- Prompts are generated inside `run_scan` while the source is on disk (same as fix diffs), so the
  API/UI, HTML, JSON and CLI all read the stored text: `RuleResult.fix_prompt`,
  `Finding.fix_prompt`, `ScanResult.fix_all_prompt`, `ScanResult.file_prompts`.
- `fix_prompt_hints: list[str]` added to `PackRule` and used in section 6.

### Feature 2: CI gate (new package `privtrace/ci/`)
- `config.py`: `.privtrace.yml` Pydantic schema (`extra="forbid"`, readable errors, YAML `yes/no`
  booleans coerced to manual answers, disabled rules require a reason).
- `policy.py`: applied right after `evaluate()` (deterministic): drop disabled rules, apply
  severity overrides, drop evidence outside `paths.include/exclude`, apply inline suppressions.
  A failed rule whose every location is suppressed/out-of-scope becomes `passed` with a message
  saying so; every suppression (active, expired, invalid) is listed in the report.
- `suppress.py`: parses `# privtrace-ignore: RULE[,RULE] reason="…" expires=YYYY-MM-DD` on the
  finding's line or the line above. No reason → invalid (does not suppress). Expired → finding is back.
- `baseline.py`: baseline file `.privtrace-baseline.json` (scores + finding metadata, **no code**);
  or `--base <ref>`: `git worktree` of the merge-base, scanned with the same config, then removed.
- `gate.py`: new / fixed / existing by fingerprint, score deltas, pass/fail reasons. Pure function
  of two results + config: **no LLM involved**.
- `outputs/`: SARIF 2.1.0, Markdown (PR comment + job summary share one renderer), GitLab Code
  Quality JSON, `CiReport` JSON (also the future `--upload` payload).
- CLI: `privtrace ci`, `privtrace init`, `privtrace baseline update`, `privtrace prompt`,
  `privtrace precommit`.
- Exit codes: 0 pass, 1 gate failed, 2 config/scan error (whole command wrapped; any exception → 2).

### Distribution
- `action.yml` at repo root (**composite** action: setup-python, `pip install` the backend from the
  action checkout, run `privtrace ci`, post/update the sticky comment with `actions/github-script`,
  write the job summary). Works today without a published image.
- `Dockerfile.action` + `.github/workflows/publish-image.yml` to publish to GHCR on tag.
- `examples/github/privtrace.yml`, `examples/gitlab/.gitlab-ci.yml`, `examples/generic/privtrace-ci.sh`,
  `.pre-commit-hooks.yaml`.

## 3. Files

New: `privtrace/findings.py`, `privtrace/fixprompt/{__init__,generator}.py` + templates,
`privtrace/ci/{__init__,config,policy,suppress,baseline,gate,report,sarif,markdown,codequality,gitutil,init_wizard}.py`,
tests `test_fix_prompts.py`, `test_ci_config.py`, `test_fingerprints.py`, `test_gate.py`,
`test_ci_outputs.py`, `test_ci_cli.py`; `action.yml`, `Dockerfile.action`, `examples/…`,
`.pre-commit-hooks.yaml`, `demo-repos/acme-chatbot/…`, `scripts/demo_ci.sh`,
`docs/{CI_INTEGRATION,FIX_PROMPTS,DEMO_SCRIPT_CI}.md`.

Changed: `models/results.py` (new optional fields only, so old JSON still loads), `packs/schema.py`
(`fix_prompt_hints`), `scan.py` (policy + findings + prompts), `cli.py`, `report/html_report.py` +
template, `frontend/src/{types.ts,components/Report.tsx}`, `docs/ADDING_A_PACK.md`, `README.md`.

## 4. Milestones
1. This plan + code reading ✅
2. Fix prompt templates + generator + `fix_prompt_hints` + tests (snapshot, leak, injection, size)
3. Prompts in JSON/HTML/React + `privtrace prompt`
4. `.privtrace.yml` schema + `privtrace init` + validation
5. Fingerprints + baseline + new/fixed/existing diff + suppressions
6. `privtrace ci` + gate + exit codes
7. SARIF + PR comment Markdown + job summary
8. GitHub Action + GHCR image workflow + example workflows (GitHub, GitLab, generic, pre-commit)
9. Demo repo + `scripts/demo_ci.sh` + `docs/DEMO_SCRIPT_CI.md`
10. Stretch: `privtrace ci --upload` + API + trends UI

## 5. Decisions
(The brief asked to stop for approval; per the follow-up instruction, I decided and logged here.)

1. **Branch instead of `main`.** `main` auto-deploys to Cloud Run; milestones are committed on
   `feature/v2-fix-prompts-ci` and nothing is pushed.
2. **Finding = rule × location.** Keeps `RuleResult` (UI unit, scoring unit) unchanged and adds a
   flat `findings` list for CI identity. Alternative (one finding per rule) cannot tell a new log
   leak from an old one in the same rule, which defeats new-findings-only mode.
3. **Fingerprint hashes the redacted line**, not the raw source, so baselines/SARIF never carry a
   reversible hash of an identifier.
4. **Gemini enrichment reuses the existing `explain` call** (`AIEnrichment.suggested_fix`, already
   structured + Pydantic-validated) instead of a second call per finding. When present it is added to
   section 6 under "Code-specific guidance (AI-enriched, review before applying)" and the prompt is
   flagged `fix_prompt_ai_enriched`. Halves Gemini traffic; the template prompt is always the base.
5. **Only `failed` findings can fail the gate on severity.** `needs_review` findings are heuristic
   (consent, minimisation, unanswered questions); they are reported but never block a merge.
   Scores already exclude them.
6. **A `None` score fails a `min_score` gate** with reason "score could not be computed": an
   unassessable scan must not look like a pass.
7. **Suppressed / out-of-scope locations are removed before scoring.** If all locations of a failed
   rule are removed, the rule is reported `passed` with an explicit message, and the suppressions are
   listed in every report format. Disabled rules are removed from results and scores and listed under
   "Rules turned off by config".
8. **No baseline + `new_findings_only`** → every finding counts as new and the summary says
   "no baseline: run `privtrace baseline update` or pass `--base`". Safer than silently passing.
9. **`privtrace ci` itself never makes network calls with AI off.** PR comment posting happens in the
   action (github-script, to the same repo's PR), not in the CLI, so the zero-outbound test covers the
   whole CLI. `--base` uses local `git worktree`, no fetch (the workflow uses `fetch-depth: 0`).
10. **Composite action, not Docker action, as the default.** It runs without a published image;
    the GHCR image + `Dockerfile.action` are shipped for teams who prefer pinned images.
11. **pre-commit hook uses `language: system`** (`privtrace` must be installed). The Python package
    lives in `backend/`, and pre-commit's `language: python` installs the repo root, which would need
    a second packaging setup that also bundles `packs/`. Fast mode = `hardcoded_secrets`,
    `pii_in_logs`, `identifiers_hardcoded` on staged files only.
12. **Prompt caps:** 40 code lines per finding block; per-rule prompt shows ≤ 5 locations; batch
    prompt defaults to top 10 findings and ≤ 30 000 characters, and states how many were left out.
13. **YAML `yes`/`no`** in `manual_answers` parse as booleans in YAML 1.1; the config coerces
    `true→yes`, `false→no` so the brief's example works as written.
14. **SARIF schema is vendored** in `backend/tests/data/` (tests run offline) and `jsonschema` is
    added as a dev dependency.

## 6. Needs DV
(Filled in as blocked items come up.)

## 7. Questions (answered by decision above)
- Base-branch vs committed baseline as the default? → `--base` when given, else the committed file
  if present, else none (all new). Trade-offs are in `docs/CI_INTEGRATION.md`.
