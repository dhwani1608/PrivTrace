# PrivTrace in CI

PrivTrace can run on every push and pull request, check the new code against the compliance packs
and rules your business picked, comment on the PR with copy-paste AI fix prompts, and block the
merge when the gate fails.

- **Pass/fail is deterministic.** It comes only from the rule engine. AI never decides anything,
  and the gate makes no LLM call.
- **Nothing leaves the runner by default.** `ai.enabled` is `false` unless you turn it on.
- **Findings are engineering evidence, not legal advice.** Rules pass, fail or need review. PrivTrace
  never says "compliant".

Contents: [Quick start](#quick-start) · [When to run it](#trigger-strategy) ·
[`.privtrace.yml` reference](#privtraceyml-reference) · [Baselines](#baselines-and-new-findings-only) ·
[Fingerprints](#fingerprints) · [Suppressions](#inline-suppressions) · [`privtrace ci`](#privtrace-ci) ·
[GitHub](#github-actions) · [Required check](#make-it-a-required-status-check) · [GitLab](#gitlab-ci) ·
[Other CI](#jenkins-bitbucket-and-others) · [pre-commit](#pre-commit-fast-local-check) ·
[Privacy guarantees](#privacy-guarantees-in-ci) · [Dashboard history](#dashboard-history)

## Quick start

```bash
pip install "git+https://github.com/dhwani1608/PrivTrace.git#subdirectory=backend"
privtrace init                     # choose packs, answer the checklist once -> .privtrace.yml
cp examples/github/privtrace.yml .github/workflows/privtrace.yml
git add .privtrace.yml .github/workflows/privtrace.yml && git commit -m "Add PrivTrace gate"
```

Then make **PrivTrace compliance gate** a required status check on `main` (see below).

## Trigger strategy

| Trigger | Why | What it does |
|---|---|---|
| `pull_request` to `main` / `production` | **The gate.** Problems are caught before they merge, not after they reach production. | Scans the PR and its base branch, comments, uploads SARIF, fails the check if the gate fails. |
| `push` to `main` | Records the main-branch score. | Same scan; the job summary and artifacts keep the score history. If you use a committed baseline, refresh it here (see below). |
| weekly `schedule` | Rules change even when code doesn't (new pack versions, new checks). | Full scan with the latest packs. |
| pre-commit (optional) | Developers find secrets and PII in logs before they push. | Fast check of staged files only. |

All four are in `examples/github/privtrace.yml` (plus the pre-commit hook in `.pre-commit-hooks.yaml`).

## `.privtrace.yml` reference

Create it with `privtrace init` (interactive) or `privtrace init --packs dpdp,certin,security --skip-checklist`.

```yaml
version: 1
packs: [dpdp-2023, certin-2022, security-baseline]   # frameworks the business selected

rules:
  disable:                          # rules that don't apply; a reason is required
    - id: GDPR-TRF-02
      reason: "No personal data leaves India"
  # or the short form:  disable: { GDPR-TRF-02: "No personal data leaves India" }
  severity_overrides: { DPDP-RET-01: critical }

paths:
  include: [src/, services/]        # empty = whole repository
  exclude: [tests/fixtures/, migrations/]

manual_answers:                     # answers to the manual checklist, so CI can score them
  DPDP-GRV-01: yes                  # yes = passed, no = failed, not_sure = needs review
  DPDP-PRC-01: not_sure

gate:
  min_score: 70                     # overall score threshold (0-100)
  min_score_per_pack: { dpdp-2023: 75 }
  fail_on_severity: high            # critical | high | medium | low | none
  new_findings_only: true           # judge the PR only on what it introduces

ai:
  enabled: false                    # default: no code leaves the runner

report:
  pr_comment: true
  sarif: true
  job_summary: true
  fix_prompts: true
  max_prompts_in_comment: 10

baseline:
  file: .privtrace-baseline.json
```

| Key | Default | Notes |
|---|---|---|
| `version` | `1` | Required to be `1`. |
| `packs` | required | Full ids or aliases (`dpdp`, `certin`, `security`, `it-act`, `gdpr`). `privtrace packs list` shows them. |
| `rules.disable` | `[]` | Each entry needs a non-empty `reason`. Disabled rules are removed from results and scores and listed under "Rules turned off by config" in every report. |
| `rules.severity_overrides` | `{}` | Changes the rule's severity, so also its scoring weight (critical 10, high 6, medium 3, low 1). |
| `paths.include` / `paths.exclude` | `[]` | Prefix (`src/`), exact file, or glob (`**/*.sql`). The **whole** repository is still scanned (data flows cross folders); only *findings* outside the scope are dropped. |
| `manual_answers` | `{}` | Only for manual / hybrid rules. YAML `yes`/`no` work (they are read as booleans and converted). For hybrid rules, code evidence of a failure still wins over a "yes". |
| `gate.min_score` | none | Fails if the overall score is below it, or if no score could be computed. |
| `gate.min_score_per_pack` | `{}` | Same, per pack. The pack must be in `packs`. |
| `gate.fail_on_severity` | `high` | Fails if any (new) **failed** finding is at least this severe. `none` turns it off. `needs_review` findings never block. |
| `gate.new_findings_only` | `true` | With a baseline, only findings that are not in the baseline count for the severity rule. Scores always count everything. |
| `ai.enabled` | `false` | When `true` *and* `GEMINI_API_KEY` + `GEMINI_MODEL` are set, redacted snippets (≤ 40 lines) go to Gemini for explanations and enrich the fix prompts. Never affects pass/fail. |
| `report.*` | `true` | Which outputs to produce. |
| `baseline.file` | `.privtrace-baseline.json` | Used when `--base` is not given. |

Validation: unknown keys, unknown packs or rules, a disabled rule without a reason, an answer for an
automated rule and out-of-range scores are all errors. `privtrace ci` prints every problem with its
YAML path and exits with code **2**.

## Baselines and new-findings-only

A company adopting PrivTrace already has findings and can't fix them all in one PR. With
`new_findings_only: true` a PR is judged on what it **introduces**. PrivTrace still scans the whole
repository (data-flow analysis needs it), then compares finding fingerprints with a baseline and
reports each finding as **new**, **existing** or **fixed**, plus the score change ("DPDP 100 → 79 ▼21").

There are two ways to get the baseline:

| | Base-branch scan (`--base origin/main`) | Committed baseline (`privtrace baseline update`) |
|---|---|---|
| How | Scans the merge-base of the PR in a temporary `git worktree`, with the PR's config. | `.privtrace-baseline.json` in the repo: fingerprints, rule ids, paths, line numbers and scores. No code. |
| Setup | `fetch-depth: 0` in checkout. Nothing to commit. | Run the command, commit the file, refresh it when you accept existing findings. |
| Cost | Two scans per run (both fast). | One scan. |
| Accuracy | Always compares with exactly what the PR branches from. Config or pack changes in the PR apply to both sides. | Goes stale: a finding fixed on `main` but still in the file is harmless, but new findings merged without the gate (e.g. direct pushes) count as "existing". |
| Best for | Pull requests (the default in the action). | Repos without full git history in CI, monorepos with slow checkouts, or "accept today's state" adoption. |

The action uses `origin/<base branch>` on `pull_request` and falls back to the committed file
otherwise. With neither, every finding counts as new and the comment says so.

## Fingerprints

Each finding (one rule at one location) gets a stable 16-hex-digit fingerprint:

```
sha256( rule_id | file | enclosing function | sha256(normalised redacted line) | occurrence )[:16]
```

- **Enclosing function**: the innermost `def`/`class` qualname from the Python AST (`<module>` at top
  level), so adding or removing lines above a finding doesn't change it.
- **Normalised redacted line**: the flagged line after redaction (identifiers become
  `[REDACTED:…]`), with whitespace collapsed and any `privtrace-ignore` comment removed. Hashing the
  *redacted* line means a fingerprint can't be brute-forced back to an Aadhaar or phone number, and
  changing one fake test value for another does not create a "new" finding.
- **Occurrence**: separates identical lines in the same function.

The fingerprint **changes** when the vulnerable code changes, moves to another function or file, or
a different rule fires. It appears in SARIF `partialFingerprints`, Code Quality `fingerprint`, the
JSON report and the baseline. Finding ids used by `privtrace prompt` are its first 10 characters.

## Inline suppressions

```python
logger.info("signup %s", user_id)  # privtrace-ignore: DPDP-SEC-02 reason="user_id is not personal data here" expires=2027-03-01

# privtrace-ignore: DPDP-SEC-02, SECB-LOG-01 reason="hashed before logging"
logger.info("email hash %s", digest)
```

- A trailing comment covers its own line; a comment on its own line covers the next code line (for a
  decorated function, through to the `def`). `#`, `//` and `--` comments are recognised.
- `reason="..."` is **required**. Without it the comment is *invalid* and suppresses nothing.
- `expires=YYYY-MM-DD` is optional. After that date the comment is *expired* and the finding is back.
- No wildcards: name every rule id.
- **Every** suppression is listed in the HTML report, the JSON, and the PR comment (active, unused,
  expired, invalid), so nobody can quietly hide an issue.
- If every location of a failed rule is suppressed (or out of `paths`), the rule is reported as
  passed, with a message saying why.

## `privtrace ci`

```bash
privtrace ci [PATH] --config .privtrace.yml --base origin/main \
  --sarif out.sarif --json out.json --markdown summary.md --html report.html \
  [--gitlab-codequality gl.json] [--report-json full.json] [--fail-on high] [--min-score 70] \
  [--report-url URL] [--summary/--no-summary]
```

| Exit code | Meaning |
|---|---|
| `0` | Gate passed. |
| `1` | Gate failed (the reasons are printed and in every output). |
| `2` | Config or scan error. **Never** treated as a pass: invalid config, missing config, unknown base ref, any crash. |

`--fail-on` and `--min-score` override the config. `--packs` overrides the config's packs (and works
without a config file). The job summary is appended to `$GITHUB_STEP_SUMMARY` when that variable is
set (turn off with `--no-summary` or `report.job_summary: false`).

Outputs:

| Output | Contents |
|---|---|
| `--json` | Code-free result: gate decision and reasons, scores and deltas, new/existing/fixed findings (ids, rules, paths, lines, fingerprints), suppressions, disabled rules. Safe to archive or upload. |
| `--markdown` | The PR comment: badge, scores with change from base, new findings table, fixed findings 🎉, a collapsible fix prompt per new finding, a "fix all new findings" prompt, suppressions, a link to the full report, the disclaimer. Kept under GitHub's 65 536-character limit by dropping prompts first. |
| `--sarif` | SARIF 2.1.0: rule metadata, help text (why + fix + reference), `security-severity` (critical 9.5, high 8.0, medium 5.5, low 3.0), `partialFingerprints`, `baselineState`. Project-level checklist findings are anchored to `.privtrace.yml`. |
| `--html` | The full self-contained report with copy buttons for every prompt. |
| `--gitlab-codequality` | GitLab Code Quality JSON. |
| `--report-json` | The full scan result, including redacted fix prompts. |

## GitHub Actions

`action.yml` at the repository root is a composite action. It installs PrivTrace, runs
`privtrace ci` (comparing with `origin/<base>` on pull requests), creates or updates **one** sticky
PR comment (found by the `<!-- privtrace-gate -->` marker), and fails the job in its last step,
after the comment is posted.

Inputs: `config`, `working-directory`, `packs`, `min-score`, `fail-on`, `base`, `gemini-api-key`,
`gemini-model`, `comment`, `output-dir`, `python-version`, `github-token`.
Outputs: `passed`, `exit-code`, `sarif-file`, `report-dir`.

Copy `examples/github/privtrace.yml`. It:

- checks out with `fetch-depth: 0` (needed for the base comparison),
- runs the action,
- uploads SARIF with `github/codeql-action/upload-sarif` (findings show in the Security tab and as
  inline annotations on the PR diff),
- uploads the HTML report and JSON as a workflow artifact,
- uses least-privilege permissions: `contents: read`, `pull-requests: write`, `security-events: write`.

The minimal version:

```yaml
on: pull_request
permissions: { contents: read, pull-requests: write, security-events: write }
jobs:
  privtrace:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with: { fetch-depth: 0 }
      - uses: dhwani1608/PrivTrace@main
```

Notes: PRs from forks get a read-only token, so the comment step is skipped (`continue-on-error`) and
the job summary still has everything. A container image is also available for teams who prefer
pinned images: `Dockerfile.action`, published to `ghcr.io/<owner>/privtrace-ci` by
`.github/workflows/publish-action-image.yml` when a `v*` tag is pushed.

## Make it a required status check

1. Run the workflow once (open any PR) so GitHub knows the check name.
2. **Settings → Branches → Add branch protection rule** (or **Rules → Rulesets**) for `main`.
3. Enable **Require status checks to pass before merging** and select **PrivTrace compliance gate**.
4. Optionally enable **Require branches to be up to date before merging** so the base comparison is current.

Failing PRs can no longer be merged. A config or scan error (exit 2) also fails the check.

## GitLab CI

`examples/gitlab/.gitlab-ci.yml` installs PrivTrace in `python:3.12-slim`, compares merge requests
with their target branch, and publishes `gl-code-quality-report.json` as a **Code Quality** report
(shown in the MR widget), plus the HTML/JSON/Markdown as artifacts. Post `privtrace.md` as an MR note
with your own token if you want a comment.

## Jenkins, Bitbucket and others

`examples/generic/privtrace-ci.sh [base-ref]` installs PrivTrace if needed, runs the gate, prints
the decision from the JSON and exits with the same codes (0 / 1 / 2). Treat any non-zero exit as a
failed build.

## pre-commit (fast local check)

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/dhwani1608/PrivTrace
    rev: main          # pin a tag
    hooks:
      - id: privtrace-fast
```

The hook runs `privtrace precommit` on staged files only: hardcoded secrets, personal data in logs and
Indian ID / personal identifier patterns. It honours `privtrace-ignore` comments, never prints the
secret it found, and does not follow cross-file flows (CI does). It uses `language: system`, so
`privtrace` must be installed.

## Privacy guarantees in CI

| Leaves the runner | Stays on the runner |
|---|---|
| With `ai.enabled: false` (default): **nothing** from PrivTrace itself. A test (`test_ci_with_ai_disabled_makes_no_network_calls`) blocks sockets and DNS and asserts zero calls, even with a Gemini key in the environment. | Your source code. |
| The PR comment and SARIF go to **your own** repository on GitHub (rule ids, paths, line numbers, fingerprints; the comment's fix prompts contain redacted code, ≤ 40 lines per finding). | Raw snippets: every snippet in every output is redacted (Aadhaar, PAN, email, phone, card numbers, secrets, …). |
| With `ai.enabled: true` and a key: redacted snippets (≤ 40 lines) go to Gemini for explanations. Pass/fail is unchanged. | Logs: the logging filter redacts identifiers in every log record. |
| `--base` uses a local `git worktree`: nothing is fetched by PrivTrace. | The baseline file and the `--json` result contain no code. |

## Dashboard history

Send each CI result to a PrivTrace server to see score trends per repository and branch, and the last
10 PRs, in the web UI (**CI history** in the header):

```bash
# on the server (e.g. Cloud Run): enable uploads with a shared secret
PRIVTRACE_CI_TOKEN=<long random string>

# in CI (store the same value as a secret)
privtrace ci --base origin/main --upload https://your-privtrace.example --token "$PRIVTRACE_TOKEN"
```

- The upload is the `--json` result (`CiReport`, `schema_version: 1`): scores, deltas, gate decision,
  finding metadata (ids, rules, paths, lines, fingerprints) and run context (provider, repo, ref,
  sha, PR number, run URL). **No code, snippets or prompts.**
- The server re-validates it against the `CiReport` schema and drops unknown fields before storing
  it, so a tampered upload can't store code either.
- Without `PRIVTRACE_CI_TOKEN` on the server, uploads are refused (503). A wrong token gets 401.
- `privtrace ci` only contacts the server when `--upload` is given. A failed upload prints a warning
  and never changes the gate's exit code.
- API: `POST /api/ci/runs` (Bearer token), `GET /api/ci/repos`, `GET /api/ci/runs?repo=…&ref=…`.
