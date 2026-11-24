# Demo script: PrivTrace in CI (about 2 minutes)

The story: *a developer's PR quietly starts logging signup data and sending a phone number to an
LLM. PrivTrace blocks the merge, tells them exactly where and why, and hands them a prompt their
AI coding tool can apply. They fix it, push again, and the gate goes green.*

Everything runs locally: no GitHub, no network. AI is off in the demo config.
For the web UI part of a demo, use the live app: <https://privtrace-836138728232.asia-south1.run.app>.

## Before you start (once)

```bash
cd PrivTrace
python -m venv backend/.venv && backend/.venv/bin/pip install -e "backend[dev]"   # Windows: backend\.venv\Scripts\pip
bash scripts/demo_ci.sh          # dry run: must end with three ✅ lines
```

For a live demo, pause between steps:

```bash
PRIVTRACE_DEMO_PAUSE=1 bash scripts/demo_ci.sh
```

Have these open in tabs: `demo-repos/acme-chatbot/.privtrace.yml`,
`demo-repos/acme-chatbot/.github/workflows/privtrace.yml`, and (after the run)
`demo-ci-output/risky-change.md` in a Markdown preview and `demo-ci-output/risky-change.html` in a browser.

## The script

| Time | Do | Say |
|---|---|---|
| 0:00 | Show `.privtrace.yml` | "Acme picked its frameworks: DPDP, CERT-In and a security baseline. It answered the organisational checklist once, turned one rule off **with a reason**, and set the gate: overall 75, DPDP 75, and no new high or critical findings." |
| 0:15 | Show the workflow file | "This is the whole integration: checkout, the PrivTrace action, SARIF upload. Least-privilege permissions. AI is off, so no code leaves the runner." |
| 0:25 | Run step 1 (`feature/good-change`) | "A harmless PR adds a health endpoint. PrivTrace scans the PR **and** the base branch, compares fingerprints, and passes. Score 100 → 100." |
| 0:40 | Run step 2 (`feature/risky-change`) | "Now someone personalises the welcome SMS: they log the signup payload and send the user's phone number straight to Gemini." |
| 0:50 | Point at the red output / `risky-change.md` | "Gate failed. Four new blocking findings: the log line and the LLM call, flagged under DPDP and the security baseline. DPDP drops from 100 to 79. The two existing checklist items don't block anything: we only judge what this PR introduces." |
| 1:05 | Open the fix prompt (printed, or in the PR comment's collapsible section) | "Every finding comes with a prompt for Claude, Cursor, Copilot or ChatGPT: the rule, why it matters, the exact lines, the data flow (`POST /signup` → `logger.info`), what a correct fix looks like and how to verify it. The code in it is redacted and marked as data, so a comment in the code can't hijack the AI." |
| 1:25 | Run step 3 (fix applied) | "The developer pastes the prompt, the AI makes the change: log the user id only, and give the model a placeholder instead of the name and phone number. Push again: green, back to 100." |
| 1:40 | Open `risky-change.html`, scroll to a finding, click **Copy AI fix prompt** | "The same prompts are in the HTML report, the JSON and the web UI, and `privtrace prompt --all` gives one batch prompt." |
| 1:50 | Close | "Pass/fail is always deterministic. AI only explains. And this is engineering evidence, not legal advice. It says *rule failed*, never *non-compliant*." |

## What the commands do

```bash
# what demo_ci.sh runs on each branch (from the throw-away repo it creates)
privtrace ci . --base main --markdown out.md --json out.json --sarif out.sarif --html out.html
#   exit 0: gate passed   exit 1: gate failed   exit 2: config or scan error

privtrace prompt DPDP-SEC-02            # the prompt for one rule
privtrace prompt --file app/main.py     # one prompt for every finding in a file
privtrace prompt --all --top 10         # batch prompt, ordered by severity
```

Expected results:

| Branch | Exit | Overall | DPDP | New blocking |
|---|---|---|---|---|
| `feature/good-change` | 0 | 100 → 100 | 100 → 100 | 0 |
| `feature/risky-change` | 1 | 100 → 84 | 100 → 79 | DPDP-SEC-01, DPDP-SEC-02, SECB-LLM-01, SECB-LOG-01 |
| risky + fix | 0 | 100 → 100 | 100 → 100 | 0 |

## If something goes wrong

- `privtrace not found`: install the backend (`pip install -e backend`) or set `PRIVTRACE=/path/to/privtrace`.
- Box-drawing characters look broken on Windows: run in Windows Terminal or Git Bash with UTF-8 (`PYTHONIOENCODING=utf-8` is set by the script).
- Want to show it on real GitHub: push `demo-repos/acme-chatbot` to a new public repository, open a PR with
  `scripts/demo/risky-change.patch` applied, and the workflow posts the comment and SARIF annotations.
  (Not done yet; see PLAN-v2.md, "Needs DV".)
