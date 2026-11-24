#!/usr/bin/env bash
# PrivTrace CI demo: simulates the GitHub workflow locally on three branches of the Acme chatbot.
#
#   bash scripts/demo_ci.sh            # from the PrivTrace repository root
#
# 1. feature/good-change   harmless /health endpoint          -> gate passes (exit 0), score unchanged
# 2. feature/risky-change  logs the signup payload and sends   -> gate fails (exit 1), DPDP score drops,
#                          the user's phone number to Gemini      PR comment lists fix prompts
# 3. risky-change + fix    applies what the fix prompt asks    -> gate passes again (exit 0)
#
# Outputs (PR comment Markdown, code-free JSON, SARIF, HTML report) land in ./demo-ci-output/.
# Nothing leaves this machine: AI is off in .privtrace.yml and --base is a local git worktree.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PATCHES="$ROOT/scripts/demo"
OUT="${PRIVTRACE_DEMO_OUT:-$ROOT/demo-ci-output}"
PAUSE="${PRIVTRACE_DEMO_PAUSE:-0}"   # set to 1 to wait for Enter between steps (live demo)

if [ -n "${PRIVTRACE:-}" ]; then PT="$PRIVTRACE"
elif command -v privtrace >/dev/null 2>&1; then PT="privtrace"
elif [ -x "$ROOT/backend/.venv/Scripts/privtrace.exe" ]; then PT="$ROOT/backend/.venv/Scripts/privtrace.exe"
elif [ -x "$ROOT/backend/.venv/bin/privtrace" ]; then PT="$ROOT/backend/.venv/bin/privtrace"
else
  echo "privtrace not found: pip install -e backend (or set PRIVTRACE=/path/to/privtrace)" >&2
  exit 2
fi
export PYTHONIOENCODING=utf-8
# a non-editable install cannot locate the repo's packs/ on its own
export PRIVTRACE_PACKS_DIR="${PRIVTRACE_PACKS_DIR:-$ROOT/packs}"
# simulate a local run even when this script itself runs inside a CI job
unset GITHUB_STEP_SUMMARY GITHUB_ACTIONS GITLAB_CI

bold() { printf '\n\033[1m%s\033[0m\n' "$*"; }
pause() { if [ "$PAUSE" = "1" ]; then read -r -p "  (Enter to continue) " _; fi; }
gitq() { git -c user.name="Acme Dev" -c user.email="dev@acme.example" "$@" -q; }

rm -rf "$OUT" && mkdir -p "$OUT"
WORK="$(mktemp -d)/acme-chatbot"
cp -r "$ROOT/demo-repos/acme-chatbot" "$WORK"
cd "$WORK" || exit 2
git init -q -b main 2>/dev/null || { git init -q && git checkout -q -b main; }
git add -A && gitq commit -m "Acme chatbot: PrivTrace config and workflow"
echo "Demo repository: $WORK"

run_gate() {  # $1 = output name
  "$PT" ci . --base main --no-summary \
    --markdown "$OUT/$1.md" --json "$OUT/$1.json" --sarif "$OUT/$1.sarif" --html "$OUT/$1.html"
}

declare -A CODES

bold "1/3  feature/good-change: add a /health endpoint"
git checkout -q -b feature/good-change main
git apply "$PATCHES/good-change.patch" && git add -A && gitq commit -m "Add /health endpoint"
git --no-pager diff --stat main
run_gate good-change; CODES[good]=$?
echo "exit code: ${CODES[good]}  (expected 0)"
pause

bold "2/3  feature/risky-change: log the signup payload, send the phone number to Gemini"
git checkout -q -b feature/risky-change main
git apply "$PATCHES/risky-change.patch" && git add -A && gitq commit -m "Personalised welcome SMS"
git --no-pager diff --stat main
run_gate risky-change; CODES[risky]=$?
echo "exit code: ${CODES[risky]}  (expected 1)"
bold "PR comment (first lines of $OUT/risky-change.md)"
sed -n '1,24p' "$OUT/risky-change.md"
echo "  ..."
bold "AI fix prompt for the new log finding (paste into Claude / Cursor / Copilot / ChatGPT)"
"$PT" prompt DPDP-SEC-02 --target . | sed -n '1,30p'
echo "  ... (full prompt: privtrace prompt DPDP-SEC-02)"
pause

bold "3/3  apply the fix the prompt asks for, push again"
git apply "$PATCHES/fix-risky-change.patch" && git add -A && gitq commit -m "Fix: log user_id only, no personal data to Gemini"
git --no-pager diff --stat HEAD~1
run_gate fixed; CODES[fixed]=$?
echo "exit code: ${CODES[fixed]}  (expected 0)"

bold "Summary"
ok=1
check() { if [ "$2" = "$3" ]; then echo "  ✅ $1: exit $2"; else echo "  ❌ $1: exit $2 (expected $3)"; ok=0; fi; }
check "feature/good-change " "${CODES[good]}" 0
check "feature/risky-change" "${CODES[risky]}" 1
check "risky-change + fix  " "${CODES[fixed]}" 0
echo "  Outputs: $OUT (open risky-change.md for the PR comment, risky-change.html for the full report)"
rm -rf "$(dirname "$WORK")"
[ "$ok" = 1 ] && exit 0 || exit 1
