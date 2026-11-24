#!/usr/bin/env bash
# PrivTrace gate for any CI (Jenkins, Bitbucket Pipelines, CircleCI, Buildkite, ...).
# Usage: privtrace-ci.sh [base-ref]      e.g. privtrace-ci.sh origin/main
#
# Exit codes: 0 passed, 1 gate failed, 2 config or scan error (treat 2 as a failure, never a pass).
# Outputs in ./privtrace-report/: privtrace.json (code-free result), report.html, comment.md, privtrace.sarif
set -uo pipefail

BASE_REF="${1:-}"
PRIVTRACE_REF="${PRIVTRACE_REF:-main}"
OUT="${PRIVTRACE_OUT:-privtrace-report}"

if ! command -v privtrace >/dev/null 2>&1; then
  tmp="$(mktemp -d)"
  git clone --quiet --depth 1 --branch "$PRIVTRACE_REF" https://github.com/dhwani1608/PrivTrace.git "$tmp/privtrace"
  python3 -m pip install --quiet "$tmp/privtrace/backend"
  export PRIVTRACE_PACKS_DIR="$tmp/privtrace/packs"
fi

mkdir -p "$OUT"
args=(ci . --json "$OUT/privtrace.json" --html "$OUT/report.html" --markdown "$OUT/comment.md" --sarif "$OUT/privtrace.sarif")
if [ -n "$BASE_REF" ]; then
  git fetch --quiet origin "${BASE_REF#origin/}" || true
  args+=(--base "$BASE_REF")
fi

privtrace "${args[@]}"
code=$?

# Read the decision from the JSON (it contains no code, so it is safe to archive or send to a dashboard).
if command -v python3 >/dev/null 2>&1 && [ -f "$OUT/privtrace.json" ]; then
  python3 -c '
import json, sys
r = json.load(open(sys.argv[1], encoding="utf-8"))
print("gate passed:", r["gate"]["passed"], "| overall:", r["overall"]["after"], "| new:", r["counts"]["new"], "| fixed:", r["counts"]["fixed"])
for reason in r["gate"]["reasons"]:
    print("  -", reason)
' "$OUT/privtrace.json"
fi

case "$code" in
  0) echo "PrivTrace gate passed" ;;
  1) echo "PrivTrace gate FAILED" ;;
  *) echo "PrivTrace could not run (exit $code)"; code=2 ;;
esac
exit "$code"
