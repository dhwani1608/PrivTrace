# Architecture

See `PLAN.md` §1 for the diagram. Summary of the pipeline:

1. **Fetch** — GitHub URL (shallow clone), ZIP upload, or local folder is copied into a temp workspace that is always deleted after the scan.
2. **Parse** — `scanner/parsers/` exposes a `LanguageParser` protocol. MVP: Python via the built-in `ast`. A tree-sitter JS/TS parser can be added without engine changes.
3. **Detect** — `scanner/detectors/` are pure functions registered by name: PII names, Indian identifiers, generic PII, secrets, sinks, config checks.
4. **Flow** — `scanner/flow/` runs a simple intra-file + import-following taint pass and builds a `DataFlowGraph` (sources → code paths → sinks).
5. **Rules** — `rules/engine.py` loads the selected packs (`packs/*.yaml`, validated by `packs/schema.py`) and runs each rule's registered check. Status is one of `passed / failed / needs_review / not_assessable`. Manual answers are merged in.
6. **AI (optional)** — `ai/gateway.py` is the only path to Gemini. It redacts identifiers, sends ≤ 40-line snippets, uses structured JSON output, and validates responses with Pydantic. AI output is attached as a separate `AIEnrichment` object that has no status field, so it cannot change a rule result.
7. **Score + report** — `report/` computes per-pack and overall scores (`docs/SCORING.md`), diffs against the previous scan, and renders JSON and HTML.

The CLI, the API, and a future Cloud Run Job all call the same `run_scan()` function.
