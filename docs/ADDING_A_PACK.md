# Adding a compliance pack

Packs are YAML files in `packs/`. The engine loads every `*.yaml` at runtime and validates it against `backend/privtrace/packs/schema.py`; no engine code changes are needed unless you need a new kind of check.

## 1. Create the file

```yaml
id: my-framework            # lowercase kebab-case, unique
name: Full official name
short_name: Short           # shown on gauges and tables
jurisdiction: IN            # ISO code, "EU" or "Global"
version: "2026-01"          # version / date of the text you followed
source_url: https://...     # official text
description: One paragraph shown in the pack picker.

rules:
  - id: MYF-SEC-01                  # UPPER-CASE segments joined by '-'; unique within the pack
    title: Short statement of the problem
    reference: "Act, s.X(Y)"         # REQUIRED. Never guess a number.
    reference_verified: false        # true only after checking the official text
    source_url: https://...          # deep link to the provision if possible
    severity: high                   # critical 10 | high 6 | medium 3 | low 1
    check_type: automated            # automated | manual | hybrid
    detector: pii_in_logs            # automated/hybrid: a registered check name
    detector_params: {}              # optional, passed to the check
    question: null                   # manual/hybrid: yes/no question for the checklist
    why_it_matters: Plain language, for developers.
    remediation: What to change.
    tags: [logging]
    fix_prompt_hints:                # optional: extra guidance added to AI fix prompts
      - "Never log request.body() or whole payloads; log user_id instead."
```

`fix_prompt_hints` (optional, list of strings) is rule-specific guidance that PrivTrace adds to
section 6 ("What a correct fix looks like") of every copy-paste AI fix prompt for this rule, e.g.
"use argon2 or bcrypt, never plain SHA-256" or "the delete path must also cover Redis keys
`user:{id}:*` and pgvector rows". Keep each hint one sentence, concrete, and free of real data.
See `docs/FIX_PROMPTS.md`.

Validation rejects: missing/empty `reference`, duplicate rule ids, automated rules without a `detector`, manual rules without a `question`, and any `detector` that is not registered.

## 2. Pick check types

| check_type | Decided by | Use when |
|---|---|---|
| automated | code evidence only | the obligation is visible in code/config |
| manual | checklist answer only | it's an organisational fact (contracts, DPO, policies) |
| hybrid | code evidence + answer | code gives partial evidence (consent fields, retention, logging) |

Hybrid: a code-level **failure** always stays failed; otherwise the answer decides.

## 3. Available checks

Run `python -c "from privtrace.rules.registry import registered_checks; print(sorted(registered_checks()))"`. Current checks:

| Check | What it looks at | Params |
|---|---|---|
| `pii_to_llm_unredacted` | personal data reaching LLM / embedding APIs without a redaction step | — |
| `pii_in_logs` | personal data or raw request bodies in logging/print calls | `include_print` |
| `pii_to_third_party` | personal data to HTTP APIs, analytics, AI providers | `hit_status` (default `needs_review`) |
| `pii_to_vector_store_unredacted` | personal data embedded into vector stores | `hit_status` |
| `sensitive_data_unprotected_at_rest` | IDs / financial / health data written to stores without encryption/masking | `hit_status` |
| `erasure_covers_all_stores` | delete-user handlers vs. every store holding personal data | — |
| `cache_pii_without_ttl` | cache writes with personal data and no TTL | — |
| `retention_mechanism_present` | purge jobs / time-based deletes | — |
| `plaintext_passwords` | passwords stored/logged unhashed, MD5/SHA for passwords | — |
| `hardcoded_secrets` | API keys, tokens, secret assignments | — |
| `committed_env_file` | `.env` files in the repo | — |
| `debug_mode_enabled`, `cors_wildcard`, `insecure_transport`, `sql_string_building` | configuration / code patterns | — |
| `delete_endpoints_authenticated` | DELETE routes without an auth dependency | — |
| `logging_configured`, `log_retention_min_days`, `time_sync_configured` | logging and time configuration | `missing_status`, `min_days` |
| `consent_captured_at_collection`, `minimisation_sensitive_fields`, `children_age_gate` | heuristics (never fail) | `categories` |
| `identifiers_hardcoded` | Aadhaar/PAN/cards/emails in code and fixtures | — |

## 4. Writing a new check

Add a function to `backend/privtrace/rules/checks.py`:

```python
@register_check("my_check")
def my_check(facts: CodeFacts, params: dict) -> CheckOutcome:
    ...
    return CheckOutcome(status=RuleStatus.failed, message="...", evidence=[...])
```

Use the facts the scanner already extracted (`facts.sinks`, `facts.models`, `facts.config`, `facts.functions`, `facts.detections`). Evidence snippets are already redacted. Heuristics must return `needs_review`, not `failed`. Add a passing and a failing case to `CASES` in `backend/tests/test_rules.py` (a test enforces this).

## 5. Legal review

Run `privtrace packs legal-todo` to regenerate `docs/LEGAL_REVIEW_TODO.md`. A test fails if an unverified reference is missing from it.
