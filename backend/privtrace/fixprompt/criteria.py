"""Acceptance criteria per detector: what a correct fix looks like.

Keyed by the rule's `detector` (pack rules that share a check share criteria). Rules without an
entry fall back to the pack's `remediation` text plus `fix_prompt_hints`.
"""

from __future__ import annotations

CRITERIA: dict[str, list[str]] = {
    "pii_to_llm_unredacted": [
        "No personal identifier (name, email, phone, Aadhaar, PAN, address, account number) reaches the LLM call in clear text.",
        "Identifiers are redacted or replaced with placeholders *before* the prompt string is built, using a single shared helper (e.g. `redact_pii()`), not ad-hoc string edits.",
        "Only the fields the task actually needs are sent; if the model needs to refer to the user, it gets a pseudonymous id.",
        "Any mapping from placeholders back to real values stays server-side and is never logged.",
    ],
    "pii_in_logs": [
        "Log calls emit identifiers such as `user_id` / `request_id`, never raw personal fields or whole request bodies / model dumps.",
        "f-strings and `%s` arguments that interpolate personal data are removed or passed through a redaction helper.",
        "A redacting `logging.Filter` is installed as a safety net (it does not replace fixing the call site).",
    ],
    "pii_to_third_party": [
        "Personal data sent to the third-party API is limited to the fields that API needs (data minimisation).",
        "Identifiers that the third party does not need are removed, redacted or pseudonymised before the request is built.",
        "The third party is listed as a data processor in configuration or docs next to the call (comment or constant).",
    ],
    "pii_to_vector_store_unredacted": [
        "Text is redacted before it is embedded and before it is stored in the vector store.",
        "Each stored vector row carries the owning `user_id` so it can be found and erased later.",
    ],
    "sensitive_data_unprotected_at_rest": [
        "Sensitive fields (government IDs, financial data, health data) are encrypted or tokenised before they are written to storage.",
        "Encryption keys come from configuration / a secret manager, never from source code.",
        "Reads decrypt in one place; no other code path reads the raw column.",
    ],
    "erasure_covers_all_stores": [
        "The delete / erasure handler removes the user's data from **every** store listed in the data-flow section (database rows, cache keys, vector rows, files), not only the primary table.",
        "Deletes are keyed by the user's id and run in the same request (or an enqueued job that is guaranteed to run).",
        "A test creates a user, writes to each store, calls the delete endpoint and asserts that nothing for that user remains in any store.",
    ],
    "cache_pii_without_ttl": [
        "Every cache write that holds personal data sets an expiry (e.g. `ex=` / `px=` in Redis) from a named constant such as `CACHE_TTL_SECONDS`.",
        "The TTL value is documented as part of the retention policy.",
    ],
    "retention_mechanism_present": [
        "There is a scheduled purge (cron, Cloud Scheduler job, Celery beat…) that deletes personal data older than a documented retention period.",
        "The retention period is a named constant / config value, not a magic number.",
    ],
    "plaintext_passwords": [
        "Passwords are hashed with a slow password hash (argon2id or bcrypt via `passlib`/`argon2-cffi`) before storage. Never plain SHA-256/MD5.",
        "The stored column is renamed or documented as a hash (e.g. `password_hash`).",
        "Login verifies with the library's `verify()`; passwords are never logged or returned in responses.",
    ],
    "hardcoded_secrets": [
        "The secret value is removed from source and read from an environment variable or secret manager.",
        "The code fails clearly at startup if the variable is missing (no silent fallback to a default secret).",
        "Note for the developer: the exposed secret must be rotated, because it is still in git history.",
    ],
    "committed_env_file": [
        "The `.env` file is removed from version control and added to `.gitignore`.",
        "A `.env.example` with placeholder values documents the required variables.",
        "Note for the developer: any real secret that was in the file must be rotated.",
    ],
    "debug_mode_enabled": [
        "Debug mode is off by default and can only be turned on through an explicit environment variable (e.g. `APP_DEBUG=1`).",
        "Production configuration cannot enable debug tracebacks.",
    ],
    "cors_wildcard": [
        "CORS `allow_origins` is an explicit allow-list loaded from configuration, not `*`.",
        "Credentials are not allowed together with a wildcard origin.",
    ],
    "insecure_transport": [
        "All outbound calls use `https://` and keep TLS verification on (`verify=True` / default).",
        "No code path disables certificate verification.",
    ],
    "sql_string_building": [
        "SQL is built with bound parameters (`text(\"... WHERE email = :email\")`, `cursor.execute(sql, params)`) instead of f-strings, `%` or `+` concatenation.",
        "User input never becomes part of the SQL text.",
    ],
    "delete_endpoints_authenticated": [
        "Every delete endpoint requires an authenticated caller (dependency / decorator).",
        "The handler checks that the caller is allowed to delete *this* record (owner or admin), returning 403 otherwise.",
    ],
    "logging_configured": [
        "Application logging is configured once at startup (level, format, handler) instead of relying on defaults.",
        "Security-relevant events (auth, deletion, admin actions) are logged without personal data.",
    ],
    "log_retention_min_days": [
        "Log retention is configured and documented for at least the period your obligations require (CERT-In directions: 180 days).",
    ],
    "time_sync_configured": [
        "Servers / containers synchronise time with a trusted NTP source and logs carry timezone-aware UTC timestamps.",
    ],
    "consent_captured_at_collection": [
        "The endpoint that collects personal data records explicit consent (a boolean plus the notice version) at the same time.",
        "Requests without consent are rejected before any personal data is stored.",
    ],
    "minimisation_sensitive_fields": [
        "Sensitive fields that are not needed for the stated purpose are removed from the model / form.",
        "Fields that are needed carry a comment or doc entry naming the purpose.",
    ],
    "children_age_gate": [
        "The signup flow captures age or date of birth and blocks or routes users under 18 to a verifiable parental-consent flow.",
    ],
    "identifiers_hardcoded": [
        "Real-looking identifiers (Aadhaar, PAN, phone, email, card numbers) are removed from source and fixtures.",
        "Test data uses obviously fake values from a generator or documented test ranges.",
    ],
}

CONSTRAINTS = [
    "Keep behaviour otherwise unchanged and make the smallest change that fixes the problem.",
    "Add or update a test that proves the fix (it should fail before the change and pass after).",
    "Do not add new dependencies unless the fix genuinely needs one; say why if you do.",
    "Do not touch unrelated files, reformat code you are not changing, or rename public APIs.",
    "Never put real personal data or real secrets in code, tests, fixtures or commit messages.",
]
