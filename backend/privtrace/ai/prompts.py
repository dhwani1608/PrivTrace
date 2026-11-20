"""Prompt templates. Inputs are always redacted, truncated snippets (see gateway.py)."""

from __future__ import annotations

SYSTEM = (
    "You assist software engineers reviewing code for privacy and security issues. "
    "You are given redacted code snippets; values like [REDACTED:EMAIL] are placeholders. "
    "Never claim code is legally 'compliant' or 'non-compliant' and do not give legal advice. "
    "Be concrete, brief and technical. Answer only with JSON matching the schema."
)

CLASSIFY = """Decide whether each identifier below is likely to hold personal data
(information about an identifiable person) in this codebase. Use the code context.

Identifiers with context:
{items}

Return JSON: {{"items": [{{"name": str, "is_personal_data": bool, "category": str, "reason": str}}]}}
Category is one of: contact, identity, government_id, financial, health, location, credentials, children, other, none."""

EXPLAIN = """A deterministic scanner reported this finding. Do not re-judge whether it
passed or failed; explain it and suggest a fix.

Rule: {title}
Framework: {framework}
Reference: {reference}
Scanner message: {message}
Location: {location}

Code snippet (redacted, may be truncated):
```python
{snippet}
```

{fix_instruction}

Return JSON: {{"explanation": str, "suggested_fix": str, "suggested_diff": str | null}}"""

FIX_WITH_DIFF = (
    "No template fix exists for this rule. Provide `suggested_fix` and, if a small change to "
    "the snippet would fix it, a unified diff in `suggested_diff` (use the same placeholders; never invent real values)."
)
FIX_TEXT_ONLY = "A template diff already exists, so set `suggested_diff` to null and keep `suggested_fix` to one sentence."
