"""Redaction of personal identifiers and secrets.

Used for: evidence snippets in reports, anything sent to Gemini, and the logging
filter. Redaction is intentionally broader than detection (no checksum needed).
"""

from __future__ import annotations

import logging
import re

from privtrace.scanner.detectors import patterns as P

# Order matters: longer / more specific patterns first so they win overlaps.
_REDACTIONS: list[tuple[str, re.Pattern[str]]] = [
    ("PRIVATE_KEY", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)")),
    *[(name.upper(), pat) for name, pat in P.SECRET_PATTERNS.items() if name != "private_key"],
    ("GSTIN", P.GSTIN),
    ("EMAIL", P.EMAIL),
    ("UPI", P.UPI),
    ("CARD", re.compile(r"(?<!\d)\d(?:[ -]?\d){12,18}(?!\d)")),
    ("AADHAAR", re.compile(r"(?<!\d)\d{4}[ -]?\d{4}[ -]?\d{4}(?!\d)")),
    ("PHONE", P.INTL_PHONE),
    ("PHONE", re.compile(r"(?<![\w+])(?:\+91[\s-]?|91[\s-]|0)?[6-9]\d{4}[\s-]?\d{5}(?!\d)")),
    ("PAN", re.compile(r"\b[A-Z]{5}\d{4}[A-Z]\b")),
    ("IFSC", P.IFSC),
    ("VOTER_ID", P.VOTER_ID),
    ("PASSPORT", P.PASSPORT),
    ("IP", P.IPV4),
]


def _redact_secret_assignments(text: str) -> str:
    def repl(m: re.Match[str]) -> str:
        value = m.group("value")
        if P.PLACEHOLDER_VALUE.match(value) or value.startswith("[REDACTED"):
            return m.group(0)
        start, end = m.span("value")
        s0 = m.start()
        whole = m.group(0)
        return whole[: start - s0] + "[REDACTED:SECRET]" + whole[end - s0 :]

    return P.SECRET_ASSIGNMENT.sub(repl, text)


def redact(text: str) -> str:
    """Replace identifiers/secrets in `text` with `[REDACTED:KIND]` tokens."""
    if not text:
        return text
    out = _redact_secret_assignments(text)
    for label, pat in _REDACTIONS:
        out = pat.sub(f"[REDACTED:{label}]", out)
    return out


def contains_unredacted_pii(text: str) -> bool:
    """True if `redact(text)` would change anything. Used by tests and the AI gateway."""
    return redact(text) != text


def truncate_lines(text: str, max_lines: int) -> str:
    lines = text.splitlines()
    if len(lines) <= max_lines:
        return text
    return "\n".join(lines[:max_lines]) + f"\n# ... truncated ({len(lines) - max_lines} more lines)"


class RedactingFilter(logging.Filter):
    """Logging filter that redacts identifiers from every log record."""

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            msg = record.getMessage()
        except Exception:  # pragma: no cover - malformed record, leave as is
            return True
        record.msg = redact(msg)
        record.args = None
        return True


def install_log_redaction() -> None:
    root = logging.getLogger()
    if not any(isinstance(f, RedactingFilter) for f in root.filters):
        root.addFilter(RedactingFilter())
    for h in root.handlers:
        if not any(isinstance(f, RedactingFilter) for f in h.filters):
            h.addFilter(RedactingFilter())
