"""Regex patterns for personal identifiers and secrets.

Two tiers:
- *Detection* patterns (used to raise findings) are strict and combined with
  checksums/context to keep false positives low.
- *Redaction* patterns (core/redaction.py) are deliberately broad: when in doubt,
  redact. A missed redaction leaks data; an extra one only hides a few characters.
"""

from __future__ import annotations

import re

# Aadhaar: 12 digits, first digit 2-9, optionally grouped 4-4-4 with space/hyphen.
AADHAAR = re.compile(r"(?<![\d])([2-9]\d{3})[ -]?(\d{4})[ -]?(\d{4})(?![\d])")

# PAN: 5 letters, 4 digits, 1 letter; 4th letter is the holder type.
PAN = re.compile(r"\b[A-Z]{3}[PCHFATBLJG][A-Z]\d{4}[A-Z]\b")

# IFSC: 4 letters, a literal 0, 6 alphanumerics.
IFSC = re.compile(r"\b[A-Z]{4}0[A-Z0-9]{6}\b")

# UPI VPA with a known PSP handle (a generic x@y would collide with emails/decorators).
UPI_HANDLES = (
    "upi|ybl|ibl|axl|apl|paytm|okaxis|okhdfcbank|okicici|oksbi|axisbank|icici|sbi|"
    "hdfcbank|kotak|yesbank|idfcbank|pnb|boi|barodampay|freecharge|jupiteraxis|fbl|"
    "airtel|waaxis|wahdfcbank|wasbi|waicici"
)
UPI = re.compile(rf"\b[A-Za-z0-9.\-_]{{2,64}}@(?:{UPI_HANDLES})\b(?![.\w])", re.IGNORECASE)

# Indian mobile: optional +91 / 91 / 0 prefix, then 10 digits starting 6-9.
IN_MOBILE = re.compile(r"(?<![\w+])(?:\+91[\s-]?|91[\s-]|0)?([6-9]\d{4})[\s-]?(\d{5})(?!\d)")

# Indian passport: letter (not Q/X/Z) + 7 digits. Weak signal -> low confidence.
PASSPORT = re.compile(r"\b[A-PR-WY][1-9]\d{6}\b")

# Voter ID (EPIC): 3 letters + 7 digits.
VOTER_ID = re.compile(r"\b[A-Z]{3}\d{7}\b")

# GSTIN: state code, PAN, entity number, 'Z', check char.
GSTIN = re.compile(r"\b\d{2}[A-Z]{5}\d{4}[A-Z][1-9A-Z]Z[0-9A-Z]\b")

EMAIL = re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9\-]+(?:\.[A-Za-z0-9\-]+)*\.[A-Za-z]{2,}\b")

# International phone with explicit + country code.
INTL_PHONE = re.compile(r"(?<![\w])\+(?!91)[1-9]\d{0,2}[\s-]?\(?\d{2,4}\)?[\s-]?\d{3,4}[\s-]?\d{3,4}\b")

# Card numbers: 13-19 digits, optionally grouped. Validated with Luhn.
CARD = re.compile(r"(?<![\d])(?:[3-6]\d{3})(?:[ -]?\d{3,4}){2,4}(?![\d])")

IPV4 = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")

# --- Secrets ---------------------------------------------------------------
SECRET_PATTERNS: dict[str, re.Pattern[str]] = {
    "google_api_key": re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"),
    "aws_access_key_id": re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    "github_token": re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"),
    "openai_api_key": re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_\-]{20,}\b"),
    "anthropic_api_key": re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{20,}\b"),
    "slack_token": re.compile(r"\bxox[abprs]-[A-Za-z0-9\-]{10,}\b"),
    "stripe_secret_key": re.compile(r"\b[sr]k_live_[A-Za-z0-9]{16,}\b"),
    "private_key": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
    "jwt": re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b"),
}

# `password = "..."`, `API_KEY: '...'`, `"secret": "..."`, `TOKEN=...` (.env style)
SECRET_ASSIGNMENT = re.compile(
    r"""(?ix)
    (?P<name>[A-Za-z0-9_\-]*(?:passw(?:or)?d|pwd|secret|api[_\-]?key|apikey|access[_\-]?key|
        auth[_\-]?token|private[_\-]?key|client[_\-]?secret|token)[A-Za-z0-9_\-]*)
    ["']?\s*(?::|=|:=)\s*
    (?P<quote>["']?)(?P<value>[^\s"'#,;)]{6,})(?P=quote)
    """
)

# Values that are clearly placeholders / indirections, not real secrets.
PLACEHOLDER_VALUE = re.compile(
    r"""(?ix)^(
        \$\{?[A-Z0-9_]+\}?        |  # ${VAR} / $VAR
        <[^>]*>                   |  # <your-key>
        \{\{.*\}\}                |  # {{ template }}
        x{4,}|\*{4,}|\.{3,}       |
        (?:your|my)[_\-]?.*       |
        change[_\-]?me.*          |
        placeholder.*|example.*|dummy.*|redacted.*|none|null|true|false|
        os\.(?:environ|getenv).*  |  # code indirection
        settings\..*|config\..*|env\..*|getenv.*|environ.*
    )$"""
)
