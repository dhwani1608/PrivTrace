"""Text-level detectors: run on any source/config/fixture file line by line.

Each detector is registered by name and returns `Detection`s with a redacted
snippet. Raw matched values are never stored.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Iterable

from privtrace.core.redaction import redact
from privtrace.models.detection import Detection
from privtrace.scanner.detectors import patterns as P
from privtrace.scanner.detectors.checksums import gstin_valid, luhn_valid, verhoeff_valid

TextDetector = Callable[[str, str], list[Detection]]
TEXT_DETECTORS: dict[str, TextDetector] = {}

_MAX_SNIPPET_CHARS = 200


def register_text_detector(name: str) -> Callable[[TextDetector], TextDetector]:
    def deco(fn: TextDetector) -> TextDetector:
        TEXT_DETECTORS[name] = fn
        return fn

    return deco


def _snippet(line: str) -> str:
    s = redact(line.strip())
    return s if len(s) <= _MAX_SNIPPET_CHARS else s[:_MAX_SNIPPET_CHARS] + "…"


def _lines(text: str) -> Iterable[tuple[int, str]]:
    for i, line in enumerate(text.splitlines(), start=1):
        if len(line) > 5000:  # minified blobs: skip
            continue
        yield i, line


def _det(detector: str, kind: str, category: str, path: str, lineno: int, line: str, conf: float) -> Detection:
    return Detection(
        detector=detector, kind=kind, data_category=category, file=path,
        line=lineno, snippet=_snippet(line), confidence=conf,
    )


# ---------------------------------------------------------------------------
@register_text_detector("indian_ids")
def detect_indian_ids(path: str, text: str) -> list[Detection]:
    out: list[Detection] = []
    for n, line in _lines(text):
        for m in P.AADHAAR.finditer(line):
            digits = "".join(m.groups())
            if verhoeff_valid(digits):
                out.append(_det("indian_ids", "aadhaar", "government_id", path, n, line, 0.95))
        for _ in P.PAN.finditer(line):
            out.append(_det("indian_ids", "pan", "government_id", path, n, line, 0.85))
        for m in P.GSTIN.finditer(line):
            if gstin_valid(m.group(0)):
                out.append(_det("indian_ids", "gstin", "government_id", path, n, line, 0.95))
        for _ in P.UPI.finditer(line):
            out.append(_det("indian_ids", "upi", "financial", path, n, line, 0.8))
        for _ in P.IFSC.finditer(line):
            out.append(_det("indian_ids", "ifsc", "financial", path, n, line, 0.7))
        for _ in P.IN_MOBILE.finditer(line):
            out.append(_det("indian_ids", "in_mobile", "contact", path, n, line, 0.7))
        for _ in P.VOTER_ID.finditer(line):
            out.append(_det("indian_ids", "voter_id", "government_id", path, n, line, 0.5))
        if _has_id_context(line, ("passport",)):
            for _ in P.PASSPORT.finditer(line):
                out.append(_det("indian_ids", "passport", "government_id", path, n, line, 0.6))
    return out


def _has_id_context(line: str, words: tuple[str, ...]) -> bool:
    low = line.lower()
    return any(w in low for w in words)


# ---------------------------------------------------------------------------
_FAKE_EMAIL_DOMAINS = re.compile(r"@(?:example\.(?:com|org|net)|test\.com|localhost)\b", re.I)


@register_text_detector("generic_pii")
def detect_generic_pii(path: str, text: str) -> list[Detection]:
    out: list[Detection] = []
    for n, line in _lines(text):
        for m in P.EMAIL.finditer(line):
            # Skip things that are really UPI handles (handled above) - they lack a dot TLD anyway.
            conf = 0.5 if _FAKE_EMAIL_DOMAINS.search(m.group(0)) else 0.85
            out.append(_det("generic_pii", "email", "contact", path, n, line, conf))
        for _ in P.INTL_PHONE.finditer(line):
            out.append(_det("generic_pii", "phone", "contact", path, n, line, 0.6))
        for m in P.CARD.finditer(line):
            digits = re.sub(r"\D", "", m.group(0))
            if 13 <= len(digits) <= 19 and luhn_valid(digits):
                out.append(_det("generic_pii", "card_number", "financial", path, n, line, 0.9))
    return out


# ---------------------------------------------------------------------------
@register_text_detector("secrets")
def detect_secrets(path: str, text: str) -> list[Detection]:
    out: list[Detection] = []
    for n, line in _lines(text):
        found_specific = False
        for name, pat in P.SECRET_PATTERNS.items():
            if pat.search(line):
                out.append(_det("secrets", f"secret:{name}", "secret", path, n, line, 0.95))
                found_specific = True
        if found_specific:
            continue
        for m in P.SECRET_ASSIGNMENT.finditer(line):
            value = m.group("value")
            if P.PLACEHOLDER_VALUE.match(value):
                continue
            # Unquoted values in code are expressions (password=hash(pw)), not literals.
            if not m.group("quote") and not _is_config_file(path):
                continue
            if re.fullmatch(r"[\w.]+\(.*", value):
                continue
            out.append(_det("secrets", "secret:hardcoded_assignment", "secret", path, n, line, 0.75))
    return out


_CONFIG_SUFFIXES = (".env", ".ini", ".cfg", ".conf", ".properties", ".toml", ".yaml", ".yml")


def _is_config_file(path: str) -> bool:
    base = path.rsplit("/", 1)[-1].lower()
    return base.endswith(_CONFIG_SUFFIXES) or base.startswith(".env")


def run_text_detectors(path: str, text: str, names: Iterable[str] | None = None) -> list[Detection]:
    selected = names or TEXT_DETECTORS.keys()
    results: list[Detection] = []
    for name in selected:
        results.extend(TEXT_DETECTORS[name](path, text))
    return results
