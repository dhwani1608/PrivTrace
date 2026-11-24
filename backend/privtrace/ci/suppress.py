"""Inline suppressions.

    logger.info("signup %s", user_id)  # privtrace-ignore: DPDP-SEC-02 reason="hashed before logging" expires=2027-03-01

    # privtrace-ignore: DPDP-SEC-02, SECB-LOG-01 reason="ids only, checked in review"
    logger.info(...)

Rules:
- A reason is required. Without one the comment is `invalid` and suppresses nothing.
- `expires=YYYY-MM-DD` is optional. After that date the comment is `expired` and the finding is back.
- A trailing comment covers its own line; a comment on its own line covers the next code line
  (and, for a decorated function, the `def` line under the decorators).
- No wildcards: every suppression names the rule ids it hides.
- Every comment found is listed in the report (`active`, `unused`, `expired`, `invalid`).
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from datetime import date

from pydantic import BaseModel, Field

from privtrace.findings import SourceCache

_MARKER = re.compile(r"(?:#|//|--)\s*privtrace-ignore\b(?P<body>.*)$", re.IGNORECASE)
_RULE_ID = re.compile(r"^[A-Z0-9]+(?:-[A-Z0-9]+)+$")
_ATTR = re.compile(r"""(?P<key>reason|expires)\s*=\s*(?:"(?P<dq>[^"]*)"|'(?P<sq>[^']*)'|(?P<bare>\S+))""", re.IGNORECASE)


class Suppression(BaseModel):
    file: str
    line: int = Field(description="Line of the comment.")
    covers: list[int] = Field(default_factory=list, description="Code lines it applies to.")
    rule_ids: list[str] = Field(default_factory=list)
    reason: str = ""
    expires: str | None = None
    state: str = "active"  # active | unused | expired | invalid
    problem: str = ""
    matched: int = 0

    def applies(self, rule_id: str, line: int) -> bool:
        return self.state in ("active", "unused") and rule_id in self.rule_ids and line in self.covers


def parse_comment(text: str, today: date) -> tuple[list[str], str, str | None, str, str] | None:
    """(rule_ids, reason, expires, state, problem) for a line, or None if there is no marker."""
    m = _MARKER.search(text)
    if not m:
        return None
    body = m.group("body").lstrip()
    if body.startswith(":"):
        body = body[1:]
    attrs_at = _ATTR.search(body)
    head = body[: attrs_at.start()] if attrs_at else body
    rule_ids = [t for t in re.split(r"[\s,]+", head.strip()) if t]
    reason, expires = "", None
    for a in _ATTR.finditer(body):
        val = a.group("dq") if a.group("dq") is not None else a.group("sq") if a.group("sq") is not None else a.group("bare")
        if a.group("key").lower() == "reason":
            reason = (val or "").strip()
        else:
            expires = (val or "").strip()
    bad_ids = [r for r in rule_ids if not _RULE_ID.match(r)]
    if not rule_ids or bad_ids:
        problem = "no rule id given" if not rule_ids else f"not a rule id: {', '.join(bad_ids)} (wildcards are not allowed)"
        return rule_ids, reason, expires, "invalid", problem
    if not reason:
        return rule_ids, reason, expires, "invalid", 'reason="..." is required'
    if expires:
        try:
            until = date.fromisoformat(expires)
        except ValueError:
            return rule_ids, reason, expires, "invalid", f"expires={expires!r} is not a YYYY-MM-DD date"
        if until < today:
            return rule_ids, reason, expires, "expired", f"expired on {expires}"
    return rule_ids, reason, expires, "active", ""


def _covered_lines(lines: list[str], idx: int) -> list[int]:
    """1-based lines a comment at 0-based `idx` applies to."""
    text = lines[idx]
    code_before = text[: _MARKER.search(text).start()].strip()  # type: ignore[union-attr]
    if code_before:
        return [idx + 1]
    covers: list[int] = []
    j = idx + 1
    while j < len(lines) and (not lines[j].strip() or _MARKER.search(lines[j]) and not lines[j].split("#")[0].strip()):
        j += 1  # skip blank lines and stacked suppression comments
    while j < len(lines):
        covers.append(j + 1)
        if not lines[j].lstrip().startswith("@"):
            break
        j += 1  # decorators: also cover the def line below them
    return covers


def find_suppressions(src: SourceCache, files: Iterable[str], today: date) -> list[Suppression]:
    out: list[Suppression] = []
    for rel in files:
        lines = src.lines(rel)
        if not lines:
            continue
        for i, text in enumerate(lines):
            if "privtrace-ignore" not in text.lower():
                continue
            parsed = parse_comment(text, today)
            if parsed is None:
                continue
            rule_ids, reason, expires, state, problem = parsed
            out.append(Suppression(
                file=rel, line=i + 1, covers=_covered_lines(lines, i), rule_ids=rule_ids,
                reason=reason, expires=expires, state=state, problem=problem,
            ))
    return out
