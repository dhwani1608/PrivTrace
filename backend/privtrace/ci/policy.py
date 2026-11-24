"""Apply `.privtrace.yml` and inline suppressions to deterministic rule results.

Runs right after `rules.engine.evaluate()` and before fixes, prompts and scoring, so every report
format, the scores and the gate all see the same results. Nothing here calls an LLM.

1. Rules in `rules.disable` are removed (and listed under "Rules turned off by config").
2. `rules.severity_overrides` change a rule's severity (and therefore its scoring weight).
3. Evidence outside `paths.include` / inside `paths.exclude` is dropped.
4. Evidence covered by an active `privtrace-ignore` comment is dropped.
   If every location of a failed / needs-review rule is dropped, the rule is reported as passed,
   with a message saying why. Suppressions are listed in every report.
"""

from __future__ import annotations

from collections.abc import Iterable
from datetime import date

from privtrace.ci.config import PrivTraceConfig
from privtrace.ci.suppress import Suppression, find_suppressions
from privtrace.findings import SourceCache
from privtrace.models.enums import RuleStatus
from privtrace.models.results import RuleResult

ACTIONABLE = (RuleStatus.failed, RuleStatus.needs_review)


def apply_policy(
    results: list[RuleResult], cfg: PrivTraceConfig | None, src: SourceCache, files: Iterable[str],
    *, today: date | None = None,
) -> tuple[list[RuleResult], list[dict], list[dict]]:
    """Return (results, suppressions as dicts, disabled rules as dicts)."""
    today = today or date.today()
    disabled: list[dict] = []
    if cfg is not None:
        off = cfg.disabled
        kept: list[RuleResult] = []
        for r in results:
            if r.rule_id in off:
                disabled.append({"pack_id": r.pack_id, "rule_id": r.rule_id, "title": r.title,
                                 "reason": off[r.rule_id], "status_before": r.status.value})
            else:
                kept.append(r)
        results = kept
        for r in results:
            if r.rule_id in cfg.rules.severity_overrides:
                r.severity = cfg.rules.severity_overrides[r.rule_id]

    sups = find_suppressions(src, files, today)
    for r in results:
        if r.status not in ACTIONABLE or not r.evidence:
            continue
        keep, out_of_scope, suppressed = [], 0, 0
        for e in r.evidence:
            if cfg is not None and not cfg.paths.in_scope(e.file):
                out_of_scope += 1
                continue
            hit = _matching(sups, r.rule_id, e.file, e.line)
            if hit is not None:
                hit.matched += 1
                suppressed += 1
                continue
            keep.append(e)
        if not (out_of_scope or suppressed):
            continue
        why = []
        if suppressed:
            why.append(f"{suppressed} suppressed inline")
        if out_of_scope:
            why.append(f"{out_of_scope} outside the configured paths")
        r.evidence = keep
        if keep:
            r.message = f"{r.message} ({'; '.join(why)}.)"
        else:
            r.message = (f"All flagged locations are excluded ({'; '.join(why)}). "
                         f"Originally: {r.message}")
            r.status = RuleStatus.passed
    for s in sups:
        if s.state == "active" and s.matched == 0:
            s.state = "unused"
    return results, [s.model_dump() for s in sups], disabled


def _matching(sups: list[Suppression], rule_id: str, file: str, line: int) -> Suppression | None:
    for s in sups:
        if s.file == file and s.state == "active" and s.applies(rule_id, line):
            return s
    return None
