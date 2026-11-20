"""Scoring. Formula is documented in docs/SCORING.md and printed in every report."""

from __future__ import annotations

from privtrace.models.enums import SEVERITY_WEIGHTS, CheckType, RiskLevel, RuleStatus, Severity
from privtrace.models.results import Coverage, PackScore, RuleResult
from privtrace.packs.schema import Pack

SCORING_FORMULA = (
    "Weights: critical 10, high 6, medium 3, low 1. "
    "Framework score = 100 × (weight of passed rules) ÷ (weight of passed + failed rules). "
    "'Needs review' and 'not assessable' rules are excluded from the score and listed separately. "
    "Manual answers: yes = passed, no = failed, not sure = needs review. "
    "Overall score = sum of passed weight ÷ sum of assessed weight across the selected frameworks "
    "(a weighted average, so frameworks with more assessed rules count more). "
    "Risk level = severity of the most severe failed rule (Low if none failed)."
)


def score_pack(pack: Pack, results: list[RuleResult]) -> PackScore:
    rs = [r for r in results if r.pack_id == pack.id]
    ps = PackScore(pack_id=pack.id, name=pack.name, short_name=pack.short_name, score=None)
    cov = Coverage(total=len(rs))
    for r in rs:
        w = SEVERITY_WEIGHTS[r.severity]
        if r.status == RuleStatus.passed:
            ps.passed += 1
            ps.passed_weight += w
            ps.assessed_weight += w
        elif r.status == RuleStatus.failed:
            ps.failed += 1
            ps.assessed_weight += w
        elif r.status == RuleStatus.needs_review:
            ps.needs_review += 1
        else:
            ps.not_assessable += 1

        if r.status == RuleStatus.not_assessable:
            cov.not_assessable += 1
        elif r.status == RuleStatus.needs_review:
            cov.needs_review += 1
        if r.manual_answer is not None and r.check_type != CheckType.automated:
            cov.manual_answered += 1
        decided_by_code = r.check_type == CheckType.automated or (
            r.check_type == CheckType.hybrid and r.manual_answer is None
        )
        if decided_by_code and r.status in (RuleStatus.passed, RuleStatus.failed):
            cov.automated_checked += 1
    ps.coverage = cov
    if ps.assessed_weight:
        ps.score = round(100 * ps.passed_weight / ps.assessed_weight, 1)
    return ps


def overall_score(scores: list[PackScore]) -> float | None:
    aw = sum(s.assessed_weight for s in scores)
    if not aw:
        return None
    return round(100 * sum(s.passed_weight for s in scores) / aw, 1)


def risk_level(results: list[RuleResult]) -> RiskLevel:
    failed = [r.severity for r in results if r.status == RuleStatus.failed]
    if not failed:
        return RiskLevel.low
    worst = max(failed, key=lambda s: s.rank)
    return {
        Severity.critical: RiskLevel.critical,
        Severity.high: RiskLevel.high,
        Severity.medium: RiskLevel.medium,
        Severity.low: RiskLevel.low,
    }[worst]
