"""Shared enums. Status values deliberately never say 'compliant' / 'non-compliant'."""

from __future__ import annotations

from enum import StrEnum


class Severity(StrEnum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"

    @property
    def weight(self) -> int:
        return SEVERITY_WEIGHTS[self]

    @property
    def rank(self) -> int:
        """Higher = more severe. Useful for sorting."""
        return {"critical": 4, "high": 3, "medium": 2, "low": 1}[self.value]


SEVERITY_WEIGHTS: dict[Severity, int] = {
    Severity.critical: 10,
    Severity.high: 6,
    Severity.medium: 3,
    Severity.low: 1,
}


class CheckType(StrEnum):
    automated = "automated"
    manual = "manual"
    hybrid = "hybrid"  # automated evidence + a manual question


class RuleStatus(StrEnum):
    passed = "passed"
    failed = "failed"
    needs_review = "needs_review"
    not_assessable = "not_assessable"


class ManualAnswerValue(StrEnum):
    yes = "yes"
    no = "no"
    not_sure = "not_sure"


class RiskLevel(StrEnum):
    low = "Low"
    medium = "Medium"
    high = "High"
    critical = "Critical"
