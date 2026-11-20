"""Scan results. Statuses are passed / failed / needs_review / not_assessable, never 'compliant'."""

from __future__ import annotations

from datetime import UTC, datetime

from pydantic import BaseModel, Field

from privtrace.models.enums import CheckType, ManualAnswerValue, RiskLevel, RuleStatus, Severity


class Evidence(BaseModel):
    file: str
    line: int
    snippet: str = ""  # redacted
    detail: str = ""
    confidence: float | None = None


class CheckOutcome(BaseModel):
    """What a registered check returns. Deterministic only."""

    status: RuleStatus
    message: str
    evidence: list[Evidence] = Field(default_factory=list)


class AIEnrichment(BaseModel):
    """Gemini output attached to a rule result. Deliberately has NO status field:
    AI can explain and suggest, it can never change whether a rule passed."""

    explanation: str | None = None
    suggested_fix: str | None = None
    suggested_diff: str | None = None
    model: str | None = None
    ai_generated: bool = True


class RuleResult(BaseModel):
    pack_id: str
    rule_id: str
    title: str
    status: RuleStatus
    severity: Severity
    check_type: CheckType
    reference: str
    reference_verified: bool
    source_url: str
    why_it_matters: str
    remediation: str
    message: str = ""
    evidence: list[Evidence] = Field(default_factory=list)
    question: str | None = None
    manual_answer: ManualAnswerValue | None = None
    fix_diff: str | None = None
    ai: AIEnrichment | None = None
    tags: list[str] = Field(default_factory=list)


class Coverage(BaseModel):
    total: int = 0
    automated_checked: int = 0
    manual_answered: int = 0
    not_assessable: int = 0
    needs_review: int = 0


class PackScore(BaseModel):
    pack_id: str
    name: str
    short_name: str
    score: float | None = Field(description="0-100, None if nothing could be assessed.")
    passed: int = 0
    failed: int = 0
    needs_review: int = 0
    not_assessable: int = 0
    passed_weight: int = 0
    assessed_weight: int = 0
    coverage: Coverage = Field(default_factory=Coverage)


class ScanSummary(BaseModel):
    files_scanned: int = 0
    python_files: int = 0
    models_with_pii: int = 0
    pii_sinks: int = 0
    risky_flows: int = 0


class ScanResult(BaseModel):
    scan_id: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    target: str
    packs: list[str]
    overall_score: float | None
    risk_level: RiskLevel
    pack_scores: list[PackScore]
    results: list[RuleResult]
    summary: ScanSummary = Field(default_factory=ScanSummary)
    data_flow: dict = Field(default_factory=dict)
    manual_answers: dict[str, ManualAnswerValue] = Field(default_factory=dict)
    ai_used: bool = False
    ai_model: str | None = None
    ai_classifications: list[dict] = Field(default_factory=list)
    diff: dict | None = None
    scoring_formula: str = ""
    disclaimer: str = ""
