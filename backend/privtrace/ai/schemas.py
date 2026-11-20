"""Structured-output schemas for every Gemini call. Responses are validated with these.

None of these carry a rule status: AI output can explain and suggest, never decide.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field


class _Strict(BaseModel):
    model_config = ConfigDict(extra="ignore")  # unexpected keys (e.g. "status") are dropped


class FieldClassification(_Strict):
    name: str
    is_personal_data: bool
    category: str = Field(description="contact, identity, government_id, financial, health, location, credentials, children, other, none")
    reason: str = Field(default="", max_length=300)


class ClassificationResponse(_Strict):
    items: list[FieldClassification]


class FindingExplanation(_Strict):
    explanation: str = Field(description="2-4 plain-language sentences for a developer. No legal verdicts.", max_length=1200)
    suggested_fix: str = Field(default="", description="Concrete change to make, 1-3 sentences.", max_length=800)
    suggested_diff: str | None = Field(default=None, description="Optional unified diff against the snippet.", max_length=4000)


class AIClassificationNote(BaseModel):
    """Shown in the report as 'possible personal data (AI-classified, review)'."""

    name: str
    category: str
    reason: str = ""
    file: str | None = None
    line: int | None = None
