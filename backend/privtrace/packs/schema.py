"""Pydantic schema for compliance packs (YAML files in `packs/`).

Packs are data, not code: the engine never special-cases a pack id.
"""

from __future__ import annotations

import re
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, HttpUrl, field_validator, model_validator

from privtrace.models.enums import CheckType, Severity

_ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]*$")
_RULE_ID_RE = re.compile(r"^[A-Z0-9]+(-[A-Z0-9]+)+$")


class PackRule(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    title: str
    reference: str = Field(description="Act + section/rule number. Never invented.")
    reference_verified: bool = False
    source_url: HttpUrl
    severity: Severity
    check_type: CheckType
    detector: str | None = Field(
        default=None, description="Name of a registered check function (automated/hybrid)."
    )
    detector_params: dict[str, Any] = Field(default_factory=dict)
    question: str | None = Field(
        default=None, description="Yes/no question for manual and hybrid rules."
    )
    why_it_matters: str
    remediation: str
    tags: list[str] = Field(default_factory=list)

    @field_validator("id")
    @classmethod
    def _rule_id_format(cls, v: str) -> str:
        if not _RULE_ID_RE.match(v):
            raise ValueError(f"rule id {v!r} must look like 'DPDP-SEC-01'")
        return v

    @field_validator("reference", "title", "why_it_matters", "remediation")
    @classmethod
    def _non_empty(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("must not be empty")
        return v.strip()

    @model_validator(mode="after")
    def _check_type_consistency(self) -> PackRule:
        if self.check_type in (CheckType.automated, CheckType.hybrid) and not self.detector:
            raise ValueError(f"{self.id}: {self.check_type} rules need a 'detector'")
        if self.check_type in (CheckType.manual, CheckType.hybrid) and not self.question:
            raise ValueError(f"{self.id}: {self.check_type} rules need a 'question'")
        if self.check_type == CheckType.manual and self.detector:
            raise ValueError(f"{self.id}: manual rules must not set a 'detector'")
        return self


class Pack(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    name: str
    short_name: str
    jurisdiction: str
    version: str
    source_url: HttpUrl
    description: str = ""
    rules: list[PackRule]

    @field_validator("id")
    @classmethod
    def _pack_id_format(cls, v: str) -> str:
        if not _ID_RE.match(v):
            raise ValueError(f"pack id {v!r} must be lowercase kebab-case")
        return v

    @model_validator(mode="after")
    def _unique_rule_ids(self) -> Pack:
        seen: set[str] = set()
        for r in self.rules:
            if r.id in seen:
                raise ValueError(f"duplicate rule id {r.id} in pack {self.id}")
            seen.add(r.id)
        if not self.rules:
            raise ValueError(f"pack {self.id} has no rules")
        return self

    # ---- summary helpers (shown in the pack picker) ----
    def count(self, check_type: CheckType) -> int:
        return sum(1 for r in self.rules if r.check_type == check_type)

    @property
    def unverified_references(self) -> list[PackRule]:
        return [r for r in self.rules if not r.reference_verified]

    def summary(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "short_name": self.short_name,
            "jurisdiction": self.jurisdiction,
            "version": self.version,
            "source_url": str(self.source_url),
            "description": self.description,
            "rule_count": len(self.rules),
            "automated": self.count(CheckType.automated),
            "hybrid": self.count(CheckType.hybrid),
            "manual": self.count(CheckType.manual),
            "unverified_references": len(self.unverified_references),
        }
