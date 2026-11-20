"""Raw detector output (before rules turn it into findings)."""

from __future__ import annotations

from pydantic import BaseModel, Field


class Detection(BaseModel):
    detector: str = Field(description="Registered detector name, e.g. 'indian_ids'.")
    kind: str = Field(description="What was found, e.g. 'aadhaar', 'secret:google_api_key'.")
    data_category: str = Field(description="e.g. government_id, contact, financial, secret.")
    file: str = Field(description="Repo-relative POSIX path.")
    line: int
    snippet: str = Field(description="The source line, ALWAYS redacted.")
    confidence: float = Field(ge=0.0, le=1.0)
    symbol: str | None = Field(default=None, description="Variable/field name, if relevant.")
