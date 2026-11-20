"""Persistence for scans (Postgres in docker-compose / Cloud SQL, SQLite locally)."""

from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import DateTime, Float, String, Text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


def _now() -> datetime:
    return datetime.now(UTC)


class Base(DeclarativeBase):
    pass


class ScanRecord(Base):
    __tablename__ = "scans"

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now, onupdate=_now)
    status: Mapped[str] = mapped_column(String(20), default="queued")  # queued|running|done|error
    stage: Mapped[str] = mapped_column(String(40), default="queued")
    message: Mapped[str] = mapped_column(Text, default="")
    source_type: Mapped[str] = mapped_column(String(10))   # github | zip
    source_ref: Mapped[str] = mapped_column(String(500))   # repo URL or uploaded file name
    packs: Mapped[str] = mapped_column(String(500))
    answers_json: Mapped[str] = mapped_column(Text, default="{}")
    baseline_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    overall_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    risk_level: Mapped[str | None] = mapped_column(String(20), nullable=True)
    result_json: Mapped[str | None] = mapped_column(Text, nullable=True)  # redacted ScanResult
