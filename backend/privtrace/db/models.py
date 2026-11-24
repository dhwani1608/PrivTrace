"""Persistence for scans (Postgres in docker-compose / Cloud SQL, SQLite locally)."""

from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import Boolean, DateTime, Float, Integer, String, Text
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


class CiRunRecord(Base):
    """One `privtrace ci --upload` result. Code-free by construction (validated as CiReport)."""

    __tablename__ = "ci_runs"

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    received_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now, index=True)
    repo: Mapped[str] = mapped_column(String(200), index=True)
    ref: Mapped[str | None] = mapped_column(String(200), nullable=True)
    sha: Mapped[str | None] = mapped_column(String(64), nullable=True)
    pr_number: Mapped[int | None] = mapped_column(Integer, nullable=True)
    provider: Mapped[str] = mapped_column(String(20), default="local")
    passed: Mapped[bool] = mapped_column(Boolean)
    overall_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    overall_delta: Mapped[float | None] = mapped_column(Float, nullable=True)
    new_count: Mapped[int] = mapped_column(Integer, default=0)
    fixed_count: Mapped[int] = mapped_column(Integer, default=0)
    report_json: Mapped[str] = mapped_column(Text)  # the validated CiReport
