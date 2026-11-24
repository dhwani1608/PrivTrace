"""Runtime configuration, loaded from environment variables / `.env`."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

# backend/privtrace/core/config.py -> repo root is three parents above `privtrace/`
_REPO_ROOT = Path(__file__).resolve().parents[3]


def _default_packs_dir() -> Path:
    """Repo-root `packs/` in a checkout; `/app/packs` inside the Docker image."""
    candidate = _REPO_ROOT / "packs"
    return candidate if candidate.is_dir() else Path("/app/packs")


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="", env_file=".env", env_file_encoding="utf-8", extra="ignore"
    )

    app_env: str = Field(default="local", alias="APP_ENV")
    packs_dir: Path = Field(default_factory=_default_packs_dir, alias="PRIVTRACE_PACKS_DIR")

    static_dir: Path | None = Field(default=None, alias="PRIVTRACE_STATIC_DIR")
    database_url: str | None = Field(default=None, alias="DATABASE_URL")
    redis_url: str | None = Field(default=None, alias="REDIS_URL")

    # Gemini is optional: scans complete without it, just without AI explanations.
    gemini_api_key: str | None = Field(default=None, alias="GEMINI_API_KEY")
    gemini_model: str | None = Field(default=None, alias="GEMINI_MODEL")
    ai_enabled: bool = Field(default=True, alias="PRIVTRACE_AI_ENABLED")

    # Hard limits that protect customer code.
    max_snippet_lines: int = Field(default=40, alias="PRIVTRACE_MAX_SNIPPET_LINES")
    max_upload_mb: int = Field(default=50, alias="PRIVTRACE_MAX_UPLOAD_MB")

    # Shared secret for `privtrace ci --upload` (dashboard history). Unset = uploads disabled.
    ci_upload_token: str | None = Field(default=None, alias="PRIVTRACE_CI_TOKEN")

    cors_origins: list[str] = Field(
        default_factory=lambda: ["http://localhost:5173", "http://127.0.0.1:5173"],
        alias="PRIVTRACE_CORS_ORIGINS",
    )

    @property
    def gemini_configured(self) -> bool:
        return bool(self.ai_enabled and self.gemini_api_key and self.gemini_model)


@lru_cache
def get_settings() -> Settings:
    return Settings()
