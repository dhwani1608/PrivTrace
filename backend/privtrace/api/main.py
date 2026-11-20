"""FastAPI application factory."""

from __future__ import annotations

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from privtrace import DISCLAIMER, __version__
from privtrace.core.config import get_settings
from privtrace.packs.loader import PackLoadError, load_packs


def create_app() -> FastAPI:
    settings = get_settings()
    app = FastAPI(
        title="PrivTrace API",
        version=__version__,
        description="Multi-framework compliance scanner. " + DISCLAIMER,
    )
    # Explicit origin list, never "*": we practise what the security pack preaches.
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_methods=["GET", "POST", "DELETE"],
        allow_headers=["*"],
    )

    @app.get("/health")
    def health() -> dict[str, object]:
        return {
            "status": "ok",
            "version": __version__,
            "ai_configured": settings.gemini_configured,
        }

    @app.get("/api/packs")
    def list_packs() -> list[dict[str, object]]:
        try:
            packs = load_packs()
        except PackLoadError as e:
            raise HTTPException(status_code=500, detail=str(e)) from e
        return [p.summary() for p in packs.values()]

    return app


app = create_app()
