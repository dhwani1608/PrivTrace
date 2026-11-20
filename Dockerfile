# Single-container image: React UI + FastAPI API on one port.
# Used by Render (render.yaml); also works on Hugging Face Spaces / any Docker host.

# ---- 1. build the UI ----
FROM node:20-alpine AS ui
WORKDIR /ui
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY frontend/ ./
RUN npm run build

# ---- 2. API + scanner ----
FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PRIVTRACE_PACKS_DIR=/app/packs \
    PRIVTRACE_STATIC_DIR=/app/static \
    DATABASE_URL=sqlite:////tmp/privtrace.db

# git is needed to clone public GitHub repos for scanning
RUN apt-get update && apt-get install -y --no-install-recommends git \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY backend/pyproject.toml backend/pyproject.toml
COPY backend/privtrace backend/privtrace
RUN pip install ./backend
COPY packs packs
COPY --from=ui /ui/dist static

RUN useradd --create-home privtrace
USER privtrace

# Render sets $PORT; default 8000 elsewhere.
EXPOSE 8000
CMD ["sh", "-c", "uvicorn privtrace.api.main:app --host 0.0.0.0 --port ${PORT:-8000}"]
