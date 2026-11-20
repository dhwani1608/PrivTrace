# Build context is the repo root (see docker-compose.yml) so packs/ can be copied in.
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PRIVTRACE_PACKS_DIR=/app/packs

RUN apt-get update \
 && apt-get install -y --no-install-recommends git \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY backend/pyproject.toml backend/pyproject.toml
COPY backend/privtrace backend/privtrace
RUN pip install ./backend

COPY packs packs

RUN useradd --create-home privtrace
USER privtrace

EXPOSE 8000
CMD ["uvicorn", "privtrace.api.main:app", "--host", "0.0.0.0", "--port", "8000"]
