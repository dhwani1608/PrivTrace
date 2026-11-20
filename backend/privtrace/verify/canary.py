"""Verify: a runtime deletion test using a canary value.

1. Create a fake user whose fields contain a unique canary string.
2. Exercise the app so the data spreads (chat, profile, ...).
3. Search every configured store for the canary (proves the test reached it).
4. Call the app's delete endpoint.
5. Search again. Any store that still contains the canary FAILS.

Only ever run this against a local/test deployment you own. It writes test data.
"""

from __future__ import annotations

import re
import subprocess
import uuid
from collections.abc import Callable
from pathlib import Path
from typing import Any

import httpx
import yaml
from pydantic import BaseModel, Field

# ----------------------------------------------------------------- config


class HttpStep(BaseModel):
    method: str = "POST"
    path: str
    json_body: Any = Field(default=None, alias="json")
    save: dict[str, str] = Field(default_factory=dict, description="var -> dotted path in the JSON response")
    expect_status: list[int] = Field(default_factory=lambda: [200, 201, 202, 204])


class StoresConfig(BaseModel):
    postgres: dict[str, Any] | None = None   # {dsn, tables?: [..]}
    redis: dict[str, Any] | None = None      # {url}
    logs: dict[str, Any] | None = None       # {file} or {compose_file, service}


class VerifyConfig(BaseModel):
    name: str = "app"
    base_url: str
    headers: dict[str, str] = Field(default_factory=dict)
    signup: HttpStep
    activity: list[HttpStep] = Field(default_factory=list)
    delete: HttpStep
    stores: StoresConfig
    settle_seconds: float = 0.5

    @classmethod
    def load(cls, path: Path) -> VerifyConfig:
        return cls.model_validate(yaml.safe_load(path.read_text(encoding="utf-8")))


class StoreResult(BaseModel):
    store: str
    found_before_delete: bool | None = None
    found_after_delete: bool | None = None
    status: str = "ERROR"   # PASS | FAIL | ERROR
    detail: str = ""


class VerifyReport(BaseModel):
    app: str
    canary: str
    user_id: Any = None
    results: list[StoreResult]
    error: str | None = None

    @property
    def passed(self) -> bool:
        return self.error is None and all(r.status == "PASS" for r in self.results)


# ----------------------------------------------------------------- templating

_VAR = re.compile(r"\{(\w+)\}")


def render(value: Any, vars_: dict[str, Any]) -> Any:
    """Substitute {var} in strings recursively. A string that is exactly "{var}" keeps the var's type."""
    if isinstance(value, str):
        m = _VAR.fullmatch(value)
        if m and m.group(1) in vars_:
            return vars_[m.group(1)]
        return _VAR.sub(lambda m: str(vars_.get(m.group(1), m.group(0))), value)
    if isinstance(value, dict):
        return {k: render(v, vars_) for k, v in value.items()}
    if isinstance(value, list):
        return [render(v, vars_) for v in value]
    return value


def dig(data: Any, dotted: str) -> Any:
    for part in dotted.split("."):
        data = data[int(part)] if isinstance(data, list) else data[part]
    return data


# ----------------------------------------------------------------- store searchers
Searcher = Callable[[str], tuple[bool, str]]  # canary -> (found, detail)


def postgres_searcher(cfg: dict[str, Any]) -> Searcher:
    import psycopg

    dsn = cfg["dsn"]
    only = set(cfg.get("tables", []))

    def search(canary: str) -> tuple[bool, str]:
        hits = []
        with psycopg.connect(dsn) as conn, conn.cursor() as cur:
            cur.execute(
                "SELECT table_schema, table_name, column_name FROM information_schema.columns "
                "WHERE table_schema NOT IN ('pg_catalog', 'information_schema') "
                "AND data_type IN ('text', 'character varying', 'character', 'json', 'jsonb')"
            )
            for schema, table, col in cur.fetchall():
                if only and table not in only:
                    continue
                q = f'SELECT count(*) FROM "{schema}"."{table}" WHERE "{col}"::text LIKE %s'
                cur.execute(q, (f"%{canary}%",))
                n = cur.fetchone()[0]
                if n:
                    hits.append(f"{table}.{col} ({n} row(s))")
        return bool(hits), ", ".join(hits) or "no rows contain the canary"

    return search


def redis_searcher(cfg: dict[str, Any]) -> Searcher:
    import redis

    client = redis.Redis.from_url(cfg["url"])

    def value_text(key: bytes) -> str:
        t = client.type(key).decode()
        if t == "string":
            return (client.get(key) or b"").decode(errors="replace")
        if t == "hash":
            return " ".join(f"{k!r}{v!r}" for k, v in client.hgetall(key).items())
        if t in ("list",):
            return " ".join(x.decode(errors="replace") for x in client.lrange(key, 0, -1))
        if t == "set":
            return " ".join(x.decode(errors="replace") for x in client.smembers(key))
        if t == "zset":
            return " ".join(x.decode(errors="replace") for x in client.zrange(key, 0, -1))
        return ""

    def search(canary: str) -> tuple[bool, str]:
        hits = []
        for key in client.scan_iter(count=500):
            if canary in key.decode(errors="replace") or canary in value_text(key):
                hits.append(key.decode(errors="replace"))
        return bool(hits), (f"keys: {', '.join(hits[:5])}" if hits else "no keys contain the canary")

    return search


def logs_searcher(cfg: dict[str, Any]) -> Searcher:
    def read() -> str:
        if "file" in cfg:
            p = Path(cfg["file"])
            return p.read_text(encoding="utf-8", errors="replace") if p.exists() else ""
        cmd = ["docker", "compose", "-f", cfg["compose_file"], "logs", "--no-color", cfg["service"]]
        return subprocess.run(cmd, capture_output=True, text=True, timeout=60, errors="replace").stdout

    def search(canary: str) -> tuple[bool, str]:
        n = read().count(canary)
        return n > 0, (f"{n} log line(s) contain the canary" if n else "logs do not contain the canary")

    return search


def build_searchers(stores: StoresConfig) -> dict[str, Searcher]:
    out: dict[str, Searcher] = {}
    if stores.postgres:
        out["postgres (incl. pgvector tables)"] = postgres_searcher(stores.postgres)
    if stores.redis:
        out["redis"] = redis_searcher(stores.redis)
    if stores.logs:
        out["logs"] = logs_searcher(stores.logs)
    return out


# ----------------------------------------------------------------- runner
def run_verify(
    cfg: VerifyConfig,
    searchers: dict[str, Searcher] | None = None,
    client: httpx.Client | None = None,
    sleep: Callable[[float], None] | None = None,
) -> VerifyReport:
    import time

    sleep = sleep or time.sleep
    canary = "ptcanary" + uuid.uuid4().hex[:12]
    searchers = searchers if searchers is not None else build_searchers(cfg.stores)
    vars_: dict[str, Any] = {"canary": canary}
    http = client or httpx.Client(base_url=cfg.base_url, timeout=30)
    report = VerifyReport(app=cfg.name, canary=canary, results=[])

    def call(step: HttpStep) -> Any:
        headers = render(cfg.headers, vars_)
        r = http.request(step.method, render(step.path, vars_), json=render(step.json_body, vars_), headers=headers)
        if r.status_code not in step.expect_status:
            raise RuntimeError(f"{step.method} {step.path} returned HTTP {r.status_code}")
        body = r.json() if r.content and "json" in r.headers.get("content-type", "") else None
        for var, path in step.save.items():
            vars_[var] = dig(body, path)
        return body

    results = {name: StoreResult(store=name) for name in searchers}
    try:
        call(cfg.signup)
        report.user_id = vars_.get("user_id")
        for step in cfg.activity:
            call(step)
        sleep(cfg.settle_seconds)
        for name, search in searchers.items():
            try:
                results[name].found_before_delete, _ = search(canary)
            except Exception as e:
                results[name].detail = f"search failed before delete: {type(e).__name__}"
        call(cfg.delete)
        sleep(cfg.settle_seconds)
        for name, search in searchers.items():
            res = results[name]
            try:
                found, detail = search(canary)
            except Exception as e:
                res.status, res.detail = "ERROR", f"search failed: {type(e).__name__}"
                continue
            res.found_after_delete = found
            if found:
                res.status, res.detail = "FAIL", f"still present after delete — {detail}"
            elif res.found_before_delete:
                res.status, res.detail = "PASS", "present before delete, gone after"
            else:
                res.status, res.detail = "PASS", "canary never reached this store"
    except Exception as e:
        report.error = f"{type(e).__name__}: {e}"
    report.results = list(results.values())
    return report
