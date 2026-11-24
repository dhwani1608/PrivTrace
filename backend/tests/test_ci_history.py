"""v2 stretch: `privtrace ci --upload` and the CI history API (scores per repo / branch over time)."""

from __future__ import annotations

import json

import httpx
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import sessionmaker
from typer.testing import CliRunner

from privtrace.api.main import create_app
from privtrace.cli import app as cli_app
from privtrace.db.session import make_engine

TOKEN = "test-upload-token"
runner = CliRunner()

LEAK = '''import logging

from fastapi import FastAPI
from pydantic import BaseModel

logger = logging.getLogger("app")
app = FastAPI()


class SignupRequest(BaseModel):
    email: str


@app.post("/signup")
def signup(req: SignupRequest):
    logger.info("signup %s", req.email)
    return {"ok": True}
'''


@pytest.fixture
def api(monkeypatch):
    monkeypatch.setenv("PRIVTRACE_CI_TOKEN", TOKEN)
    from privtrace.core.config import get_settings

    get_settings.cache_clear()
    sm = sessionmaker(bind=make_engine("sqlite:///:memory:"), expire_on_commit=False)
    client = TestClient(create_app(sm, run_inline=True))
    client.sm = sm  # type: ignore[attr-defined]
    yield client
    get_settings.cache_clear()


def ci_json(tmp_path, monkeypatch, *, ref: str, pr: int | None = None) -> str:
    """Run `privtrace ci` as if on GitHub Actions and return its --json output."""
    (tmp_path / "app.py").write_text(LEAK, encoding="utf-8")
    (tmp_path / ".privtrace.yml").write_text("version: 1\npacks: [dpdp]\n", encoding="utf-8")
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.setenv("GITHUB_REPOSITORY", "acme/chatbot")
    monkeypatch.setenv("GITHUB_REF", f"refs/pull/{pr}/merge" if pr else f"refs/heads/{ref}")
    monkeypatch.setenv("GITHUB_HEAD_REF", ref if pr else "")
    monkeypatch.setenv("GITHUB_REF_NAME", ref)
    monkeypatch.setenv("GITHUB_SHA", "a" * 40)
    monkeypatch.setenv("GITHUB_RUN_ID", "42")
    monkeypatch.delenv("GITHUB_STEP_SUMMARY", raising=False)
    out = tmp_path / "out.json"
    r = runner.invoke(cli_app, ["ci", str(tmp_path), "--json", str(out)])
    assert r.exit_code == 1, r.output
    return out.read_text(encoding="utf-8")


def test_upload_requires_a_token(api, tmp_path, monkeypatch):
    body = ci_json(tmp_path, monkeypatch, ref="main")
    assert api.post("/api/ci/runs", content=body).status_code == 401
    assert api.post("/api/ci/runs", content=body, headers={"Authorization": "Bearer nope"}).status_code == 401
    r = api.post("/api/ci/runs", content=body, headers={"Authorization": f"Bearer {TOKEN}"})
    assert r.status_code == 201 and r.json()["repo"] == "acme/chatbot" and r.json()["passed"] is False


def test_uploads_disabled_without_server_token(monkeypatch, tmp_path):
    monkeypatch.delenv("PRIVTRACE_CI_TOKEN", raising=False)
    from privtrace.core.config import get_settings

    get_settings.cache_clear()
    client = TestClient(create_app(sessionmaker(bind=make_engine("sqlite:///:memory:")), run_inline=True))
    assert client.post("/api/ci/runs", content="{}", headers={"Authorization": "Bearer x"}).status_code == 503
    get_settings.cache_clear()


def test_history_per_repo_and_branch_and_no_code_stored(api, tmp_path, monkeypatch):
    auth = {"Authorization": f"Bearer {TOKEN}"}
    main_run = json.loads(ci_json(tmp_path, monkeypatch, ref="main"))
    pr_run = json.loads(ci_json(tmp_path, monkeypatch, ref="feature/x", pr=7))
    pr_run["findings"][0]["snippet"] = "logger.info('a@b.example')"  # a tampered upload carrying code
    pr_run["source_code"] = "print('secret')"
    assert api.post("/api/ci/runs", content=json.dumps(main_run), headers=auth).status_code == 201
    assert api.post("/api/ci/runs", content=json.dumps(pr_run), headers=auth).status_code == 201

    repos = api.get("/api/ci/repos").json()
    assert repos == [{"repo": "acme/chatbot", "runs": 2, "last": repos[0]["last"]}]
    runs = api.get("/api/ci/runs", params={"repo": "acme/chatbot"}).json()
    assert [r["pr_number"] for r in runs] == [7, None]
    assert runs[0]["ref"] == "feature/x" and runs[0]["packs"][0]["pack_id"] == "dpdp-2023"
    assert runs[0]["run_url"].endswith("/acme/chatbot/actions/runs/42")
    only_main = api.get("/api/ci/runs", params={"repo": "acme/chatbot", "ref": "main"}).json()
    assert len(only_main) == 1

    # unknown fields were dropped before storage
    from privtrace.db.models import CiRunRecord

    with api.sm() as s:
        stored = "".join(r.report_json for r in s.query(CiRunRecord).all())
    assert "a@b.example" not in stored and "source_code" not in stored and "snippet" not in stored


def test_cli_upload_sends_the_code_free_report(api, tmp_path, monkeypatch):
    (tmp_path / "app.py").write_text(LEAK, encoding="utf-8")
    (tmp_path / ".privtrace.yml").write_text("version: 1\npacks: [dpdp]\n", encoding="utf-8")
    for var in ("GITHUB_STEP_SUMMARY", "GITHUB_ACTIONS", "GITLAB_CI"):  # behave as a local run, even on CI
        monkeypatch.delenv(var, raising=False)
    sent: list[dict] = []

    def fake_post(url, content=None, headers=None, timeout=None):
        sent.append({"url": url, "body": content, "headers": headers})
        r = api.post("/api/ci/runs", content=content, headers=headers)
        return httpx.Response(r.status_code, text=r.text)

    monkeypatch.setattr(httpx, "post", fake_post)
    r = runner.invoke(cli_app, ["ci", str(tmp_path), "--upload", "https://privtrace.example", "--token", TOKEN])
    assert r.exit_code == 1  # the gate result, unchanged by the upload
    assert sent and sent[0]["url"] == "https://privtrace.example/api/ci/runs"
    assert "logger.info" not in sent[0]["body"] and "fix_prompt" not in sent[0]["body"]
    assert len(api.get("/api/ci/runs", params={"repo": "local"}).json()) == 1

    # a failing upload never turns a failed gate into a pass (or vice versa)
    def broken(*a, **k):
        raise httpx.ConnectError("down")

    monkeypatch.setattr(httpx, "post", broken)
    r = runner.invoke(cli_app, ["ci", str(tmp_path), "--upload", "https://privtrace.example", "--token", TOKEN])
    assert r.exit_code == 1 and "upload failed" in r.output
