"""v2 feature 2: gate logic, `privtrace ci` exit codes, base-branch scans and zero network in CI."""

from __future__ import annotations

import json
import shutil
import socket
import subprocess
from datetime import date
from pathlib import Path

import pytest
from typer.testing import CliRunner

from privtrace.ci.baseline import baseline_from_result, diff_findings
from privtrace.ci.config import GateConfig, parse_config
from privtrace.ci.gate import evaluate_gate
from privtrace.cli import app as cli_app
from privtrace.scan import run_scan

ROOT = Path(__file__).resolve().parents[2]
FIXED = ROOT / "demo-app-fixed"
runner = CliRunner()

CLEAN = '''import logging

from fastapi import FastAPI
from pydantic import BaseModel

logger = logging.getLogger("app")
app = FastAPI()


class SignupRequest(BaseModel):
    email: str
    phone: str


@app.post("/signup")
def signup(req: SignupRequest):
    logger.info("signup ok")
    return {"ok": True}
'''
LEAK = CLEAN.replace('logger.info("signup ok")', 'logger.info("signup %s", req.email)')


def write(tmp: Path, code: str, cfg: str = "version: 1\npacks: [dpdp]\n") -> Path:
    (tmp / "app.py").write_text(code, encoding="utf-8")
    (tmp / ".privtrace.yml").write_text(cfg, encoding="utf-8")
    return tmp


def gate(head, base, **kw):
    g = GateConfig(**kw)
    return evaluate_gate(head, diff_findings(base, head), base, g)


@pytest.fixture()
def clean_and_leak(tmp_path):
    a, b = tmp_path / "a", tmp_path / "b"
    a.mkdir(), b.mkdir()
    (a / "app.py").write_text(CLEAN, encoding="utf-8")
    (b / "app.py").write_text(LEAK, encoding="utf-8")
    base = baseline_from_result(run_scan(a, ["dpdp"], prompts=False)[0])
    head = run_scan(b, ["dpdp"], prompts=False)[0]
    return base, head


# ---------------------------------------------------------------- gate logic
def test_new_high_finding_fails_the_gate(clean_and_leak):
    base, head = clean_and_leak
    d = gate(head, base, fail_on_severity="high")
    assert not d.passed and "new failed finding(s) at or above high" in d.reasons[0]
    assert len(d.blocking) == 1


@pytest.mark.parametrize("threshold,passed", [("critical", True), ("high", False), ("medium", False), ("none", True)])
def test_severity_thresholds(clean_and_leak, threshold, passed):
    base, head = clean_and_leak
    assert gate(head, base, fail_on_severity=threshold).passed is passed


def test_min_score_thresholds(clean_and_leak):
    base, head = clean_and_leak
    score = head.overall_score
    assert gate(head, base, fail_on_severity="none", min_score=score).passed
    d = gate(head, base, fail_on_severity="none", min_score=score + 1)
    assert not d.passed and "below the minimum" in d.reasons[0]
    ps = head.pack_scores[0].score
    assert gate(head, base, fail_on_severity="none", min_score_per_pack={"dpdp-2023": ps}).passed
    assert ps < 100
    d = gate(head, base, fail_on_severity="none", min_score_per_pack={"dpdp-2023": min(100.0, ps + 1)})
    assert not d.passed and "below its minimum" in d.reasons[0]


def test_new_only_vs_all_findings(clean_and_leak):
    _, head = clean_and_leak
    same = baseline_from_result(head)  # the leak is already in the baseline
    assert gate(head, same, new_findings_only=True).passed
    d = gate(head, same, new_findings_only=False)
    assert not d.passed and "failed finding(s) at or above high" in d.reasons[0]


def test_no_baseline_counts_everything_as_new(clean_and_leak):
    _, head = clean_and_leak
    d = gate(head, None)
    assert not d.passed and any("No baseline" in n for n in d.notes)


def test_none_score_fails_a_min_score_gate(tmp_path):
    (tmp_path / "README.md").write_text("nothing to see\n", encoding="utf-8")
    head = run_scan(tmp_path, ["certin"], prompts=False)[0]
    if head.overall_score is None:
        d = gate(head, None, min_score=10)
        assert not d.passed and "could not be computed" in d.reasons[0]


def test_severity_override_and_disabled_rule_change_the_decision(tmp_path):
    (tmp_path / "app.py").write_text(LEAK, encoding="utf-8")
    low = parse_config("version: 1\npacks: [dpdp]\nrules:\n  severity_overrides: {DPDP-SEC-02: low}\n")
    head = run_scan(tmp_path, ["dpdp"], config=low, prompts=False)[0]
    assert gate(head, None, fail_on_severity="high").passed is (
        not [f for f in head.findings if f.status.value == "failed" and f.severity.rank >= 3])
    off = parse_config('version: 1\npacks: [dpdp]\nrules:\n  disable: {DPDP-SEC-02: "scrubbed upstream"}\n')
    head = run_scan(tmp_path, ["dpdp"], config=off, prompts=False)[0]
    assert not [f for f in head.findings if f.rule_id == "DPDP-SEC-02"]


def test_expired_suppression_blocks_again(tmp_path):
    code = LEAK.replace('req.email)', 'req.email)  # privtrace-ignore: DPDP-SEC-02 reason="temp" expires=2026-01-01')
    (tmp_path / "app.py").write_text(code, encoding="utf-8")
    before = run_scan(tmp_path, ["dpdp"], prompts=False, today=date(2025, 12, 1))[0]
    after = run_scan(tmp_path, ["dpdp"], prompts=False, today=date(2026, 2, 1))[0]
    assert gate(before, None).passed or not [f for f in before.findings if f.rule_id == "DPDP-SEC-02"]
    assert not gate(after, None).passed
    assert after.suppressions[0]["state"] == "expired"


# ---------------------------------------------------------------- exit codes
def test_exit_0_when_the_gate_passes(tmp_path):
    write(tmp_path, CLEAN, "version: 1\npacks: [dpdp]\ngate:\n  min_score: 0\n")
    r = runner.invoke(cli_app, ["ci", str(tmp_path), "--json", str(tmp_path / "out.json")])
    assert r.exit_code == 0, r.output
    data = json.loads((tmp_path / "out.json").read_text(encoding="utf-8"))
    assert data["gate"]["passed"] is True


def test_exit_1_when_the_gate_fails(tmp_path):
    write(tmp_path, LEAK)
    r = runner.invoke(cli_app, ["ci", str(tmp_path), "--json", str(tmp_path / "out.json")])
    assert r.exit_code == 1, r.output
    data = json.loads((tmp_path / "out.json").read_text(encoding="utf-8"))
    assert data["gate"]["passed"] is False and data["counts"]["blocking"] == 1
    # the CI result is code-free
    blob = json.dumps(data)
    assert "logger.info" not in blob and "snippet" not in blob and "fix_prompt" not in blob


def test_cli_flags_override_config(tmp_path):
    write(tmp_path, LEAK)
    assert runner.invoke(cli_app, ["ci", str(tmp_path), "--fail-on", "critical"]).exit_code == 0
    assert runner.invoke(cli_app, ["ci", str(tmp_path), "--fail-on", "none", "--min-score", "100"]).exit_code == 1


@pytest.mark.parametrize("cfg", ["version: 1\npacks: []\n", "version: 1\npacks: [nope]\n", "gate: [\n"])
def test_exit_2_on_config_error(tmp_path, cfg):
    write(tmp_path, CLEAN, cfg)
    r = runner.invoke(cli_app, ["ci", str(tmp_path)])
    assert r.exit_code == 2, r.output
    assert "error" in r.output


def test_exit_2_on_missing_config(tmp_path):
    (tmp_path / "app.py").write_text(CLEAN, encoding="utf-8")
    r = runner.invoke(cli_app, ["ci", str(tmp_path)])
    assert r.exit_code == 2 and "not found" in r.output


def test_exit_2_on_scan_error_never_looks_like_a_pass(tmp_path, monkeypatch):
    write(tmp_path, CLEAN)

    def boom(*a, **k):
        raise RuntimeError("disk on fire")

    monkeypatch.setattr("privtrace.scan.run_scan", boom)
    r = runner.invoke(cli_app, ["ci", str(tmp_path)])
    assert r.exit_code == 2 and "could not complete the scan" in r.output


def test_exit_2_on_bad_base_ref(tmp_path):
    if shutil.which("git") is None:
        pytest.skip("git not installed")
    write(tmp_path, CLEAN)
    _git(tmp_path, "init", "-q")
    _commit(tmp_path, "init")
    r = runner.invoke(cli_app, ["ci", str(tmp_path), "--base", "origin/does-not-exist"])
    assert r.exit_code == 2, r.output


# ---------------------------------------------------------------- base branch (git worktree)
def _git(root: Path, *args: str) -> str:
    return subprocess.run(["git", "-C", str(root), *args], check=True, capture_output=True, text=True).stdout


def _commit(root: Path, msg: str) -> None:
    _git(root, "add", "-A")
    _git(root, "-c", "user.name=t", "-c", "user.email=t@example.invalid", "commit", "-q", "-m", msg)


@pytest.mark.skipif(shutil.which("git") is None, reason="git not installed")
def test_base_branch_comparison(tmp_path):
    write(tmp_path, CLEAN)
    _git(tmp_path, "init", "-q", "-b", "main")
    _commit(tmp_path, "base")
    _git(tmp_path, "checkout", "-q", "-b", "feature/risky")
    (tmp_path / "app.py").write_text(LEAK, encoding="utf-8")
    _commit(tmp_path, "risky")
    out = tmp_path / "out.json"
    r = runner.invoke(cli_app, ["ci", str(tmp_path), "--base", "main", "--json", str(out)])
    assert r.exit_code == 1, r.output
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["baseline"]["source"] == "git:main"
    assert [f["rule_id"] for f in data["findings"] if f["state"] == "new" and f["status"] == "failed"] == ["DPDP-SEC-02"]
    assert data["packs"][0]["delta"] < 0
    assert "worktree" not in _git(tmp_path, "status", "--porcelain")
    assert len(_git(tmp_path, "worktree", "list").strip().splitlines()) == 1  # temp worktree removed

    _git(tmp_path, "checkout", "-q", "main")
    _git(tmp_path, "checkout", "-q", "-b", "feature/good")
    (tmp_path / "app.py").write_text(CLEAN + "\n# harmless comment\n", encoding="utf-8")
    _commit(tmp_path, "good")
    r = runner.invoke(cli_app, ["ci", str(tmp_path), "--base", "main"])
    assert r.exit_code == 0, r.output


# ---------------------------------------------------------------- privacy: zero network
def test_ci_with_ai_disabled_makes_no_network_calls(tmp_path, monkeypatch):
    """Even with a Gemini key in the environment, ai.enabled: false means nothing leaves the runner."""
    monkeypatch.setenv("GEMINI_API_KEY", "test-key-not-real")
    monkeypatch.setenv("GEMINI_MODEL", "gemini-test")
    from privtrace.core.config import get_settings

    get_settings.cache_clear()
    calls: list[str] = []

    def no_connect(self, address, *a, **k):
        calls.append(f"connect {address}")
        raise OSError("network blocked by test")

    def no_dns(*a, **k):
        calls.append(f"dns {a[:1]}")
        raise OSError("network blocked by test")

    class NoTransport:
        def __init__(self, *a, **k):
            calls.append("GeminiTransport created")
            raise RuntimeError("must not be created")

    monkeypatch.setattr(socket.socket, "connect", no_connect)
    monkeypatch.setattr(socket.socket, "connect_ex", no_connect)
    monkeypatch.setattr(socket, "getaddrinfo", no_dns)
    monkeypatch.setattr(socket, "create_connection", no_dns)
    monkeypatch.setattr("privtrace.ai.client.GeminiTransport", NoTransport)
    monkeypatch.setattr("privtrace.ai.gateway.GeminiTransport", NoTransport)

    shutil.copytree(FIXED, tmp_path / "repo", ignore=shutil.ignore_patterns("__pycache__"))
    repo = tmp_path / "repo"
    (repo / "app" / "main.py").write_text(
        (repo / "app" / "main.py").read_text(encoding="utf-8") + '\n\n@app.get("/x")\ndef x(req: SignupRequest):\n'
        '    logger.info("x %s", req.email)\n', encoding="utf-8")
    (repo / ".privtrace.yml").write_text("version: 1\npacks: [dpdp, certin, security]\nai:\n  enabled: false\n",
                                         encoding="utf-8")
    try:
        r = runner.invoke(cli_app, ["ci", str(repo), "--json", str(tmp_path / "o.json"), "--html", str(tmp_path / "r.html")])
    finally:
        get_settings.cache_clear()
    assert r.exit_code in (0, 1), r.output
    assert calls == []


def test_network_harness_would_catch_an_ai_call(tmp_path, monkeypatch):
    """Control for the test above: with ai.enabled true the (blocked) transport *is* reached."""
    monkeypatch.setenv("GEMINI_API_KEY", "test-key-not-real")
    monkeypatch.setenv("GEMINI_MODEL", "gemini-test")
    from privtrace.core.config import get_settings

    get_settings.cache_clear()
    calls: list[str] = []

    class NoTransport:
        def __init__(self, *a, **k):
            calls.append("GeminiTransport created")
            raise RuntimeError("blocked")

    monkeypatch.setattr("privtrace.ai.gateway.GeminiTransport", NoTransport)
    write(tmp_path, LEAK, "version: 1\npacks: [dpdp]\nai:\n  enabled: true\n")
    try:
        r = runner.invoke(cli_app, ["ci", str(tmp_path)])
    finally:
        get_settings.cache_clear()
    assert calls == ["GeminiTransport created"]
    assert r.exit_code == 1  # AI unavailable never changes the deterministic decision
