"""v2 feature 2: SARIF 2.1.0, PR comment / job summary Markdown, GitLab Code Quality."""

from __future__ import annotations

import json
import re
from pathlib import Path

import jsonschema
import pytest
from typer.testing import CliRunner

from privtrace.ci.baseline import baseline_from_result, write_baseline
from privtrace.ci.outputs import COMMENT_MARKER, GITHUB_COMMENT_LIMIT, render_markdown, to_codequality, to_sarif
from privtrace.ci.runner import CiOptions, run_ci
from privtrace.cli import app as cli_app
from privtrace.fixprompt import PROMPT_DISCLAIMER
from privtrace.scan import run_scan

ROOT = Path(__file__).resolve().parents[2]
DEMO = ROOT / "demo-app"
SCHEMA = json.loads((Path(__file__).parent / "data" / "sarif-schema-2.1.0.json").read_text(encoding="utf-8"))
runner = CliRunner()

CLEAN = '''import logging

from fastapi import FastAPI
from pydantic import BaseModel

logger = logging.getLogger("app")
app = FastAPI()


class SignupRequest(BaseModel):
    email: str


@app.post("/signup")
def signup(req: SignupRequest):
    logger.info("signup ok")
    return {"ok": True}
'''
LEAK = CLEAN.replace('logger.info("signup ok")', 'logger.info("signup %s", req.email)')


@pytest.fixture(scope="module")
def demo_run():
    return run_ci(CiOptions(root=DEMO, packs="dpdp,certin,security"))


@pytest.fixture()
def pr_run(tmp_path):
    """Baseline = clean code; HEAD adds one log leak."""
    (tmp_path / "app.py").write_text(CLEAN, encoding="utf-8")
    (tmp_path / ".privtrace.yml").write_text("version: 1\npacks: [dpdp]\n", encoding="utf-8")
    write_baseline(baseline_from_result(run_scan(tmp_path, ["dpdp"], prompts=False)[0]), tmp_path / ".privtrace-baseline.json")
    (tmp_path / "app.py").write_text(LEAK, encoding="utf-8")
    return run_ci(CiOptions(root=tmp_path))


# ---------------------------------------------------------------- SARIF
def test_sarif_validates_against_the_2_1_0_schema(demo_run):
    sarif = to_sarif(demo_run)
    jsonschema.validate(sarif, SCHEMA)
    run = sarif["runs"][0]
    assert sarif["version"] == "2.1.0" and run["tool"]["driver"]["name"] == "PrivTrace"
    assert len(run["results"]) == len(demo_run.head.findings)


def test_sarif_rule_metadata_severity_and_fingerprints(demo_run):
    run = to_sarif(demo_run)["runs"][0]
    rules = {r["id"]: r for r in run["tool"]["driver"]["rules"]}
    era = rules["DPDP-ERA-01"]
    assert era["properties"]["security-severity"] == "9.5" and era["defaultConfiguration"]["level"] == "error"
    assert "Why it matters" in era["help"]["markdown"] and "How to fix" in era["help"]["markdown"]
    assert "reference pending review" in era["help"]["text"]
    for res in run["results"]:
        assert re.fullmatch(r"[0-9a-f]{16}", res["partialFingerprints"]["privtrace/v1"])
        assert run["tool"]["driver"]["rules"][res["ruleIndex"]]["id"] == res["ruleId"]
        loc = res["locations"][0]["physicalLocation"]
        assert loc["region"]["startLine"] >= 1 and not loc["artifactLocation"]["uri"].startswith("/")
    levels = {r["level"] for r in run["results"]}
    assert levels <= {"error", "warning", "note"}
    # project-level checklist findings are anchored to the config file
    assert any(r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == ".privtrace.yml" for r in run["results"])


def test_sarif_has_no_code(demo_run):
    """Messages name the sink API (e.g. `→ logger.info`) but never carry source lines."""
    blob = json.dumps(to_sarif(demo_run))
    snippets = {f.snippet for f in demo_run.head.findings if len(f.snippet) > 12}
    assert snippets and not [s for s in snippets if json.dumps(s)[1:-1] in blob]


def test_sarif_baseline_state(pr_run):
    results = to_sarif(pr_run)["runs"][0]["results"]
    states = {r["ruleId"]: r["baselineState"] for r in results}
    assert states["DPDP-SEC-02"] == "new"
    assert "unchanged" in states.values()


# ---------------------------------------------------------------- Markdown
def test_pr_comment_content(pr_run):
    md = render_markdown(pr_run, report_url="https://example.invalid/report")
    assert md.startswith(COMMENT_MARKER)  # the action finds and updates this comment instead of adding one
    assert "## ❌ PrivTrace gate failed" in md
    assert "| **Overall** |" in md and "▼" in md
    assert "### New findings (1)" in md
    assert "| 🟧 high | `DPDP-SEC-02` Personal data written to application logs | `app.py:16` | **blocking** |" in md
    assert "<summary>Fix prompt: <code>DPDP-SEC-02</code> at <code>app.py:16</code></summary>" in md
    assert "<b>Fix all new findings</b>" in md
    assert "[Full report](https://example.invalid/report)" in md
    assert PROMPT_DISCLAIMER in md
    assert "compliant" not in md.lower().replace("non-compliance", "")


def test_pr_comment_when_passing_and_fixed(tmp_path):
    (tmp_path / "app.py").write_text(LEAK, encoding="utf-8")
    (tmp_path / ".privtrace.yml").write_text("version: 1\npacks: [dpdp]\n", encoding="utf-8")
    write_baseline(baseline_from_result(run_scan(tmp_path, ["dpdp"], prompts=False)[0]), tmp_path / ".privtrace-baseline.json")
    (tmp_path / "app.py").write_text(CLEAN, encoding="utf-8")
    run = run_ci(CiOptions(root=tmp_path))
    md = render_markdown(run)
    assert run.decision.passed
    assert "## ✅ PrivTrace gate passed" in md and "### Fixed 🎉 (1)" in md and "`DPDP-SEC-02`" in md
    assert "No new findings in this change" in md


def test_pr_comment_fits_github_limit(demo_run):
    md = render_markdown(demo_run, max_prompts=50)
    assert len(md) <= GITHUB_COMMENT_LIMIT
    small = render_markdown(demo_run, limit=8_000)
    assert len(small) <= 8_000


def test_pr_comment_prompts_are_fenced_safely(pr_run):
    md = render_markdown(pr_run)
    block = md.split("<summary>Fix prompt:", 1)[1].split("</details>", 1)[0]
    fence = re.search(r"^(`{4,})markdown$", block, re.M)
    assert fence, "prompt contains ``` fences, so the outer fence must be longer"
    assert block.rstrip().endswith(fence.group(1))


def test_suppressions_and_disabled_rules_are_listed(tmp_path):
    code = LEAK.replace("req.email)", 'req.email)  # privtrace-ignore: DPDP-SEC-02 reason="ids only"')
    (tmp_path / "app.py").write_text(code, encoding="utf-8")
    (tmp_path / ".privtrace.yml").write_text(
        'version: 1\npacks: [dpdp]\nrules:\n  disable: {DPDP-CHD-01: "adults only service"}\n', encoding="utf-8")
    md = render_markdown(run_ci(CiOptions(root=tmp_path)))
    assert "Suppressions (1) and disabled rules (1)" in md
    assert "ids only" in md and "adults only service" in md


# ---------------------------------------------------------------- job summary, code quality, CLI flags
def test_cli_writes_all_outputs_and_job_summary(tmp_path, monkeypatch):
    (tmp_path / "app.py").write_text(LEAK, encoding="utf-8")
    (tmp_path / ".privtrace.yml").write_text("version: 1\npacks: [dpdp]\n", encoding="utf-8")
    summary = tmp_path / "summary.md"
    summary.write_text("earlier step\n", encoding="utf-8")
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary))
    out = tmp_path / "out"
    r = runner.invoke(cli_app, ["ci", str(tmp_path), "--sarif", str(out / "o.sarif"), "--markdown", str(out / "c.md"),
                                "--json", str(out / "o.json"), "--html", str(out / "r.html"),
                                "--gitlab-codequality", str(out / "gl.json")])
    assert r.exit_code == 1, r.output
    jsonschema.validate(json.loads((out / "o.sarif").read_text(encoding="utf-8")), SCHEMA)
    assert (out / "c.md").read_text(encoding="utf-8").startswith(COMMENT_MARKER)
    assert "Copy AI fix prompt" in (out / "r.html").read_text(encoding="utf-8")
    text = summary.read_text(encoding="utf-8")
    assert text.startswith("earlier step\n") and "PrivTrace gate failed" in text

    gl = json.loads((out / "gl.json").read_text(encoding="utf-8"))
    leak = next(i for i in gl if i["check_name"] == "DPDP-SEC-02")
    assert leak["severity"] == "critical" and leak["location"] == {"path": "app.py", "lines": {"begin": 16}}
    assert len({i["fingerprint"] for i in gl}) == len(gl)


def test_no_summary_flag(tmp_path, monkeypatch):
    (tmp_path / "app.py").write_text(CLEAN, encoding="utf-8")
    (tmp_path / ".privtrace.yml").write_text("version: 1\npacks: [dpdp]\n", encoding="utf-8")
    summary = tmp_path / "summary.md"
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary))
    runner.invoke(cli_app, ["ci", str(tmp_path), "--no-summary"])
    assert not summary.exists()


def test_codequality_shape(demo_run):
    for issue in to_codequality(demo_run):
        assert set(issue) >= {"description", "check_name", "fingerprint", "severity", "location"}
        assert issue["severity"] in {"info", "minor", "major", "critical", "blocker"}
