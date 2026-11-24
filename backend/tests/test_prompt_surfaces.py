"""v2 feature 1: prompts reach every surface (JSON, HTML, CLI)."""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest
from typer.testing import CliRunner

from privtrace.cli import app as cli_app
from privtrace.report.html_report import render_html
from privtrace.scan import run_scan

ROOT = Path(__file__).resolve().parents[2]
DEMO = ROOT / "demo-app"
runner = CliRunner()


@pytest.fixture(scope="module")
def demo():
    return run_scan(DEMO, ["dpdp", "security"])[0]


def test_json_report_carries_prompts(demo):
    data = json.loads(demo.model_dump_json())
    assert data["fix_all_prompt"].startswith("# Fix the top")
    assert data["findings"] and all(f["fix_prompt"] for f in data["findings"])
    assert all(len(f["fingerprint"]) == 16 and f["id"] == f["fingerprint"][:10] for f in data["findings"])
    assert "app/main.py" in data["file_prompts"]
    failed = [r for r in data["results"] if r["status"] == "failed"]
    assert failed and all(r["fix_prompt"] for r in failed)


def test_old_json_reports_still_load():
    """Reports saved before v2 have none of the new fields."""
    from privtrace.models.results import ScanResult

    data = json.loads(run_scan(DEMO, ["dpdp"], prompts=False)[0].model_dump_json())
    for k in ("findings", "file_prompts", "fix_all_prompt", "suppressions", "disabled_rules"):
        data.pop(k)
    for r in data["results"]:
        r.pop("fix_prompt"), r.pop("fix_prompt_ai_enriched")
    assert ScanResult.model_validate(data).findings == []


def test_html_report_has_copy_buttons_that_work_offline(demo):
    html = render_html(demo)
    assert 'data-copy="prompt-all"' in html and "Copy fix-all prompt" in html
    assert "Copy prompt for this file" in html
    n_rules = sum(1 for r in demo.results if r.fix_prompt)
    assert html.count(">Copy AI fix prompt<") == n_rules
    # prompt text is embedded (escaped) so the copy works from a file opened from disk
    assert '<textarea class="prompt-src" id="prompt-dpdp-2023-DPDP-SEC-02" readonly># Fix a data-protection finding' in html
    assert "document.execCommand(\"copy\")" in html  # fallback when the Clipboard API is unavailable
    assert re.search(r"<dialog class=\"pt-dialog\"", html)


def test_cli_prompt_by_rule_file_finding_and_all(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    base = ["prompt", "--target", str(DEMO), "--packs", "dpdp,security"]
    r = runner.invoke(cli_app, [*base, "DPDP-SEC-02"])
    assert r.exit_code == 0, r.output
    assert r.output.startswith("# Fix a data-protection finding: Personal data written to application logs")

    r = runner.invoke(cli_app, [*base, "--file", "./app/main.py"])
    assert r.exit_code == 0 and r.output.startswith("# Fix all PrivTrace findings in `app/main.py`")

    r = runner.invoke(cli_app, [*base, "--all", "--top", "3"])
    assert r.exit_code == 0 and r.output.startswith("# Fix the top 3 PrivTrace findings")

    fid = run_scan(DEMO, ["dpdp", "security"], prompts=False)[0].findings[0].id
    r = runner.invoke(cli_app, [*base, fid])
    assert r.exit_code == 0 and "## 9. Disclaimer" in r.output

    r = runner.invoke(cli_app, [*base, "nope-not-an-id"])
    assert r.exit_code == 1
    r = runner.invoke(cli_app, [*base])
    assert r.exit_code != 0


def test_scan_summary_shows_finding_ids(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    r = runner.invoke(cli_app, ["scan", str(DEMO), "--packs", "dpdp", "--no-ai", "--no-history"])
    assert r.exit_code == 0
    assert re.search(r"id [0-9a-f]{10}", r.output)
    assert "privtrace prompt" in r.output
