"""Phase 9: end-to-end on the demo apps — the score must go from low to high after fixes."""

from pathlib import Path

import pytest
from typer.testing import CliRunner

from privtrace.cli import app as cli_app
from privtrace.models.enums import RiskLevel, RuleStatus
from privtrace.scan import run_scan

ROOT = Path(__file__).resolve().parents[2]
DEMO, FIXED = ROOT / "demo-app", ROOT / "demo-app-fixed"
pytestmark = pytest.mark.skipif(not DEMO.exists(), reason="demo apps not present")


@pytest.fixture(scope="module")
def scans():
    before, _ = run_scan(DEMO, ["dpdp", "security"])
    after, _ = run_scan(FIXED, ["dpdp", "security"], baseline=before)
    return before, after


def status(result, rule_id):
    return next(r for r in result.results if r.rule_id == rule_id)


def test_demo_app_scores_low_with_specific_findings(scans):
    before, _ = scans
    assert before.overall_score < 30
    assert before.risk_level == RiskLevel.critical
    expected = {
        "DPDP-SEC-01": "app/llm.py",      # PII into the Gemini prompt (via main.py)
        "DPDP-SEC-02": "app/main.py",     # request body + PII logged
        "DPDP-SEC-03": "app/main.py",     # plaintext password stored
        "DPDP-ERA-01": "app/main.py",     # delete only touches Postgres
        "DPDP-RET-01": "app/cache.py",    # Redis profile without TTL
        "SECB-SECRET-01": "app/config.py",
        "SECB-SECRET-02": ".env",
        "SECB-INJ-01": "app/main.py",
        "SECB-CFG-01": "app/config.py",
        "SECB-CFG-02": "app/main.py",
    }
    for rule_id, file in expected.items():
        r = status(before, rule_id)
        assert r.status == RuleStatus.failed, rule_id
        assert any(e.file == file and e.line > 0 for e in r.evidence), (rule_id, [e.file for e in r.evidence])
    erasure = status(before, "DPDP-ERA-01")
    assert "cache" in erasure.message and "vector_store" in erasure.message
    assert erasure.fix_diff and "delete" in erasure.fix_diff


def test_fixed_app_scores_clearly_higher(scans):
    before, after = scans
    assert after.overall_score >= 80
    assert after.overall_score - before.overall_score >= 50
    assert after.risk_level == RiskLevel.low
    assert not [r.rule_id for r in after.results if r.status == RuleStatus.failed]
    fixed = {f["rule_id"] for f in after.diff["fixed"]}
    assert {"DPDP-SEC-01", "DPDP-ERA-01", "SECB-SECRET-01"} <= fixed


def test_demo_reports_contain_no_raw_fixture_values(scans):
    before, _ = scans
    js = before.model_dump_json()
    for raw in ("asha.demo@example.com", "ABCPD1234F", "98765 00001", "4111 1111 1111 1111", "AIzaSyDEMO_FAKE_KEY_not_a_real_key_0000"):
        assert raw not in js


def test_cli_done_criteria(tmp_path, monkeypatch):
    """`privtrace scan ./demo-app --packs dpdp,security` produces an HTML report with file:line findings."""
    monkeypatch.chdir(tmp_path)
    out = tmp_path / "report.html"
    r = CliRunner().invoke(cli_app, ["scan", str(DEMO), "--packs", "dpdp,security", "--out", str(out), "--no-ai"])
    assert r.exit_code == 0, r.output
    html = out.read_text(encoding="utf-8")
    assert "app/main.py:" in html and "Erasure does not reach every store" in html
