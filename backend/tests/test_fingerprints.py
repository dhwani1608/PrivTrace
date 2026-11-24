"""v2 feature 2: fingerprints, suppressions, config policy and baselines."""

from __future__ import annotations

import json
from datetime import date
from pathlib import Path

from typer.testing import CliRunner

from privtrace.ci.baseline import baseline_from_result, diff_findings, load_baseline
from privtrace.ci.config import parse_config
from privtrace.ci.suppress import parse_comment
from privtrace.cli import app as cli_app
from privtrace.findings import fingerprint, normalise_code
from privtrace.models.enums import RuleStatus, Severity
from privtrace.scan import run_scan

TODAY = date(2026, 11, 24)
runner = CliRunner()

APP = '''import logging

from fastapi import FastAPI
from pydantic import BaseModel

logger = logging.getLogger("app")
app = FastAPI()


class SignupRequest(BaseModel):
    email: str
    phone: str


@app.post("/signup")
def signup(req: SignupRequest):
{pre}    logger.info("signup %s", req.email){comment}
    return {{"ok": True}}
'''


def scan(tmp_path: Path, pre: str = "", comment: str = "", packs=("dpdp",), cfg=None, extra: str = ""):
    (tmp_path / "app.py").write_text(APP.format(pre=pre, comment=comment) + extra, encoding="utf-8")
    return run_scan(tmp_path, list(packs), config=cfg, today=TODAY, prompts=False)[0]


def log_findings(result):
    return [f for f in result.findings if f.rule_id == "DPDP-SEC-02"]


# ---------------------------------------------------------------- fingerprint stability
def test_fingerprint_survives_line_shifts(tmp_path):
    a = log_findings(scan(tmp_path))
    b = log_findings(scan(tmp_path, pre="    # a comment\n    x = 1\n    y = 2\n"))
    assert len(a) == 1 and len(b) == 1
    assert a[0].line != b[0].line
    assert a[0].fingerprint == b[0].fingerprint
    assert a[0].function == "signup"


def test_fingerprint_survives_whitespace_only_changes():
    assert fingerprint("R-01", "a.py", "f", 'logger.info("x %s",  req.email)') == \
        fingerprint("R-01", "a.py", "f", '    logger.info("x %s", req.email)   ')


def test_fingerprint_changes_when_the_vulnerable_code_changes(tmp_path):
    a = log_findings(scan(tmp_path))
    (tmp_path / "app.py").write_text(
        APP.format(pre="", comment="").replace('logger.info("signup %s", req.email)', 'logger.warning("new user %s", req.phone)'),
        encoding="utf-8")
    b = log_findings(run_scan(tmp_path, ["dpdp"], prompts=False)[0])
    assert len(b) == 1 and a[0].fingerprint != b[0].fingerprint


def test_fingerprint_differs_by_rule_file_function_and_occurrence():
    base = fingerprint("R-01", "a.py", "f", "x = 1")
    assert base != fingerprint("R-02", "a.py", "f", "x = 1")
    assert base != fingerprint("R-01", "b.py", "f", "x = 1")
    assert base != fingerprint("R-01", "a.py", "g", "x = 1")
    assert base != fingerprint("R-01", "a.py", "f", "x = 1", occurrence=1)


def test_fingerprint_ignores_suppression_comments_and_hashes_redacted_code():
    assert normalise_code('log(x)  # privtrace-ignore: R-01 reason="y"') == "log(x)"
    # an identifier and a different identifier of the same kind normalise identically
    assert normalise_code('send("9876543210")') == normalise_code('send("9123456789")')


# ---------------------------------------------------------------- suppressions
def test_parse_comment_states():
    assert parse_comment('x  # privtrace-ignore: DPDP-SEC-02 reason="ok"', TODAY)[3] == "active"
    assert parse_comment('# privtrace-ignore: DPDP-SEC-02, SECB-LOG-01 reason="ok" expires=2027-03-01', TODAY)[:4] == \
        (["DPDP-SEC-02", "SECB-LOG-01"], "ok", "2027-03-01", "active")
    assert parse_comment("# privtrace-ignore: DPDP-SEC-02", TODAY)[3:] == ("invalid", 'reason="..." is required')
    assert parse_comment('# privtrace-ignore: DPDP-SEC-02 reason="ok" expires=2025-01-01', TODAY)[3] == "expired"
    assert parse_comment('# privtrace-ignore: DPDP-SEC-02 reason="ok" expires=soon', TODAY)[3] == "invalid"
    assert parse_comment('# privtrace-ignore: * reason="everything"', TODAY)[3] == "invalid"
    assert parse_comment("x = 1  # normal comment", TODAY) is None


def test_valid_suppression_hides_the_finding_and_is_listed(tmp_path):
    r = scan(tmp_path, comment='  # privtrace-ignore: DPDP-SEC-02 reason="user id only in prod" expires=2027-03-01')
    assert log_findings(r) == []
    rule = next(x for x in r.results if x.rule_id == "DPDP-SEC-02")
    assert rule.status == RuleStatus.passed and "suppressed inline" in rule.message
    assert [(s["state"], s["rule_ids"], s["reason"]) for s in r.suppressions] == \
        [("active", ["DPDP-SEC-02"], "user id only in prod")]


def test_suppression_on_the_line_above(tmp_path):
    r = scan(tmp_path, pre='    # privtrace-ignore: DPDP-SEC-02 reason="reviewed"\n')
    assert log_findings(r) == [] and r.suppressions[0]["state"] == "active"


def test_suppression_without_reason_does_not_suppress(tmp_path):
    r = scan(tmp_path, comment="  # privtrace-ignore: DPDP-SEC-02")
    assert len(log_findings(r)) == 1
    assert r.suppressions[0]["state"] == "invalid"


def test_expired_suppression_turns_back_into_a_finding(tmp_path):
    r = scan(tmp_path, comment='  # privtrace-ignore: DPDP-SEC-02 reason="temporary" expires=2026-01-31')
    assert len(log_findings(r)) == 1
    assert next(x for x in r.results if x.rule_id == "DPDP-SEC-02").status == RuleStatus.failed
    assert r.suppressions[0]["state"] == "expired"


def test_suppression_for_another_rule_is_listed_as_unused(tmp_path):
    r = scan(tmp_path, comment='  # privtrace-ignore: SECB-LOG-01 reason="not this one"')
    assert len(log_findings(r)) == 1
    assert r.suppressions[0]["state"] == "unused"


# ---------------------------------------------------------------- config policy
def test_disabled_rules_are_removed_and_listed(tmp_path):
    cfg = parse_config('version: 1\npacks: [dpdp]\nrules:\n  disable:\n    DPDP-SEC-02: "logs are scrubbed by the platform"\n')
    r = scan(tmp_path, cfg=cfg)
    assert "DPDP-SEC-02" not in {x.rule_id for x in r.results}
    assert r.disabled_rules[0]["rule_id"] == "DPDP-SEC-02"
    assert r.disabled_rules[0]["reason"] == "logs are scrubbed by the platform"
    assert log_findings(r) == []


def test_severity_override_changes_weight(tmp_path):
    cfg = parse_config("version: 1\npacks: [dpdp]\nrules:\n  severity_overrides: {DPDP-SEC-02: low}\n")
    plain, overridden = scan(tmp_path), scan(tmp_path, cfg=cfg)
    assert next(x for x in overridden.results if x.rule_id == "DPDP-SEC-02").severity == Severity.low
    assert overridden.overall_score > plain.overall_score


def test_paths_exclude_drops_findings(tmp_path):
    cfg = parse_config("version: 1\npacks: [dpdp]\npaths:\n  exclude: [app.py]\n")
    r = scan(tmp_path, cfg=cfg)
    assert log_findings(r) == []
    assert "outside the configured paths" in next(x for x in r.results if x.rule_id == "DPDP-SEC-02").message


def test_manual_answers_from_config_are_scored(tmp_path):
    cfg = parse_config("version: 1\npacks: [dpdp]\nmanual_answers:\n  DPDP-BRE-01: yes\n  DPDP-GRV-01: no\n")
    r = scan(tmp_path, cfg=cfg)
    status = {x.rule_id: x.status for x in r.results}
    assert status["DPDP-BRE-01"] == RuleStatus.passed and status["DPDP-GRV-01"] == RuleStatus.failed


# ---------------------------------------------------------------- baseline
def test_baseline_contains_no_code_and_diffs_new_fixed_existing(tmp_path):
    before = scan(tmp_path)
    base = baseline_from_result(before)
    blob = base.model_dump_json()
    assert "logger.info" not in blob and "snippet" not in blob and "fix_prompt" not in blob

    # same code shifted down + one new leak: the old one is existing, the new one is new
    extra = '\n\n@app.post("/otp")\ndef otp(req: SignupRequest):\n    logger.info("otp to %s", req.phone)\n    return {}\n'
    after = scan(tmp_path, pre="    # moved\n", extra=extra)
    d = diff_findings(base, after)
    assert [f.function for f in d.new if f.rule_id == "DPDP-SEC-02"] == ["otp"]
    assert [f.function for f in d.existing if f.rule_id == "DPDP-SEC-02"] == ["signup"]
    assert not [f for f in d.fixed if f.rule_id == "DPDP-SEC-02"]

    (tmp_path / "app.py").write_text(APP.format(pre="", comment="").replace(", req.email", ""), encoding="utf-8")
    fixed = run_scan(tmp_path, ["dpdp"], prompts=False)[0]
    d = diff_findings(base, fixed)
    assert [f.rule_id for f in d.fixed] == ["DPDP-SEC-02"] and not [f for f in d.new if f.rule_id == "DPDP-SEC-02"]


def test_no_baseline_means_everything_is_new(tmp_path):
    r = scan(tmp_path)
    d = diff_findings(None, r)
    assert len(d.new) == len(r.findings) and not d.existing and not d.fixed


def test_baseline_update_cli(tmp_path):
    scan(tmp_path)
    (tmp_path / ".privtrace.yml").write_text("version: 1\npacks: [dpdp]\n", encoding="utf-8")
    res = runner.invoke(cli_app, ["baseline", "update", "--target", str(tmp_path)])
    assert res.exit_code == 0, res.output
    b = load_baseline(tmp_path / ".privtrace-baseline.json")
    assert b.packs == ["dpdp-2023"] and any(f.rule_id == "DPDP-SEC-02" for f in b.findings)
    data = json.loads((tmp_path / ".privtrace-baseline.json").read_text(encoding="utf-8"))
    assert set(data) >= {"schema_version", "findings", "pack_scores", "overall_score"}

    (tmp_path / ".privtrace.yml").write_text("version: 1\npacks: []\n", encoding="utf-8")
    res = runner.invoke(cli_app, ["baseline", "update", "--target", str(tmp_path)])
    assert res.exit_code == 2 and "invalid" in res.output
