"""v2 feature 2: .privtrace.yml validation and `privtrace init`."""

from __future__ import annotations

from pathlib import Path

import pytest
from typer.testing import CliRunner

from privtrace.ci.config import ConfigError, load_and_validate, load_config, parse_config, validate_against_packs
from privtrace.cli import app as cli_app
from privtrace.models.enums import ManualAnswerValue, Severity
from privtrace.packs.loader import load_packs

runner = CliRunner()

GOOD = """
version: 1
packs: [dpdp-2023, certin, security-baseline]
rules:
  disable:
    - id: CERTIN-POC-01
      reason: "Point of contact handled by the parent company"
  severity_overrides: { DPDP-RET-01: critical }
paths:
  include: [src/, services/]
  exclude: [tests/fixtures/, migrations/]
manual_answers:
  DPDP-BRE-01: yes
  DPDP-PRC-01: not_sure
  CERTIN-INC-01: no
gate:
  min_score: 70
  min_score_per_pack: { dpdp: 75 }
  fail_on_severity: high
  new_findings_only: true
ai:
  enabled: false
report:
  pr_comment: true
  sarif: true
"""


@pytest.fixture(scope="module")
def packs():
    return load_packs()


def test_good_config(packs):
    cfg = parse_config(GOOD)
    assert validate_against_packs(cfg, packs) == []
    assert cfg.packs == ["dpdp-2023", "certin-2022", "security-baseline"]
    # YAML 1.1 reads `yes` / `no` as booleans: they come back as checklist answers
    assert cfg.manual_answers == {"DPDP-BRE-01": ManualAnswerValue.yes, "DPDP-PRC-01": ManualAnswerValue.not_sure,
                                  "CERTIN-INC-01": ManualAnswerValue.no}
    assert cfg.disabled == {"CERTIN-POC-01": "Point of contact handled by the parent company"}
    assert cfg.rules.severity_overrides == {"DPDP-RET-01": Severity.critical}
    assert cfg.gate.min_score_per_pack == {"dpdp-2023": 75}
    assert cfg.ai.enabled is False
    assert cfg.paths.in_scope("src/app.py") and not cfg.paths.in_scope("lib/x.py")
    assert not cfg.paths.in_scope("src/tests/fixtures/x.py")  # excluded even inside an included dir


def test_defaults_are_safe():
    cfg = parse_config("version: 1\npacks: [dpdp]\n")
    assert cfg.ai.enabled is False
    assert cfg.gate.new_findings_only is True
    assert cfg.gate.fail_on_severity == Severity.high
    assert cfg.paths.in_scope("anything/at/all.py")


@pytest.mark.parametrize("text,needle", [
    ("version: 1\npacks: []\n", "packs: List should have at least 1 item"),
    ("version: 2\npacks: [dpdp]\n", "version: Input should be 1"),
    ("version: 1\npacks: [dpdp]\ngate:\n  min_score: 120\n", "gate.min_score: Input should be less than or equal to 100"),
    ("version: 1\npacks: [dpdp]\ngate:\n  fail_on: high\n", "gate.fail_on: unknown key"),
    ("version: 1\npacks: [dpdp]\nrules:\n  disable: [DPDP-RET-01]\n", "has no reason"),
    ("version: 1\npacks: [dpdp]\nrules:\n  disable:\n    - id: DPDP-RET-01\n      reason: ' '\n", "a reason is required"),
    ("version: 1\npacks: [dpdp]\nmanual_answers:\n  DPDP-BRE-01: maybe\n", "manual_answers.DPDP-BRE-01"),
    ("version: 1\npacks: [dpdp]\ngate:\n  fail_on_severity: severe\n", "gate.fail_on_severity"),
    ("packs: [dpdp\n", "not valid YAML"),
    ("", "is empty"),
    ("- just\n- a list\n", "top level must be a mapping"),
])
def test_bad_config_has_clear_errors(text, needle):
    with pytest.raises(ConfigError) as e:
        parse_config(text)
    assert needle in str(e.value), str(e.value)


@pytest.mark.parametrize("text,needle", [
    ("version: 1\npacks: [nope]\n", "unknown pack 'nope'"),
    ("version: 1\npacks: [dpdp]\nrules:\n  severity_overrides: {FAKE-RULE-01: high}\n", "unknown rule 'FAKE-RULE-01'"),
    ("version: 1\npacks: [dpdp]\nmanual_answers: {CERTIN-INC-01: yes}\n", "not selected"),
    ("version: 1\npacks: [dpdp]\nmanual_answers: {DPDP-SEC-02: yes}\n", "automated rule"),
    ("version: 1\npacks: [dpdp]\ngate:\n  min_score_per_pack: {certin: 70}\n", "is not in `packs`"),
])
def test_config_cross_checked_against_packs(tmp_path, packs, text, needle):
    p = tmp_path / ".privtrace.yml"
    p.write_text(text, encoding="utf-8")
    with pytest.raises(ConfigError) as e:
        load_and_validate(p, packs)
    assert needle in str(e.value), str(e.value)


def test_missing_config(tmp_path):
    with pytest.raises(ConfigError) as e:
        load_config(tmp_path / ".privtrace.yml")
    assert "not found" in str(e.value) and "privtrace init" in str(e.value)


def test_init_non_interactive(tmp_path, packs):
    out = tmp_path / ".privtrace.yml"
    r = runner.invoke(cli_app, ["init", "--path", str(out), "--packs", "dpdp,certin,security", "--skip-checklist",
                                "--answer", "DPDP-BRE-01=yes", "--min-score", "75"])
    assert r.exit_code == 0, r.output
    cfg = load_and_validate(out, packs)
    assert cfg.packs == ["dpdp-2023", "certin-2022", "security-baseline"]
    assert cfg.manual_answers == {"DPDP-BRE-01": ManualAnswerValue.yes}
    assert cfg.gate.min_score == 75 and cfg.ai.enabled is False
    r = runner.invoke(cli_app, ["init", "--path", str(out), "--packs", "dpdp"])
    assert r.exit_code == 2 and "already exists" in r.output


def test_init_interactive_walks_the_checklist(tmp_path, packs):
    out = tmp_path / ".privtrace.yml"
    questions = [r for r in packs["dpdp-2023"].rules if r.check_type.value != "automated" and r.question]
    # pack choice, then: first question yes, second no, third not sure, the rest skipped, then min score
    answers = ["dpdp", "y", "n", "?"] + [""] * (len(questions) - 3) + ["80"]
    r = runner.invoke(cli_app, ["init", "--path", str(out)], input="\n".join(answers) + "\n")
    assert r.exit_code == 0, r.output
    cfg = load_and_validate(out, packs)
    assert list(cfg.manual_answers.values()) == [ManualAnswerValue.yes, ManualAnswerValue.no, ManualAnswerValue.not_sure]
    assert list(cfg.manual_answers) == [q.id for q in questions[:3]]
    assert cfg.gate.min_score == 80
    assert "# " in Path(out).read_text(encoding="utf-8")  # comments preserved
