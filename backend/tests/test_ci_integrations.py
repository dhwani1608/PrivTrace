"""v2 feature 2: GitHub Action, example workflows, GitLab / generic templates, pre-commit fast mode."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest
import yaml
from typer.testing import CliRunner

from privtrace.cli import app as cli_app

ROOT = Path(__file__).resolve().parents[2]
runner = CliRunner()
BASH = shutil.which("bash")


def load(rel: str):
    return yaml.safe_load((ROOT / rel).read_text(encoding="utf-8"))


def test_action_inputs_outputs_and_steps():
    a = load("action.yml")
    assert a["runs"]["using"] == "composite"
    assert {"config", "packs", "min-score", "fail-on", "gemini-api-key", "comment"} <= set(a["inputs"])
    assert {"passed", "exit-code", "sarif-file", "report-dir"} <= set(a["outputs"])
    steps = a["runs"]["steps"]
    run_step = next(s for s in steps if s.get("id") == "scan")
    assert "privtrace \"${args[@]}\"" in run_step["run"]
    assert run_step["env"]["PRIVTRACE_PACKS_DIR"].endswith("/packs")
    comment = next(s for s in steps if s.get("uses", "").startswith("actions/github-script"))
    assert "<!-- privtrace-gate -->" in comment["with"]["script"]  # sticky: update, don't duplicate
    assert "updateComment" in comment["with"]["script"]
    # the job fails only in the last step, after the comment was posted
    assert "exit 1" in steps[-1]["run"] and "exit 2" in steps[-1]["run"]


@pytest.mark.skipif(BASH is None, reason="bash not installed")
def test_action_and_generic_scripts_are_valid_bash(tmp_path):
    a = load("action.yml")
    for i, s in enumerate(a["runs"]["steps"]):
        if s.get("shell") == "bash":
            f = tmp_path / f"step{i}.sh"
            f.write_text(s["run"].replace("${{", "__").replace("}}", "__"), encoding="utf-8", newline="\n")
            r = subprocess.run([BASH, "-n", str(f)], capture_output=True, text=True)
            assert r.returncode == 0, (i, r.stderr)
    r = subprocess.run([BASH, "-n", str(ROOT / "examples/generic/privtrace-ci.sh")], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr


def test_example_github_workflow():
    w = load("examples/github/privtrace.yml")
    on = w[True] if True in w else w["on"]  # YAML 1.1 reads the key `on` as boolean true
    assert set(on["pull_request"]["branches"]) == {"main", "production"}
    assert on["push"]["branches"] == ["main"] and on["schedule"]
    assert w["permissions"] == {"contents": "read", "pull-requests": "write", "security-events": "write"}
    steps = w["jobs"]["privtrace"]["steps"]
    assert steps[0]["with"]["fetch-depth"] == 0
    uses = [s.get("uses", "") for s in steps]
    assert any(u.startswith("dhwani1608/PrivTrace") for u in uses)
    assert any(u.startswith("github/codeql-action/upload-sarif") for u in uses)
    assert any(u.startswith("actions/upload-artifact") for u in uses)
    for s in steps[2:]:
        assert s["if"].startswith("always()")  # reports upload even when the gate fails


def test_gitlab_template_and_precommit_hook():
    g = load("examples/gitlab/.gitlab-ci.yml")["privtrace"]
    assert g["artifacts"]["reports"]["codequality"] == "gl-code-quality-report.json"
    assert "--gitlab-codequality" in "\n".join(g["script"])
    hooks = load(".pre-commit-hooks.yaml")
    assert hooks[0]["id"] == "privtrace-fast" and hooks[0]["entry"] == "privtrace precommit"


# ---------------------------------------------------------------- pre-commit fast mode
FAKE_KEY = "AIza" + "Q" * 35


def test_precommit_flags_secrets_and_pii_logs(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "settings.py").write_text(f'GEMINI_API_KEY = "{FAKE_KEY}"\n', encoding="utf-8")
    (tmp_path / "clean.py").write_text("x = 1\n", encoding="utf-8")
    r = runner.invoke(cli_app, ["precommit", "settings.py", "clean.py"])
    assert r.exit_code == 1
    assert "settings.py:1: hardcoded secret" in r.output
    assert FAKE_KEY not in r.output  # never echo the secret

    r = runner.invoke(cli_app, ["precommit", "clean.py"])
    assert r.exit_code == 0, r.output


def test_precommit_respects_suppressions(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "settings.py").write_text(
        f'GEMINI_API_KEY = "{FAKE_KEY}"  # privtrace-ignore: SECB-SECRET-01 reason="test key for docs"\n',
        encoding="utf-8")
    assert runner.invoke(cli_app, ["precommit", "settings.py"]).exit_code == 0


def test_precommit_with_nothing_staged(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    assert runner.invoke(cli_app, ["precommit"]).exit_code == 0
