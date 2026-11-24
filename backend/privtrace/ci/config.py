"""`.privtrace.yml`: the business's choice of packs, rules and gate thresholds.

Validated with Pydantic (`extra="forbid"`, so typos fail loudly), then cross-checked against the
loaded packs (unknown pack / rule ids are errors). Every error message names the YAML path.
See docs/CI_INTEGRATION.md#privtraceyml-reference.
"""

from __future__ import annotations

import fnmatch
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

from privtrace.models.enums import CheckType, ManualAnswerValue, Severity
from privtrace.packs.loader import PackLoadError, resolve_pack_ids
from privtrace.packs.schema import Pack

DEFAULT_CONFIG_NAME = ".privtrace.yml"
DEFAULT_BASELINE_NAME = ".privtrace-baseline.json"


class ConfigError(Exception):
    """Invalid or missing configuration. `privtrace ci` exits with code 2."""


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class DisabledRule(_Strict):
    id: str
    reason: str

    @field_validator("reason")
    @classmethod
    def _reason_required(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("a reason is required to turn a rule off")
        return v.strip()


class RulesConfig(_Strict):
    disable: list[DisabledRule] = Field(default_factory=list)
    severity_overrides: dict[str, Severity] = Field(default_factory=dict)

    @field_validator("disable", mode="before")
    @classmethod
    def _disable_forms(cls, v: Any) -> Any:
        """Accept `[{id, reason}]` or `{RULE-ID: reason}`; a bare id has no reason and is rejected."""
        if v is None:
            return []
        if isinstance(v, dict):
            return [{"id": k, "reason": r} for k, r in v.items()]
        if isinstance(v, list):
            out = []
            for item in v:
                if isinstance(item, str):
                    raise ValueError(
                        f"rule {item!r} has no reason. Write it as `- id: {item}` + `reason: \"...\"` "
                        f"or `{item}: \"reason\"`"
                    )
                out.append(item)
            return out
        return v


class PathsConfig(_Strict):
    include: list[str] = Field(default_factory=list, description="Only findings under these paths count (empty = all).")
    exclude: list[str] = Field(default_factory=list, description="Findings under these paths are ignored.")

    def in_scope(self, path: str) -> bool:
        if not path:
            return True  # project-level findings are always in scope
        if self.include and not any(_match(path, p) for p in self.include):
            return False
        return not any(_match(path, p) for p in self.exclude)


def _match(path: str, pattern: str) -> bool:
    pattern = pattern.replace("\\", "/").removeprefix("./")
    if pattern.endswith("/"):
        return path.startswith(pattern) or ("/" + pattern) in ("/" + path)
    if any(ch in pattern for ch in "*?["):
        return fnmatch.fnmatch(path, pattern) or fnmatch.fnmatch(path, pattern.replace("**/", ""))
    return path == pattern or path.startswith(pattern.rstrip("/") + "/")


class GateConfig(_Strict):
    min_score: float | None = Field(default=None, ge=0, le=100, description="Overall score threshold.")
    min_score_per_pack: dict[str, float] = Field(default_factory=dict)
    fail_on_severity: Severity | Literal["none"] = Field(
        default=Severity.high, description="Fail if any (new) failed finding is at least this severe."
    )
    new_findings_only: bool = True

    @field_validator("min_score_per_pack")
    @classmethod
    def _pack_scores_in_range(cls, v: dict[str, float]) -> dict[str, float]:
        for k, s in v.items():
            if not 0 <= s <= 100:
                raise ValueError(f"min score for {k!r} must be between 0 and 100, got {s}")
        return v


class AIConfig(_Strict):
    enabled: bool = Field(default=False, description="Off by default: no code leaves the runner.")


class ReportConfig(_Strict):
    pr_comment: bool = True
    sarif: bool = True
    job_summary: bool = True
    fix_prompts: bool = True
    max_prompts_in_comment: int = Field(default=10, ge=0, le=50)


class BaselineConfig(_Strict):
    file: str = DEFAULT_BASELINE_NAME


class PrivTraceConfig(_Strict):
    version: Literal[1] = 1
    packs: list[str] = Field(min_length=1)
    rules: RulesConfig = Field(default_factory=RulesConfig)
    paths: PathsConfig = Field(default_factory=PathsConfig)
    manual_answers: dict[str, ManualAnswerValue] = Field(default_factory=dict)
    gate: GateConfig = Field(default_factory=GateConfig)
    ai: AIConfig = Field(default_factory=AIConfig)
    report: ReportConfig = Field(default_factory=ReportConfig)
    baseline: BaselineConfig = Field(default_factory=BaselineConfig)

    @field_validator("manual_answers", mode="before")
    @classmethod
    def _yaml_booleans(cls, v: Any) -> Any:
        """YAML 1.1 reads `yes` / `no` as booleans; map them back to checklist answers."""
        if not isinstance(v, dict):
            return v
        out: dict[str, Any] = {}
        for k, val in v.items():
            if val is True:
                val = "yes"
            elif val is False:
                val = "no"
            elif isinstance(val, str):
                val = val.strip().lower().replace("-", "_").replace(" ", "_")
            out[str(k)] = val
        return out

    @field_validator("packs", mode="before")
    @classmethod
    def _packs_csv(cls, v: Any) -> Any:
        return [p.strip() for p in v.split(",") if p.strip()] if isinstance(v, str) else v

    @model_validator(mode="after")
    def _no_duplicate_disables(self) -> PrivTraceConfig:
        ids = [d.id for d in self.rules.disable]
        dupes = sorted({i for i in ids if ids.count(i) > 1})
        if dupes:
            raise ValueError(f"rules.disable lists {', '.join(dupes)} more than once")
        return self

    # ---- derived ----
    @property
    def disabled(self) -> dict[str, str]:
        return {d.id: d.reason for d in self.rules.disable}


def _format_validation_error(e: ValidationError, source: str) -> str:
    lines = [f"{source} is invalid:"]
    for err in e.errors():
        loc = ".".join(str(p) for p in err["loc"]) or "(top level)"
        msg = err["msg"].removeprefix("Value error, ")
        if err["type"] == "extra_forbidden":
            msg = "unknown key (check the spelling; see docs/CI_INTEGRATION.md)"
        lines.append(f"  - {loc}: {msg}")
    return "\n".join(lines)


def parse_config(text: str, source: str = DEFAULT_CONFIG_NAME) -> PrivTraceConfig:
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as e:
        raise ConfigError(f"{source} is not valid YAML: {e}") from e
    if data is None:
        raise ConfigError(f"{source} is empty. Run `privtrace init` to create one.")
    if not isinstance(data, dict):
        raise ConfigError(f"{source}: the top level must be a mapping (key: value).")
    try:
        return PrivTraceConfig.model_validate(data)
    except ValidationError as e:
        raise ConfigError(_format_validation_error(e, source)) from e


def load_config(path: Path) -> PrivTraceConfig:
    if not path.exists():
        raise ConfigError(
            f"config file not found: {path}. Run `privtrace init` to create one, or pass --config."
        )
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as e:
        raise ConfigError(f"cannot read {path}: {e}") from e
    return parse_config(text, path.name)


def validate_against_packs(cfg: PrivTraceConfig, packs: dict[str, Pack]) -> list[str]:
    """Resolve pack aliases in place and return human-readable errors for unknown ids."""
    errors: list[str] = []
    try:
        cfg.packs = resolve_pack_ids(cfg.packs, packs)
    except PackLoadError as e:
        errors.append(f"packs: {e}")
        return errors
    selected = [packs[p] for p in cfg.packs]
    rules = {r.id: r for p in selected for r in p.rules}
    all_rules = {r.id for p in packs.values() for r in p.rules}

    def check(section: str, ids: list[str]) -> None:
        for rid in ids:
            if rid not in rules:
                where = " (it belongs to a pack that is not selected)" if rid in all_rules else ""
                errors.append(f"{section}: unknown rule {rid!r}{where}")

    check("rules.disable", [d.id for d in cfg.rules.disable])
    check("rules.severity_overrides", list(cfg.rules.severity_overrides))
    check("manual_answers", list(cfg.manual_answers))
    for rid in cfg.manual_answers:
        r = rules.get(rid)
        if r is not None and r.check_type == CheckType.automated:
            errors.append(f"manual_answers: {rid} is an automated rule and has no checklist question")
    resolved_scores: dict[str, float] = {}
    for key, score in cfg.gate.min_score_per_pack.items():
        try:
            pid = resolve_pack_ids([key], packs)[0]
        except PackLoadError:
            errors.append(f"gate.min_score_per_pack: unknown pack {key!r}")
            continue
        if pid not in cfg.packs:
            errors.append(f"gate.min_score_per_pack: pack {key!r} is not in `packs`")
        resolved_scores[pid] = score
    cfg.gate.min_score_per_pack = resolved_scores
    return errors


def load_and_validate(path: Path, packs: dict[str, Pack]) -> PrivTraceConfig:
    cfg = load_config(path)
    errors = validate_against_packs(cfg, packs)
    if errors:
        raise ConfigError(f"{path.name} is invalid:\n" + "\n".join(f"  - {e}" for e in errors))
    return cfg


# ---------------------------------------------------------------- writing (privtrace init)
def render_config(
    packs: list[str], answers: dict[str, ManualAnswerValue], questions: dict[str, str], *,
    min_score: float = 70, fail_on: str = "high", include: list[str] | None = None,
    exclude: list[str] | None = None,
) -> str:
    """A commented `.privtrace.yml`. Hand-written so the comments survive."""
    out = [
        "# PrivTrace configuration: which compliance packs and rules apply to this repository,",
        "# and when the CI gate should block a merge. Reference: docs/CI_INTEGRATION.md",
        "# Findings are engineering evidence, not legal advice.",
        "version: 1",
        "",
        "# Frameworks the business selected (`privtrace packs list` shows all of them).",
        f"packs: [{', '.join(packs)}]",
        "",
        "rules:",
        "  # Rules that do not apply. Each needs a reason; they are listed in every report.",
        "  disable: []",
        "  #  - id: GDPR-TRF-02",
        '  #    reason: "No personal data leaves India"',
        "  severity_overrides: {}   # e.g. { DPDP-RET-01: critical }",
        "",
        "paths:",
        f"  include: [{', '.join(include or [])}]   # empty = whole repository",
        f"  exclude: [{', '.join(exclude or ['tests/fixtures/', 'migrations/'])}]",
        "",
        "# Answers to the manual checklist, so CI can score organisational controls.",
        "# yes = passed, no = failed, not_sure = needs review.",
    ]
    if answers:
        out.append("manual_answers:")
        for rid, ans in answers.items():
            question = questions.get(rid, "").replace("\n", " ")
            out.append(f"  {rid}: {ans.value}" + (f"   # {question[:110]}" if question else ""))
    else:
        out.append("manual_answers: {}")
    out += [
        "",
        "gate:",
        f"  min_score: {min_score:g}              # overall score threshold (0-100)",
        "  min_score_per_pack: {}     # e.g. { dpdp-2023: 75 }",
        f"  fail_on_severity: {fail_on}     # fail if any NEW failed finding is at least this severe (or: none)",
        "  new_findings_only: true    # judge a PR only on what it introduces (needs a baseline)",
        "",
        "ai:",
        "  enabled: false             # default: no code leaves the CI runner",
        "",
        "report:",
        "  pr_comment: true",
        "  sarif: true",
        "  job_summary: true",
        "  fix_prompts: true",
        "",
        "baseline:",
        f"  file: {DEFAULT_BASELINE_NAME}",
        "",
    ]
    text = "\n".join(out)
    parse_config(text)  # never write a file we cannot read back
    return text
