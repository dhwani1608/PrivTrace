"""Registry of rule check functions referenced by `detector:` in pack YAML.

A check receives the scan context and the rule's `detector_params` and returns a
`CheckOutcome`. Checks are registered with `@register_check("name")`.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

CheckFn = Callable[..., Any]

_CHECKS: dict[str, CheckFn] = {}


def register_check(name: str) -> Callable[[CheckFn], CheckFn]:
    def deco(fn: CheckFn) -> CheckFn:
        if name in _CHECKS and _CHECKS[name] is not fn:
            raise ValueError(f"check {name!r} registered twice")
        _CHECKS[name] = fn
        return fn

    return deco


def get_check(name: str) -> CheckFn:
    try:
        return _CHECKS[name]
    except KeyError as e:
        raise KeyError(f"no check registered as {name!r}") from e


def registered_checks() -> set[str]:
    _ensure_loaded()
    return set(_CHECKS)


def _ensure_loaded() -> None:
    """Import modules that register checks (no-op until checks exist)."""
    try:
        import privtrace.rules.checks  # noqa: F401
    except ModuleNotFoundError as e:  # pragma: no cover - only during early phases
        if e.name != "privtrace.rules.checks":
            raise
