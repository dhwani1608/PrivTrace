"""Load and validate compliance packs from YAML at runtime."""

from __future__ import annotations

from pathlib import Path

import yaml
from pydantic import ValidationError

from privtrace.core.config import get_settings
from privtrace.packs.schema import Pack


class PackLoadError(Exception):
    pass


def load_pack_file(path: Path, known_checks: set[str] | None = None) -> Pack:
    """Parse one YAML pack. If `known_checks` is given, every detector must exist."""
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as e:
        raise PackLoadError(f"{path.name}: invalid YAML: {e}") from e
    if not isinstance(data, dict):
        raise PackLoadError(f"{path.name}: top level must be a mapping")
    try:
        pack = Pack.model_validate(data)
    except ValidationError as e:
        raise PackLoadError(f"{path.name}: schema error:\n{e}") from e

    if known_checks is not None:
        missing = sorted(
            {r.detector for r in pack.rules if r.detector and r.detector not in known_checks}
        )
        if missing:
            raise PackLoadError(f"{path.name}: unknown detector(s): {', '.join(missing)}")
    return pack


def load_packs(
    packs_dir: Path | None = None, *, validate_detectors: bool = True
) -> dict[str, Pack]:
    """Load every `*.yaml` pack in `packs_dir`, keyed by pack id."""
    packs_dir = packs_dir or get_settings().packs_dir
    if not packs_dir.is_dir():
        raise PackLoadError(f"packs directory not found: {packs_dir}")

    known: set[str] | None = None
    if validate_detectors:
        from privtrace.rules.registry import registered_checks

        known = registered_checks()

    packs: dict[str, Pack] = {}
    for path in sorted(packs_dir.glob("*.y*ml")):
        pack = load_pack_file(path, known)
        if pack.id in packs:
            raise PackLoadError(f"duplicate pack id {pack.id!r} ({path.name})")
        packs[pack.id] = pack
    return packs


def resolve_pack_ids(requested: list[str], packs: dict[str, Pack]) -> list[str]:
    """Accept full ids ('dpdp-2023') or short aliases ('dpdp')."""
    resolved: list[str] = []
    for req in requested:
        req = req.strip().lower()
        if not req:
            continue
        if req in packs:
            resolved.append(req)
            continue
        matches = [pid for pid in packs if pid.split("-")[0] == req or pid.startswith(req)]
        if len(matches) != 1:
            raise PackLoadError(
                f"unknown pack {req!r}; available: {', '.join(sorted(packs))}"
            )
        resolved.append(matches[0])
    return list(dict.fromkeys(resolved))
