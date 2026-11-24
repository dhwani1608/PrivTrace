"""Local git helpers for CI. Everything is local (`git worktree`, `rev-parse`): no fetch, no network."""

from __future__ import annotations

import shutil
import subprocess
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from privtrace.ci.config import ConfigError


def _git(root: Path, *args: str, check: bool = True) -> str:
    if shutil.which("git") is None:
        raise ConfigError("git is not installed, so --base cannot be used")
    proc = subprocess.run(["git", "-C", str(root), *args], capture_output=True, text=True, timeout=120)
    if check and proc.returncode != 0:
        raise ConfigError(f"git {' '.join(args)} failed: {proc.stderr.strip() or proc.stdout.strip()}")
    return proc.stdout.strip()


def head_commit(root: Path) -> str | None:
    try:
        return _git(root, "rev-parse", "HEAD") or None
    except (ConfigError, OSError, subprocess.SubprocessError):
        return None


def merge_base(root: Path, base_ref: str) -> str:
    """Commit the PR branches off from (falls back to the ref itself, e.g. on a push to main)."""
    _git(root, "rev-parse", "--verify", f"{base_ref}^{{commit}}")
    mb = _git(root, "merge-base", "HEAD", base_ref, check=False)
    return mb or _git(root, "rev-parse", base_ref)


@contextmanager
def worktree_at(root: Path, commit: str) -> Iterator[Path]:
    """Check `commit` out into a temporary worktree; always removed afterwards."""
    tmp = Path(tempfile.mkdtemp(prefix="privtrace-base-"))
    path = tmp / "base"
    _git(root, "worktree", "add", "--detach", "--force", str(path), commit)
    try:
        yield path
    finally:
        _git(root, "worktree", "remove", "--force", str(path), check=False)
        shutil.rmtree(tmp, ignore_errors=True)
        _git(root, "worktree", "prune", check=False)


def repo_subpath(root: Path) -> Path:
    """`root` relative to the repository top level (Path('.') when it *is* the top level)."""
    top = Path(_git(root, "rev-parse", "--show-toplevel")).resolve()
    try:
        return root.resolve().relative_to(top)
    except ValueError:
        return Path(".")
