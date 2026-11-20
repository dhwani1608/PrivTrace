"""Get customer code into a temporary workspace, and always delete it afterwards."""

from __future__ import annotations

import re
import shutil
import subprocess
import tempfile
import zipfile
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

SKIP_DIRS = {
    ".git", "node_modules", ".venv", "venv", "env", "__pycache__", ".mypy_cache",
    ".pytest_cache", ".tox", "dist", "build", ".next", ".idea", ".vscode", "site-packages",
    ".privtrace",
}
MAX_FILE_BYTES = 1_000_000
_GITHUB_URL = re.compile(r"^https://github\.com/[\w.\-]+/[\w.\-]+?(\.git)?/?$")


class FetchError(Exception):
    pass


@contextmanager
def workspace() -> Iterator[Path]:
    """A temp dir that is removed even if the scan crashes."""
    d = Path(tempfile.mkdtemp(prefix="privtrace-"))
    try:
        yield d
    finally:
        shutil.rmtree(d, ignore_errors=True)


def clone_github(url: str, dest: Path, timeout: int = 120) -> Path:
    if not _GITHUB_URL.match(url.strip()):
        raise FetchError("only public https://github.com/<owner>/<repo> URLs are supported")
    target = dest / "repo"
    try:
        subprocess.run(
            ["git", "clone", "--depth", "1", "--single-branch", "--no-tags", url.strip(), str(target)],
            check=True, capture_output=True, timeout=timeout,
            env={"GIT_TERMINAL_PROMPT": "0", "PATH": _path_env()},
        )
    except subprocess.CalledProcessError as e:
        raise FetchError(f"git clone failed: {e.stderr.decode(errors='replace')[:300]}") from e
    except subprocess.TimeoutExpired as e:
        raise FetchError("git clone timed out") from e
    return target


def _path_env() -> str:
    import os

    return os.environ.get("PATH", "")


def extract_zip(zip_path: Path, dest: Path, max_bytes: int = 200 * 1024 * 1024) -> Path:
    target = dest / "upload"
    target.mkdir()
    total = 0
    with zipfile.ZipFile(zip_path) as zf:
        for info in zf.infolist():
            name = Path(info.filename)
            if name.is_absolute() or ".." in name.parts:  # zip-slip
                raise FetchError(f"unsafe path in zip: {info.filename}")
            total += info.file_size
            if total > max_bytes:
                raise FetchError("zip too large when extracted")
        zf.extractall(target)
    # unwrap a single top-level folder
    children = [c for c in target.iterdir() if c.name not in ("__MACOSX",)]
    return children[0] if len(children) == 1 and children[0].is_dir() else target


def iter_files(root: Path) -> Iterator[tuple[str, Path]]:
    """Yield (repo-relative POSIX path, absolute path) for scannable files."""
    for p in sorted(root.rglob("*")):
        if not p.is_file():
            continue
        rel = p.relative_to(root)
        if any(part in SKIP_DIRS for part in rel.parts[:-1]):
            continue
        try:
            if p.stat().st_size > MAX_FILE_BYTES:
                continue
        except OSError:
            continue
        yield rel.as_posix(), p


TEXT_EXTENSIONS = {
    ".py", ".pyi", ".json", ".yaml", ".yml", ".toml", ".ini", ".cfg", ".conf", ".env",
    ".txt", ".md", ".csv", ".sql", ".sh", ".properties", ".js", ".ts", ".tsx", ".jsx",
    ".html", ".xml", ".tf", ".dockerfile",
}


def is_text_candidate(rel: str) -> bool:
    name = rel.rsplit("/", 1)[-1].lower()
    if name.startswith(".env") or name in ("dockerfile", "docker-compose.yml", "procfile"):
        return True
    return Path(name).suffix in TEXT_EXTENSIONS


def read_text(path: Path) -> str | None:
    try:
        data = path.read_bytes()
    except OSError:
        return None
    if b"\x00" in data[:4096]:
        return None
    return data.decode("utf-8", errors="replace")
