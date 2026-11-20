"""Parser layer. Each language implements `LanguageParser`.

MVP: Python via the stdlib `ast`. A tree-sitter JS/TS parser can be added by
implementing the same protocol and registering it in `PARSERS`.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from typing import Protocol


@dataclass
class ParsedModule:
    path: str          # repo-relative POSIX path
    module: str        # dotted module name relative to the scan root
    source: str
    tree: ast.Module
    # local alias -> fully qualified dotted name ("np" -> "numpy", "Client" -> "google.genai.Client")
    imports: dict[str, str] = field(default_factory=dict)
    # local alias -> (module, name) for `from x import y`, used to follow imports into the repo
    from_imports: dict[str, tuple[str, str]] = field(default_factory=dict)
    lines: list[str] = field(default_factory=list)

    def line(self, n: int) -> str:
        return self.lines[n - 1] if 0 < n <= len(self.lines) else ""


class LanguageParser(Protocol):
    language: str
    extensions: tuple[str, ...]

    def parse(self, path: str, source: str) -> ParsedModule | None: ...
