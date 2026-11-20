"""Python parser using the built-in `ast` module."""

from __future__ import annotations

import ast

from privtrace.scanner.parsers.base import ParsedModule


def module_name_for(path: str) -> str:
    parts = path[:-3].split("/") if path.endswith(".py") else path.split("/")
    if parts and parts[-1] == "__init__":
        parts = parts[:-1]
    return ".".join(parts)


class PythonParser:
    language = "python"
    extensions = (".py",)

    def parse(self, path: str, source: str) -> ParsedModule | None:
        try:
            tree = ast.parse(source, filename=path, type_comments=False)
        except (SyntaxError, ValueError):
            return None
        mod = ParsedModule(
            path=path, module=module_name_for(path), source=source, tree=tree,
            lines=source.splitlines(),
        )
        package = mod.module.rsplit(".", 1)[0] if "." in mod.module else ""
        if path.endswith("__init__.py"):
            package = mod.module
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for a in node.names:
                    if a.asname:
                        mod.imports[a.asname] = a.name
                    else:
                        # `import google.genai` binds `google`
                        root = a.name.split(".")[0]
                        mod.imports.setdefault(root, root)
            elif isinstance(node, ast.ImportFrom):
                base = node.module or ""
                if node.level:
                    pkg_parts = package.split(".") if package else []
                    up = node.level - 1
                    pkg_parts = pkg_parts[: len(pkg_parts) - up] if up else pkg_parts
                    base = ".".join([*pkg_parts, base] if base else pkg_parts)
                for a in node.names:
                    if a.name == "*":
                        continue
                    alias = a.asname or a.name
                    mod.imports[alias] = f"{base}.{a.name}" if base else a.name
                    mod.from_imports[alias] = (base, a.name)
        return mod


PARSERS = {".py": PythonParser()}
