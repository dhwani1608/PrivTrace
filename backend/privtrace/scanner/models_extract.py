"""Find Pydantic / SQLAlchemy / dataclass / Django models and their PII fields."""

from __future__ import annotations

import ast

from privtrace.scanner.detectors.pii_names import classify_name
from privtrace.scanner.facts import PiiField, PiiModel
from privtrace.scanner.parsers.base import ParsedModule

_PYDANTIC_BASES = {"BaseModel", "pydantic.BaseModel", "SQLModel", "sqlmodel.SQLModel"}
_SKIP_BASES = {"BaseSettings", "pydantic_settings.BaseSettings", "pydantic.BaseSettings", "Enum", "enum.Enum", "StrEnum", "IntEnum", "Exception"}
_SQLA_BASES = {"Base", "DeclarativeBase", "declarative_base", "db.Model", "Model"}
_FIELD_FACTORIES = {"Column", "mapped_column", "Field", "relationship"}
_SKIP_FIELDS = {"model_config", "Config", "__tablename__", "__table_args__", "id"}


def _base_name(mod: ParsedModule, b: ast.AST) -> str:
    if isinstance(b, ast.Name):
        return mod.imports.get(b.id, b.id) if b.id not in ("Base", "BaseModel") else (
            mod.imports.get(b.id, b.id)
        )
    if isinstance(b, ast.Attribute):
        return ast.unparse(b)
    if isinstance(b, ast.Subscript):
        return _base_name(mod, b.value)
    return ""


def _is_dataclass(node: ast.ClassDef) -> bool:
    for d in node.decorator_list:
        target = d.func if isinstance(d, ast.Call) else d
        name = target.id if isinstance(target, ast.Name) else getattr(target, "attr", "")
        if name in ("dataclass", "define", "frozen", "attrs"):
            return True
    return False


def _has_vector(value: ast.AST | None) -> bool:
    if value is None:
        return False
    for n in ast.walk(value):
        if isinstance(n, ast.Name) and n.id in ("Vector", "VECTOR"):
            return True
        if isinstance(n, ast.Attribute) and n.attr in ("Vector", "VECTOR"):
            return True
    return False


def extract_models(modules: list[ParsedModule]) -> dict[str, PiiModel]:
    """Return models keyed by class name. Two passes so subclasses inherit fields."""
    classes: list[tuple[ParsedModule, ast.ClassDef]] = [
        (m, n) for m in modules for n in ast.walk(m.tree) if isinstance(n, ast.ClassDef)
    ]
    out: dict[str, PiiModel] = {}

    for _ in range(2):
        for mod, node in classes:
            bases = [_base_name(mod, b) for b in node.bases]
            short = [b.rsplit(".", 1)[-1] for b in bases]
            if any(b in _SKIP_BASES or s in _SKIP_BASES for b, s in zip(bases, short)):
                continue
            body_names = {
                t.id for st in node.body if isinstance(st, ast.Assign) for t in st.targets if isinstance(t, ast.Name)
            }
            parent = next((out[s] for s in short if s in out and s != node.name), None)
            if "__tablename__" in body_names or any(b in _SQLA_BASES or b.endswith(".Model") for b in bases):
                kind = "django" if any("django" in b for b in bases) else "sqlalchemy"
            elif any(b in _PYDANTIC_BASES or s in ("BaseModel", "SQLModel") for b, s in zip(bases, short)):
                kind = "pydantic"
            elif _is_dataclass(node):
                kind = "dataclass"
            elif parent:
                kind = parent.model_kind
            else:
                continue

            model = PiiModel(name=node.name, file=mod.path, line=node.lineno, model_kind=kind)
            if parent:
                model.fields = list(parent.fields)
                model.all_field_names = list(parent.all_field_names)
                model.ambiguous_fields = list(parent.ambiguous_fields)
                model.is_vector = parent.is_vector
                model.table = parent.table

            for st in node.body:
                fname: str | None = None
                value: ast.AST | None = None
                if isinstance(st, ast.AnnAssign) and isinstance(st.target, ast.Name):
                    fname, value = st.target.id, st.value
                    if "ClassVar" in ast.unparse(st.annotation):
                        continue
                    if _has_vector(st.annotation):
                        model.is_vector = True
                elif isinstance(st, ast.Assign) and len(st.targets) == 1 and isinstance(st.targets[0], ast.Name):
                    fname, value = st.targets[0].id, st.value
                    if fname == "__tablename__" and isinstance(value, ast.Constant):
                        model.table = str(value.value)
                        continue
                    is_field = isinstance(value, ast.Call) and (
                        getattr(value.func, "id", None) in _FIELD_FACTORIES
                        or getattr(value.func, "attr", "").endswith(("Field", "Column"))
                        or getattr(value.func, "attr", None) in _FIELD_FACTORIES
                    )
                    if not is_field:
                        continue
                if not fname or fname in _SKIP_FIELDS or fname.startswith("_"):
                    continue
                if _has_vector(value):
                    model.is_vector = True
                if fname not in model.all_field_names:
                    model.all_field_names.append(fname)
                c = classify_name(fname)
                if c is None:
                    continue
                if c.is_pii:
                    if not any(f.name == fname for f in model.fields):
                        model.fields.append(PiiField(name=fname, category=c.category, sensitive=c.is_sensitive, line=st.lineno))
                elif fname not in model.ambiguous_fields:
                    model.ambiguous_fields.append(fname)
            if kind == "sqlalchemy" and not model.table:
                model.table = node.name.lower()
            out[node.name] = model
    return out
