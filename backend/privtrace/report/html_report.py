"""Render a ScanResult as a single self-contained, printable HTML file."""

from __future__ import annotations

from html import escape
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape
from markupsafe import Markup

from privtrace.models.enums import RuleStatus
from privtrace.models.results import RuleResult, ScanResult

_TEMPLATES = Path(__file__).parent / "templates"
_env = Environment(loader=FileSystemLoader(_TEMPLATES), autoescape=select_autoescape(["html", "j2"]))

SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
STATUS_ORDER = {"failed": 0, "needs_review": 1, "passed": 2, "not_assessable": 3}


def score_color(score: float | None) -> str:
    if score is None:
        return "#8a8f98"
    if score >= 80:
        return "#1f9d55"
    if score >= 50:
        return "#d97706"
    return "#dc2626"


def gauge_svg(score: float | None, size: int = 120, label: str = "") -> Markup:
    r = size / 2 - 10
    c = 2 * 3.14159265 * r
    pct = 0 if score is None else max(0.0, min(100.0, score)) / 100
    color = score_color(score)
    text = "n/a" if score is None else f"{score:.0f}"
    return Markup(
        f'<svg width="{size}" height="{size}" viewBox="0 0 {size} {size}" role="img" aria-label="{escape(label)} score {text}">'
        f'<circle cx="{size/2}" cy="{size/2}" r="{r}" fill="none" stroke="#e5e7eb" stroke-width="10"/>'
        f'<circle cx="{size/2}" cy="{size/2}" r="{r}" fill="none" stroke="{color}" stroke-width="10" '
        f'stroke-dasharray="{c*pct:.1f} {c:.1f}" stroke-linecap="round" transform="rotate(-90 {size/2} {size/2})"/>'
        f'<text x="50%" y="50%" text-anchor="middle" dominant-baseline="central" font-size="{size/4:.0f}" '
        f'font-weight="700" fill="{color}">{text}</text></svg>'
    )


def flow_svg(graph: dict, width: int = 1000) -> Markup:
    """Three-column layered graph: sources | code paths | stores & sinks."""
    nodes = graph.get("nodes", [])
    edges = graph.get("edges", [])
    if not nodes:
        return Markup('<p class="muted">No personal data flows were detected.</p>')
    cols = {"source": [], "code": [], "sink": []}
    for n in nodes:
        cols[n["type"]].append(n)
    row_h, box_h, box_w, top = 38, 28, 280, 34
    xs = {"source": 10, "code": width / 2 - box_w / 2, "sink": width - box_w - 10}
    pos: dict[str, tuple[float, float]] = {}
    height = top + max(len(v) for v in cols.values()) * row_h + 10
    parts = [f'<svg class="flow" viewBox="0 0 {width} {height}" width="100%" role="img" aria-label="Data-flow map">']
    for t, title in (("source", "Personal data"), ("code", "Code path"), ("sink", "Store / sink")):
        parts.append(f'<text x="{xs[t] + box_w/2}" y="18" text-anchor="middle" class="flow-h">{title}</text>')
    for t, items in cols.items():
        for i, n in enumerate(items):
            y = top + i * row_h
            pos[n["id"]] = (xs[t], y)
    for e in edges:
        if e["source"] not in pos or e["target"] not in pos:
            continue
        x1, y1 = pos[e["source"]]
        x2, y2 = pos[e["target"]]
        x1 += box_w
        y1 += box_h / 2
        y2 += box_h / 2
        mx = (x1 + x2) / 2
        cls = "edge risky" if e.get("risky") else "edge"
        tip = escape(", ".join(e.get("locations", [])[:5]))
        parts.append(f'<path class="{cls}" d="M{x1},{y1} C{mx},{y1} {mx},{y2} {x2},{y2}"><title>{tip}</title></path>')
    for n in nodes:
        x, y = pos[n["id"]]
        label = n["label"] if len(n["label"]) <= 40 else n["label"][:39] + "…"
        parts.append(
            f'<g class="node {n["type"]}"><rect x="{x}" y="{y}" width="{box_w}" height="{box_h}" rx="6"/>'
            f'<text x="{x + 10}" y="{y + box_h/2}" dominant-baseline="central">{escape(label)}</text>'
            f'<title>{escape(n["label"])}</title></g>'
        )
    parts.append("</svg>")
    return Markup("".join(parts))


def top_fixes(results: list[RuleResult], n: int = 5) -> list[RuleResult]:
    seen: set[str] = set()
    out: list[RuleResult] = []
    for r in sorted((r for r in results if r.status == RuleStatus.failed), key=lambda r: (SEV_ORDER[r.severity.value], r.rule_id)):
        key = r.title
        if key in seen:
            continue
        seen.add(key)
        out.append(r)
        if len(out) == n:
            break
    return out


def render_html(result: ScanResult) -> str:
    by_pack: dict[str, list[RuleResult]] = {}
    for r in result.results:
        by_pack.setdefault(r.pack_id, []).append(r)
    for rs in by_pack.values():
        rs.sort(key=lambda r: (STATUS_ORDER[r.status.value], SEV_ORDER[r.severity.value], r.rule_id))
    manual = [r for r in result.results if r.check_type.value != "automated" and r.question]
    tpl = _env.get_template("report.html.j2")
    return tpl.render(
        r=result, by_pack=by_pack, manual=manual, top=top_fixes(result.results),
        gauge=gauge_svg, flow=flow_svg(result.data_flow), score_color=score_color,
        RuleStatus=RuleStatus,
    )


def write_html(result: ScanResult, path: Path) -> Path:
    path.write_text(render_html(result), encoding="utf-8")
    return path
