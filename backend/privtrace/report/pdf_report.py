"""Render a ScanResult as a PDF (pure Python via reportlab — no system libraries needed).

Layout mirrors the web report: summary, where-it-breaks (file hotspots), then every finding per
framework as What / Where / Why / How, the manual checklist, coverage and the disclaimer.
"""

from __future__ import annotations

import io
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (
    BaseDocTemplate, CondPageBreak, Flowable, Frame, KeepTogether, NextPageTemplate, PageBreak,
    PageTemplate, Paragraph, Spacer, Table, TableStyle,
)

from privtrace.models.results import RuleResult, ScanResult

# ------------------------------------------------------------------ palette
INK = colors.HexColor("#0a0912")
INK_2 = colors.HexColor("#1b1829")
VIOLET = colors.HexColor("#6d28d9")
VIOLET_L = colors.HexColor("#ede9fe")
LIME = colors.HexColor("#d4ff3f")
MUTED = colors.HexColor("#6b7280")
LINE = colors.HexColor("#e5e7eb")
SOFT = colors.HexColor("#f6f5fa")
STATUS_C = {"failed": colors.HexColor("#e11d48"), "needs_review": colors.HexColor("#d97706"),
            "passed": colors.HexColor("#16a34a"), "not_assessable": colors.HexColor("#9ca3af")}
SEV_C = {"critical": colors.HexColor("#e11d48"), "high": colors.HexColor("#ea580c"),
         "medium": colors.HexColor("#ca8a04"), "low": colors.HexColor("#0284c7")}
RISK_C = {"Critical": colors.HexColor("#e11d48"), "High": colors.HexColor("#ea580c"),
          "Medium": colors.HexColor("#d97706"), "Low": colors.HexColor("#16a34a")}
SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
STATUS_ORDER = {"failed": 0, "needs_review": 1, "passed": 2, "not_assessable": 3}

PAGE_W, PAGE_H = A4
MARGIN = 16 * mm
CONTENT_W = PAGE_W - 2 * MARGIN

# Standard PDF fonts only cover Latin-1/cp1252; map the few symbols we use elsewhere.
_SUBST = {"→": "->", "←": "<-", "✓": "OK", "✕": "x", "✗": "x", "≤": "<=", "≥": ">=", "…": "...", "—": "-", "–": "-",
          "•": "-", "·": "-", "‘": "'", "’": "'", "“": '"', "”": '"'}


def _plain(s: object) -> str:
    text = "" if s is None else str(s)
    for k, v in _SUBST.items():
        text = text.replace(k, v)
    return text.encode("cp1252", "replace").decode("cp1252")


def t(s: object) -> str:
    """Escape arbitrary text for a reportlab Paragraph."""
    return escape(_plain(s))


def score_color(score: float | None) -> colors.Color:
    if score is None:
        return colors.HexColor("#9ca3af")
    if score >= 80:
        return colors.HexColor("#16a34a")
    if score >= 50:
        return colors.HexColor("#d97706")
    return colors.HexColor("#e11d48")


def _sv(e: object) -> str:
    return getattr(e, "value", e)  # enum or str


# ------------------------------------------------------------------ styles
def _styles() -> dict[str, ParagraphStyle]:
    base = ParagraphStyle("base", fontName="Helvetica", fontSize=9.2, leading=13, textColor=INK)
    return {
        "base": base,
        "muted": ParagraphStyle("muted", parent=base, textColor=MUTED, fontSize=8.4, leading=11.5),
        "small": ParagraphStyle("small", parent=base, fontSize=8, leading=10.5),
        "kicker": ParagraphStyle("kicker", parent=base, fontName="Helvetica-Bold", fontSize=7, leading=9, textColor=MUTED),
        "h1": ParagraphStyle("h1", parent=base, fontName="Helvetica-Bold", fontSize=22, leading=26, textColor=colors.white),
        "h2": ParagraphStyle("h2", parent=base, fontName="Helvetica-Bold", fontSize=15, leading=19, spaceBefore=4, spaceAfter=6),
        "h3": ParagraphStyle("h3", parent=base, fontName="Helvetica-Bold", fontSize=11.5, leading=14.5),
        "h4": ParagraphStyle("h4", parent=base, fontName="Helvetica-Bold", fontSize=9.4, leading=12),
        "mono": ParagraphStyle("mono", parent=base, fontName="Courier", fontSize=7.8, leading=10, wordWrap="CJK"),
        "monob": ParagraphStyle("monob", parent=base, fontName="Courier-Bold", fontSize=7.8, leading=10, textColor=VIOLET),
        "big": ParagraphStyle("big", parent=base, fontName="Helvetica-Bold", fontSize=20, leading=22, alignment=TA_CENTER),
        "center": ParagraphStyle("center", parent=base, alignment=TA_CENTER, fontSize=8, leading=10, textColor=MUTED),
    }


S = _styles()


# ------------------------------------------------------------------ flowables
class Gauge(Flowable):
    def __init__(self, score: float | None, size: float = 34 * mm, stroke: float = 7):
        super().__init__()
        self.score, self.size, self.stroke = score, size, stroke
        self.width = self.height = size

    def draw(self) -> None:
        c, s, w = self.canv, self.size, self.stroke
        pad = w / 2 + 1
        c.setLineWidth(w)
        c.setStrokeColor(LINE)
        c.circle(s / 2, s / 2, s / 2 - pad, stroke=1, fill=0)
        if self.score is not None and self.score > 0:
            c.setStrokeColor(score_color(self.score))
            c.setLineCap(1)
            extent = -360 * max(0.0, min(100.0, self.score)) / 100
            c.arc(pad, pad, s - pad, s - pad, startAng=90, extent=extent if extent > -359.9 else -359.9)
        c.setFillColor(INK)
        txt = "n/a" if self.score is None else f"{self.score:.0f}"
        fs = s / 3.4
        c.setFont("Helvetica-Bold", fs)
        c.drawCentredString(s / 2, s / 2 - fs / 3, txt)


class Bar(Flowable):
    """Stacked status bar (failed / review / passed / n/a)."""

    def __init__(self, parts: list[tuple[int, colors.Color]], width: float, height: float = 5):
        super().__init__()
        self.parts, self.width, self.height = parts, width, height

    def draw(self) -> None:
        total = sum(n for n, _ in self.parts) or 1
        x = 0.0
        c = self.canv
        c.setFillColor(LINE)
        c.roundRect(0, 0, self.width, self.height, self.height / 2, stroke=0, fill=1)
        for n, col in self.parts:
            if n:
                w = self.width * n / total
                c.setFillColor(col)
                c.rect(x, 0, w, self.height, stroke=0, fill=1)
                x += w


def pill(text: str, bg: colors.Color, fg: colors.Color = colors.white) -> Table:
    p = Paragraph(f'<font color="{fg.hexval()}"><b>{t(text).upper()}</b></font>',
                  ParagraphStyle("pill", parent=S["small"], fontSize=6.6, leading=8))
    tb = Table([[p]], style=TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), bg), ("LEFTPADDING", (0, 0), (-1, -1), 4), ("RIGHTPADDING", (0, 0), (-1, -1), 4),
        ("TOPPADDING", (0, 0), (-1, -1), 1.5), ("BOTTOMPADDING", (0, 0), (-1, -1), 2), ("ROUNDEDCORNERS", [3, 3, 3, 3]),
    ]))
    return tb


def boxed(rows: list, bg: colors.Color = SOFT, border: colors.Color | None = None, pad: float = 7, width: float = CONTENT_W) -> Table:
    tb = Table([[r] for r in rows], colWidths=[width])
    style = [("BACKGROUND", (0, 0), (-1, -1), bg), ("LEFTPADDING", (0, 0), (-1, -1), pad), ("RIGHTPADDING", (0, 0), (-1, -1), pad),
             ("TOPPADDING", (0, 0), (-1, -1), 2), ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
             ("TOPPADDING", (0, 0), (-1, 0), pad), ("BOTTOMPADDING", (0, -1), (-1, -1), pad), ("ROUNDEDCORNERS", [6, 6, 6, 6])]
    if border is not None:
        style.append(("BOX", (0, 0), (-1, -1), 0.6, border))
    tb.setStyle(TableStyle(style))
    return tb


def section(n: str, title: str, sub: str | None = None) -> list:
    out: list = [CondPageBreak(40 * mm), Spacer(1, 4), Paragraph(t(n), S["kicker"]), Paragraph(t(title), S["h2"])]
    if sub:
        out += [Paragraph(t(sub), S["muted"]), Spacer(1, 6)]
    return out


def diff_block(text: str, width: float, max_lines: int = 70) -> Table:
    lines = text.splitlines()
    more = len(lines) - max_lines
    rows = []
    for ln in lines[:max_lines]:
        col = "#c4b5fd" if ln.startswith(("+++", "---", "@@")) else "#d4ff3f" if ln.startswith("+") else "#fda4af" if ln.startswith("-") else "#9ca3af" if ln.startswith("#") else "#e5e7eb"
        rows.append([Paragraph(f'<font color="{col}">{t(ln) or "&nbsp;"}</font>'.replace("  ", "&nbsp; "), S["mono"])])
    if more > 0:
        rows.append([Paragraph(f'<font color="#9ca3af">... {more} more lines (see HTML/JSON report)</font>', S["mono"])])
    tb = Table(rows, colWidths=[width])
    tb.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), INK), ("LEFTPADDING", (0, 0), (-1, -1), 8),
                            ("RIGHTPADDING", (0, 0), (-1, -1), 8), ("TOPPADDING", (0, 0), (-1, -1), 0.5),
                            ("BOTTOMPADDING", (0, 0), (-1, -1), 0.5), ("TOPPADDING", (0, 0), (-1, 0), 6),
                            ("BOTTOMPADDING", (0, -1), (-1, -1), 6), ("ROUNDEDCORNERS", [5, 5, 5, 5])]))
    return tb


# ------------------------------------------------------------------ page chrome
def _logo(canv, x: float, y: float, size: float) -> None:
    """The PrivTrace mark (1024-unit artwork scaled to `size`), bottom-left at (x, y)."""
    k = size / 1024
    canv.saveState()
    canv.translate(x, y + size)
    canv.scale(k, -k)  # artwork uses a top-left origin
    canv.setFillColor(colors.HexColor("#13111f"))
    canv.setStrokeColor(colors.HexColor("#3a3552"))
    canv.setLineWidth(24)
    canv.roundRect(0, 0, 1024, 1024, 210, stroke=1, fill=1)
    p = canv.beginPath()
    p.moveTo(369, 820)
    p.lineTo(369, 225)
    p.lineTo(573, 225)
    p.arcTo(379, 225, 767, 613, startAng=270, extent=180)
    p.lineTo(500, 613)
    canv.setStrokeColor(colors.HexColor("#f3f3f4"))
    canv.setLineWidth(92)
    canv.setLineCap(1)
    canv.setLineJoin(1)
    canv.drawPath(p, stroke=1, fill=0)
    canv.setFillColor(LIME)
    canv.circle(461, 614, 82, stroke=0, fill=1)
    canv.restoreState()


def _cover_band(canv, doc, result: ScanResult) -> None:
    canv.saveState()
    band = 52 * mm
    canv.setFillColor(INK)
    canv.rect(0, PAGE_H - band, PAGE_W, band, stroke=0, fill=1)
    canv.setFillColor(VIOLET)
    canv.circle(PAGE_W - 30 * mm, PAGE_H - 8 * mm, 36 * mm, stroke=0, fill=1)
    canv.setFillColor(INK_2)
    canv.circle(PAGE_W - 30 * mm, PAGE_H - 8 * mm, 26 * mm, stroke=0, fill=1)
    canv.setFillColor(LIME)
    canv.rect(0, PAGE_H - band, PAGE_W, 1.6 * mm, stroke=0, fill=1)
    _logo(canv, MARGIN, PAGE_H - 18 * mm, 8 * mm)
    canv.setFillColor(colors.white)
    canv.setFont("Helvetica-Bold", 11)
    canv.drawString(MARGIN + 10.5 * mm, PAGE_H - 15.2 * mm, "PrivTrace")
    canv.setFillColor(colors.HexColor("#a1a1aa"))
    canv.setFont("Helvetica", 8)
    canv.drawString(MARGIN + 31 * mm, PAGE_H - 15.2 * mm, "Compliance exposure report")
    canv.restoreState()
    _footer(canv, doc, result)


def _footer(canv, doc, result: ScanResult) -> None:
    canv.saveState()
    canv.setStrokeColor(LINE)
    canv.setLineWidth(0.5)
    canv.line(MARGIN, 11 * mm, PAGE_W - MARGIN, 11 * mm)
    canv.setFont("Helvetica", 7)
    canv.setFillColor(MUTED)
    canv.drawString(MARGIN, 7 * mm, _plain(f"PrivTrace - scan {result.scan_id} - {result.target}")[:110])
    canv.drawRightString(PAGE_W - MARGIN, 7 * mm, f"Not legal advice  -  page {doc.page}")
    canv.restoreState()


def _later(canv, doc, result: ScanResult) -> None:
    canv.saveState()
    canv.setFillColor(LIME)
    canv.rect(0, PAGE_H - 2.2 * mm, PAGE_W, 2.2 * mm, stroke=0, fill=1)
    _logo(canv, MARGIN, PAGE_H - 10.4 * mm, 4.6 * mm)
    canv.setFont("Helvetica-Bold", 8)
    canv.setFillColor(INK)
    canv.drawString(MARGIN + 6.2 * mm, PAGE_H - 9 * mm, "PrivTrace")
    canv.setFont("Helvetica", 8)
    canv.setFillColor(MUTED)
    canv.drawRightString(PAGE_W - MARGIN, PAGE_H - 9 * mm, _plain(result.target)[:80])
    canv.restoreState()
    _footer(canv, doc, result)


# ------------------------------------------------------------------ content builders
def _summary(result: ScanResult) -> list:
    counts = defaultdict(int)
    for r in result.results:
        counts[_sv(r.status)] += 1
    s = result.summary
    risk = _sv(result.risk_level)
    risk_cell = Table([[Paragraph("RISK LEVEL", ParagraphStyle("k", parent=S["kicker"], textColor=colors.white))],
                       [Paragraph(f'<font color="#ffffff">{t(risk)}</font>', S["big"])]],
                      colWidths=[44 * mm], rowHeights=[8 * mm, 14 * mm])
    risk_cell.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), RISK_C.get(risk, MUTED)), ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                                   ("VALIGN", (0, 0), (-1, -1), "MIDDLE"), ("ROUNDEDCORNERS", [8, 8, 8, 8])]))

    def stat(v: object, label: str, bg: colors.Color = SOFT) -> Table:
        tb = Table([[Paragraph(t(v), S["big"])], [Paragraph(t(label), S["center"])]], colWidths=[30 * mm])
        tb.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), bg), ("ROUNDEDCORNERS", [8, 8, 8, 8]),
                                ("TOPPADDING", (0, 0), (-1, 0), 7), ("BOTTOMPADDING", (0, -1), (-1, -1), 7)]))
        return tb

    gauge_col = [Paragraph("OVERALL SCORE", S["kicker"]), Spacer(1, 3), Gauge(result.overall_score, 36 * mm, 8)]
    top = Table([[gauge_col, risk_cell, stat(s.files_scanned, f"files scanned ({s.python_files} Python)"),
                  stat(s.pii_sinks, "personal data reaching a sink"), stat(s.risky_flows, "risky flows", colors.HexColor("#ffe4e6"))]],
                colWidths=[42 * mm, 48 * mm, 30.6 * mm, 30.6 * mm, 30.6 * mm])
    top.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "MIDDLE"), ("LEFTPADDING", (0, 0), (-1, -1), 0)]))

    bar = Bar([(counts["failed"], STATUS_C["failed"]), (counts["needs_review"], STATUS_C["needs_review"]),
               (counts["passed"], STATUS_C["passed"]), (counts["not_assessable"], STATUS_C["not_assessable"])], CONTENT_W)
    legend = Paragraph(
        f'<font color="{STATUS_C["failed"].hexval()}"><b>{counts["failed"]}</b> failed</font> &nbsp;&nbsp; '
        f'<font color="{STATUS_C["needs_review"].hexval()}"><b>{counts["needs_review"]}</b> needs review</font> &nbsp;&nbsp; '
        f'<font color="{STATUS_C["passed"].hexval()}"><b>{counts["passed"]}</b> passed</font> &nbsp;&nbsp; '
        f'<font color="#6b7280"><b>{counts["not_assessable"]}</b> not assessable</font> &nbsp;&nbsp; '
        f'<font color="#6b7280"><b>{s.models_with_pii}</b> data models hold personal data</font>', S["small"])

    out: list = [top, Spacer(1, 8), bar, Spacer(1, 3), legend, Spacer(1, 10)]

    # frameworks table
    rows = [[Paragraph("FRAMEWORK", S["kicker"]), Paragraph("SCORE", S["kicker"]), Paragraph("FAILED", S["kicker"]),
             Paragraph("REVIEW", S["kicker"]), Paragraph("PASSED", S["kicker"]), Paragraph("COVERAGE", S["kicker"])]]
    for p in result.pack_scores:
        sc = "n/a" if p.score is None else f"{p.score:.0f}"
        rows.append([Paragraph(f"<b>{t(p.short_name)}</b><br/><font size=7 color='#6b7280'>{t(p.name)}</font>", S["small"]),
                     Paragraph(f'<font color="{score_color(p.score).hexval()}"><b>{sc}</b></font>', S["h3"]),
                     Paragraph(f'<font color="{STATUS_C["failed"].hexval()}"><b>{p.failed}</b></font>', S["base"]),
                     Paragraph(str(p.needs_review), S["base"]), Paragraph(str(p.passed), S["base"]),
                     Paragraph(f"{p.coverage.automated_checked}/{p.coverage.total} automated, {p.coverage.manual_answered} answered, "
                               f"{p.coverage.not_assessable} not assessable", S["muted"])])
    tb = Table(rows, colWidths=[52 * mm, 18 * mm, 16 * mm, 16 * mm, 16 * mm, CONTENT_W - 118 * mm], repeatRows=1)
    tb.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "MIDDLE"), ("LINEBELOW", (0, 0), (-1, -2), 0.5, LINE),
                            ("TOPPADDING", (0, 0), (-1, -1), 5), ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                            ("BACKGROUND", (0, 0), (-1, 0), SOFT)]))
    out += [tb]

    d = result.diff
    if d:
        def fmt(v: object) -> str:
            return "n/a" if v is None else f"{v}"
        delta = d.get("overall_delta")
        ds = "" if delta is None else f" ({'+' if delta >= 0 else ''}{delta:.1f})"
        fixed = ", ".join(f["rule_id"] for f in d.get("fixed", [])) or "none"
        regressed = ", ".join(f["rule_id"] for f in d.get("regressed", [])) or "none"
        out += [Spacer(1, 10), boxed([
            Paragraph("CHANGES SINCE LAST SCAN", S["kicker"]),
            Paragraph(f"<b>Overall {t(fmt(d.get('overall_before')))} -&gt; {t(fmt(d.get('overall_after')))}{t(ds)}</b> &nbsp; "
                      f"Risk {t(d.get('risk_before'))} -&gt; <b>{t(d.get('risk_after'))}</b>", S["base"]),
            Paragraph(f'<font color="#16a34a"><b>Fixed:</b></font> {t(fixed)}', S["small"]),
            Paragraph(f'<font color="#e11d48"><b>New failures:</b></font> {t(regressed)}', S["small"]),
        ], bg=VIOLET_L)]
    return out


def _top_fixes(result: ScanResult) -> list:
    seen: set[str] = set()
    top = []
    for r in sorted((r for r in result.results if _sv(r.status) == "failed"), key=lambda r: SEV_ORDER[_sv(r.severity)]):
        if r.title not in seen:
            seen.add(r.title)
            top.append(r)
    top = top[:5]
    out = section("01", "Top fixes", "Highest-severity failures first - start here.")
    if not top:
        return out + [Paragraph("No failed rules.", S["base"])]
    for i, r in enumerate(top, 1):
        loc = f"{r.evidence[0].file}:{r.evidence[0].line}" if r.evidence and r.evidence[0].file else ""
        row = Table([[Paragraph(f'<font color="#c4b5fd" size=16><b>{i:02d}</b></font>', S["base"]),
                      [Paragraph(f'<b>{t(r.title)}</b> &nbsp;<font size=7 color="{SEV_C[_sv(r.severity)].hexval()}"><b>{t(_sv(r.severity)).upper()}</b></font>', S["base"]),
                       Paragraph(f'<font name="Courier" color="#6d28d9">{t(loc)}</font>', S["small"]) if loc else Spacer(1, 0),
                       Paragraph(t(r.remediation), S["muted"])]]],
                    colWidths=[12 * mm, CONTENT_W - 12 * mm])
        row.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "TOP"), ("LINEBELOW", (0, 0), (-1, -1), 0.5, LINE),
                                 ("TOPPADDING", (0, 0), (-1, -1), 5), ("BOTTOMPADDING", (0, 0), (-1, -1), 6)]))
        out.append(row)
    return out


def _hotspots(result: ScanResult, pack_names: dict[str, str]) -> list:
    files: dict[str, list[tuple[RuleResult, object]]] = defaultdict(list)
    for r in result.results:
        if _sv(r.status) in ("failed", "needs_review"):
            for e in r.evidence:
                if e.file:
                    files[e.file].append((r, e))
    out = section("02", "Where it breaks", "Every file with a failing or needs-review finding, worst first, with the exact lines.")
    if not files:
        return out + [Paragraph("No file-level problems found.", S["base"])]

    def key(item: tuple[str, list]) -> tuple:
        hits = item[1]
        failed = [h for h in hits if _sv(h[0].status) == "failed"]
        worst = min((SEV_ORDER[_sv(h[0].severity)] for h in (failed or hits)), default=3)
        return (0 if failed else 1, worst, -len(hits))

    for file, hits in sorted(files.items(), key=key):
        failed = sum(1 for h in hits if _sv(h[0].status) == "failed")
        head = Paragraph(f'<font name="Courier-Bold">{t(file)}</font> &nbsp; '
                         + (f'<font size=7 color="#e11d48"><b>{failed} FAILED</b></font> &nbsp;' if failed else "")
                         + (f'<font size=7 color="#d97706"><b>{len(hits) - failed} REVIEW</b></font>' if len(hits) > failed else ""),
                         S["base"])
        rows = [[head, ""]]
        for r, e in sorted(hits, key=lambda h: (h[1].line, STATUS_ORDER[_sv(h[0].status)])):
            rows.append([Paragraph(f"L{e.line}", S["monob"]),
                         [Paragraph(f'<b>{t(r.title)}</b> &nbsp;<font size=7 color="{STATUS_C[_sv(r.status)].hexval()}"><b>{t(_sv(r.status)).replace("_", " ").upper()}</b></font>'
                                    f' &nbsp;<font size=7 color="#6b7280">{t(pack_names.get(r.pack_id, r.pack_id))} - {t(r.rule_id)}</font>', S["small"]),
                          Paragraph(t(e.snippet), S["mono"]) if e.snippet else Spacer(1, 0)]])
        tb = Table(rows, colWidths=[16 * mm, CONTENT_W - 16 * mm])
        tb.setStyle(TableStyle([("SPAN", (0, 0), (-1, 0)), ("BACKGROUND", (0, 0), (-1, 0), SOFT), ("VALIGN", (0, 0), (-1, -1), "TOP"),
                                ("ALIGN", (0, 1), (0, -1), "RIGHT"), ("LINEBELOW", (0, 1), (-1, -2), 0.3, LINE),
                                ("BOX", (0, 0), (-1, -1), 0.6, LINE), ("TOPPADDING", (0, 0), (-1, -1), 4), ("BOTTOMPADDING", (0, 0), (-1, -1), 4)]))
        out += [tb, Spacer(1, 6)]
    return out


def _finding(r: RuleResult, pack_short: str) -> list:
    status, sev = _sv(r.status), _sv(r.severity)
    inner = CONTENT_W - 10 * mm
    head = Table([[pill(status.replace("_", " "), STATUS_C[status]), pill(sev, SEV_C[sev]),
                   Paragraph(f"<b>{t(r.title)}</b>", S["h3"]),
                   Paragraph(f'<font name="Courier" color="#6b7280">{t(r.rule_id)}</font>', S["small"])]],
                 colWidths=[24 * mm, 17 * mm, CONTENT_W - 77 * mm, 36 * mm])
    head.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "MIDDLE"), ("LEFTPADDING", (0, 0), (-1, -1), 0),
                              ("ALIGN", (-1, 0), (-1, 0), "RIGHT"), ("LINEABOVE", (0, 0), (-1, 0), 2, STATUS_C[status]),
                              ("TOPPADDING", (0, 0), (-1, -1), 6)]))

    def label(n: str, word: str, color: str) -> Paragraph:
        return Paragraph(f'<font color="{color}"><b>{n} - {word.upper()}</b></font>', S["kicker"])

    body: list = [label("01", "What", "#e11d48"), Paragraph(t(r.message), S["base"])]
    if r.question:
        ans = _sv(r.manual_answer).replace("_", " ") if r.manual_answer else "not answered"
        body.append(Paragraph(f'<font color="#6b7280">Checklist:</font> {t(r.question)} - <b>{t(ans)}</b>', S["small"]))

    body += [Spacer(1, 5), label("02", "Where", "#6d28d9")]
    if r.evidence:
        rows = []
        for e in r.evidence[:25]:
            loc = f"{e.file}:{e.line}" if e.file else "-"
            cell = [Paragraph(t(e.snippet), S["mono"])] if e.snippet else []
            if e.detail:
                cell.append(Paragraph(t(e.detail), S["muted"]))
            rows.append([Paragraph(t(loc), S["monob"]), cell or Paragraph("", S["small"])])
        if len(r.evidence) > 25:
            rows.append([Paragraph(f"+{len(r.evidence) - 25} more", S["muted"]), ""])
        ev = Table(rows, colWidths=[52 * mm, inner - 52 * mm])
        ev.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "TOP"), ("BACKGROUND", (0, 0), (-1, -1), SOFT),
                                ("LINEBELOW", (0, 0), (-1, -2), 0.3, LINE), ("TOPPADDING", (0, 0), (-1, -1), 3),
                                ("BOTTOMPADDING", (0, 0), (-1, -1), 3), ("ROUNDEDCORNERS", [4, 4, 4, 4])]))
        body.append(ev)
    else:
        body.append(Paragraph("Organisational control - answered from the checklist, not from code." if _sv(r.check_type) == "manual"
                              else "No specific code location for this rule.", S["muted"]))

    ref = t(r.reference) + ("" if r.reference_verified else ' <font color="#d97706"><b>(unverified)</b></font>')
    if r.source_url:
        ref += f' - <link href="{escape(r.source_url)}" color="#6d28d9"><u>source</u></link>'
    body += [Spacer(1, 5), label("03", "Why", "#ca8a04"), Paragraph(t(r.why_it_matters), S["base"]),
             Paragraph(f'<font color="#6b7280">Legal reference:</font> {ref}', S["small"])]
    if r.ai and r.ai.explanation:
        body.append(Paragraph(f'<font color="#6d28d9"><b>AI explanation:</b></font> {t(r.ai.explanation)}', S["small"]))

    body += [Spacer(1, 5), label("04", "How", "#16a34a"), Paragraph(t(r.remediation), S["base"])]
    if r.fix_diff:
        body += [Paragraph("Suggested change (template-generated - review before applying):", S["muted"]), diff_block(r.fix_diff, inner)]
    elif r.ai and (r.ai.suggested_diff or r.ai.suggested_fix):
        body.append(Paragraph("Suggested change (AI-suggested - review before applying):", S["muted"]))
        if r.ai.suggested_fix:
            body.append(Paragraph(t(r.ai.suggested_fix), S["small"]))
        if r.ai.suggested_diff:
            body.append(diff_block(r.ai.suggested_diff, inner))

    wrap = Table([[b] for b in body], colWidths=[inner])
    wrap.setStyle(TableStyle([("LEFTPADDING", (0, 0), (-1, -1), 0), ("RIGHTPADDING", (0, 0), (-1, -1), 0),
                              ("TOPPADDING", (0, 0), (-1, -1), 1.5), ("BOTTOMPADDING", (0, 0), (-1, -1), 1.5)]))
    indent = Table([["", wrap]], colWidths=[10 * mm, inner])
    indent.setStyle(TableStyle([("LEFTPADDING", (0, 0), (-1, -1), 0), ("RIGHTPADDING", (0, 0), (-1, -1), 0),
                                ("LINEBEFORE", (1, 0), (1, 0), 1.2, STATUS_C[status]), ("LEFTPADDING", (1, 0), (1, 0), 8)]))
    return [CondPageBreak(75 * mm), KeepTogether([head, Spacer(1, 4)]), indent, Spacer(1, 10)]


def _compact(rs: list[RuleResult]) -> Table:
    rows = [[Paragraph("STATUS", S["kicker"]), Paragraph("RULE", S["kicker"]), Paragraph("TITLE", S["kicker"])]]
    for r in rs:
        st = _sv(r.status)
        rows.append([Paragraph(f'<font color="{STATUS_C[st].hexval()}"><b>{t(st.replace("_", " "))}</b></font>', S["small"]),
                     Paragraph(t(r.rule_id), S["mono"]), Paragraph(t(r.title), S["small"])])
    tb = Table(rows, colWidths=[28 * mm, 36 * mm, CONTENT_W - 64 * mm], repeatRows=1)
    tb.setStyle(TableStyle([("LINEBELOW", (0, 0), (-1, -2), 0.3, LINE), ("BACKGROUND", (0, 0), (-1, 0), SOFT),
                            ("VALIGN", (0, 0), (-1, -1), "TOP")]))
    return tb


def _findings(result: ScanResult) -> list:
    out = section("03", "Findings by framework",
                  "Each failing or needs-review rule: what is wrong, where it breaks, why it matters and how to fix it.")
    for p in result.pack_scores:
        rs = sorted((r for r in result.results if r.pack_id == p.pack_id),
                    key=lambda r: (STATUS_ORDER[_sv(r.status)], SEV_ORDER[_sv(r.severity)]))
        sc = "n/a" if p.score is None else f"{p.score:.0f}/100"
        header = Table([[Gauge(p.score, 18 * mm, 4.5),
                         [Paragraph(t(p.name), S["h3"]),
                          Paragraph(f'<font color="{score_color(p.score).hexval()}"><b>{sc}</b></font> &nbsp; '
                                    f"{p.passed} passed - {p.failed} failed - {p.needs_review} review - {p.not_assessable} n/a", S["muted"])]]],
                       colWidths=[22 * mm, CONTENT_W - 22 * mm])
        header.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "MIDDLE"), ("BACKGROUND", (0, 0), (-1, -1), SOFT),
                                    ("ROUNDEDCORNERS", [8, 8, 8, 8]), ("TOPPADDING", (0, 0), (-1, -1), 6), ("BOTTOMPADDING", (0, 0), (-1, -1), 6)]))
        out += [CondPageBreak(60 * mm), Spacer(1, 6), header, Spacer(1, 8)]
        open_ = [r for r in rs if _sv(r.status) in ("failed", "needs_review")]
        rest = [r for r in rs if _sv(r.status) not in ("failed", "needs_review")]
        for r in open_:
            out += _finding(r, p.short_name)
        if rest:
            out += [Paragraph("Passed and not assessable", S["h4"]), Spacer(1, 3), _compact(rest), Spacer(1, 8)]
    return out


def _checklist(result: ScanResult, pack_names: dict[str, str]) -> list:
    manual = [r for r in result.results if _sv(r.check_type) != "automated" and r.question]
    out = section("04", "Manual checklist answers")
    if not manual:
        return out + [Paragraph("No manual questions for these frameworks.", S["muted"])]
    rows = [[Paragraph(h, S["kicker"]) for h in ("RULE", "QUESTION", "ANSWER", "RESULT")]]
    for m in manual:
        st = _sv(m.status)
        rows.append([Paragraph(f"{t(m.rule_id)}<br/><font size=6.5 color='#6b7280'>{t(pack_names.get(m.pack_id, m.pack_id))}</font>", S["mono"]),
                     Paragraph(t(m.question), S["small"]),
                     Paragraph(t(_sv(m.manual_answer).replace("_", " ") if m.manual_answer else "-"), S["small"]),
                     Paragraph(f'<font color="{STATUS_C[st].hexval()}"><b>{t(st.replace("_", " "))}</b></font>', S["small"])])
    tb = Table(rows, colWidths=[34 * mm, CONTENT_W - 84 * mm, 22 * mm, 28 * mm], repeatRows=1)
    tb.setStyle(TableStyle([("LINEBELOW", (0, 0), (-1, -2), 0.3, LINE), ("BACKGROUND", (0, 0), (-1, 0), SOFT), ("VALIGN", (0, 0), (-1, -1), "TOP")]))
    return out + [tb]


def _coverage(result: ScanResult) -> list:
    out = section("05", "Coverage and limitations")
    for p in result.pack_scores:
        c = p.coverage
        out.append(Paragraph(f"- <b>{t(p.short_name)}</b>: {c.automated_checked} of {c.total} rules checked automatically, "
                             f"{c.manual_answered} answered manually, {c.not_assessable} not assessable from code, {c.needs_review} need review.", S["base"]))
    for line in ("Python is analysed in depth; other files get identifier, secret and configuration checks.",
                 "Flow tracking is intra-function plus calls into repo modules; dynamic dispatch and infrastructure config are not followed.",
                 "Consent, minimisation, children's data and third-party sharing are heuristics and never \"fail\" on their own."):
        out.append(Paragraph(f'<font color="#6b7280">- {t(line)}</font>', S["base"]))
    flows = result.data_flow.get("edges", []) if isinstance(result.data_flow, dict) else []
    risky = [e for e in flows if e.get("risky")]
    if risky:
        names = {n["id"]: n.get("label", n["id"]) for n in result.data_flow.get("nodes", [])}
        out += section("06", "Risky data flows", "Personal data reaching AI prompts, logs or third parties unredacted.")
        rows = [[Paragraph(h, S["kicker"]) for h in ("FROM", "TO", "WHERE")]]
        for e in risky[:60]:
            rows.append([Paragraph(t(names.get(e["source"], e["source"])), S["mono"]), Paragraph(t(names.get(e["target"], e["target"])), S["mono"]),
                         Paragraph(t(", ".join(e.get("locations", [])[:4])), S["mono"])])
        tb = Table(rows, colWidths=[52 * mm, 52 * mm, CONTENT_W - 104 * mm], repeatRows=1)
        tb.setStyle(TableStyle([("LINEBELOW", (0, 0), (-1, -2), 0.3, LINE), ("BACKGROUND", (0, 0), (-1, 0), SOFT), ("VALIGN", (0, 0), (-1, -1), "TOP")]))
        out.append(tb)
    out += section("07", "Disclaimer")
    out += [Paragraph(t(result.disclaimer), S["base"]), Spacer(1, 6),
            boxed([Paragraph(f"<b>How the score is calculated.</b> {t(result.scoring_formula)}", S["small"])])]
    return out


# ------------------------------------------------------------------ public API
def render_pdf(result: ScanResult) -> bytes:
    buf = io.BytesIO()
    doc = BaseDocTemplate(buf, pagesize=A4, leftMargin=MARGIN, rightMargin=MARGIN, topMargin=16 * mm, bottomMargin=16 * mm,
                          title=f"PrivTrace report - {_plain(result.target)}", author="PrivTrace",
                          subject="Compliance exposure report (not legal advice)")
    first = Frame(MARGIN, 16 * mm, CONTENT_W, PAGE_H - 16 * mm - 58 * mm, id="first", leftPadding=0, rightPadding=0)
    later = Frame(MARGIN, 16 * mm, CONTENT_W, PAGE_H - 32 * mm, id="later", leftPadding=0, rightPadding=0)
    doc.addPageTemplates([PageTemplate("cover", [first], onPage=lambda c, d: _cover_band(c, d, result)),
                          PageTemplate("body", [later], onPage=lambda c, d: _later(c, d, result))])

    created = result.created_at.strftime("%d %b %Y, %H:%M UTC") if isinstance(result.created_at, datetime) else str(result.created_at)
    pack_names = {p.pack_id: p.short_name for p in result.pack_scores}
    meta = f"Scan {result.scan_id} - {created} - {', '.join(pack_names.values())}"
    if result.ai_used and result.ai_model:
        meta += f" - AI: {result.ai_model}"

    story: list = [NextPageTemplate("body"),
                   Paragraph("REPORT", S["kicker"]), Paragraph(f"<b>{t(result.target)}</b>", S["h2"]), Paragraph(t(meta), S["muted"]),
                   Spacer(1, 8),
                   boxed([Paragraph(f'<font color="#92400e"><b>Not legal advice.</b> {t(result.disclaimer)}</font>', S["small"])],
                         bg=colors.HexColor("#fffbeb"), border=colors.HexColor("#fde68a")),
                   Spacer(1, 10)]
    story += _summary(result)
    story += _top_fixes(result)
    story += _hotspots(result, pack_names)
    story += [PageBreak()]
    story += _findings(result)
    story += _checklist(result, pack_names)
    story += _coverage(result)
    doc.build(story)
    return buf.getvalue()


def write_pdf(result: ScanResult, out: Path) -> Path:
    out.write_bytes(render_pdf(result))
    return out
