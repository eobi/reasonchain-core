"""Report renderer — turn an ``AssessmentResult`` into a structured PDF
plus a parallel JSON artifact.

Pentagon's analogue lives in ``pentagon/intelligence/vuln_assessor/
report_pdf.py``. This module is the reasonchain-core mirror: same
structure (executive summary + severity breakdown + per-engine groups
+ CVE roll-up + per-finding evidence) using pure-Python ``reportlab``
so no external binaries are required.

Public API:

    render_pdf(result, out_path)        # AssessmentResult -> PDF file
    render_json(result, out_path)       # AssessmentResult -> JSON file
    render_both(result, stem)           # writes <stem>.pdf and <stem>.json

The PDF is intentionally compact (executive summary fits on one
landing page) but every finding gets a row, with CVE IDs and
evidence keys called out.
"""
from __future__ import annotations

import json
from collections import Counter
from dataclasses import asdict, is_dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from reportlab.lib import colors
from reportlab.lib.pagesizes import LETTER
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import (
    PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle,
)

from reasonchain.models import AssessmentResult, Finding


_SEV_COLORS = {
    "critical": colors.HexColor("#7c0a02"),
    "high":     colors.HexColor("#c8102e"),
    "medium":   colors.HexColor("#e08400"),
    "low":      colors.HexColor("#2867b2"),
    "info":     colors.HexColor("#5a6e8c"),
}
_SEV_ORDER = ("critical", "high", "medium", "low", "info")


# ── Public API ────────────────────────────────────────────────────────


def render_json(result: AssessmentResult, out_path: str | Path) -> Path:
    p = Path(out_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(_dump(result), indent=2, default=str))
    return p


def render_pdf(result: AssessmentResult, out_path: str | Path) -> Path:
    """Render the assessment as a structured PDF.

    Layout:
      1. Executive summary (target, duration, severity counts)
      2. Engines that fired
      3. Severity breakdown table
      4. CVE roll-up (sorted by occurrence)
      5. Findings grouped by engine, then by severity
    """
    p = Path(out_path)
    p.parent.mkdir(parents=True, exist_ok=True)

    doc = SimpleDocTemplate(
        str(p), pagesize=LETTER,
        leftMargin=0.6*inch, rightMargin=0.6*inch,
        topMargin=0.7*inch, bottomMargin=0.7*inch,
        title=f"reasonchain assessment — {result.spec.target}",
        author="reasonchain-core",
    )

    styles = _styles()
    flow: list = []
    flow.extend(_block_header(result, styles))
    flow.extend(_block_executive_summary(result, styles))
    flow.extend(_block_engines(result, styles))
    flow.extend(_block_severity(result, styles))
    flow.extend(_block_cve_rollup(result, styles))
    flow.append(PageBreak())
    flow.extend(_block_findings(result, styles))

    doc.build(flow)
    return p


def render_both(result: AssessmentResult, stem: str | Path) -> dict:
    """Convenience: writes both ``<stem>.pdf`` and ``<stem>.json``."""
    stem = Path(stem)
    return {
        "pdf": render_pdf(result, stem.with_suffix(".pdf")),
        "json": render_json(result, stem.with_suffix(".json")),
    }


# ── Style ─────────────────────────────────────────────────────────────


def _styles() -> dict:
    base = getSampleStyleSheet()
    return {
        "title": ParagraphStyle(
            "title", parent=base["Title"], fontSize=20,
            spaceAfter=4, textColor=colors.HexColor("#0f172a"),
        ),
        "subtitle": ParagraphStyle(
            "subtitle", parent=base["Normal"], fontSize=10,
            textColor=colors.HexColor("#475569"),
            spaceAfter=14,
        ),
        "h2": ParagraphStyle(
            "h2", parent=base["Heading2"], fontSize=13,
            textColor=colors.HexColor("#0f172a"),
            spaceBefore=10, spaceAfter=6,
        ),
        "h3": ParagraphStyle(
            "h3", parent=base["Heading3"], fontSize=11,
            textColor=colors.HexColor("#0f172a"),
            spaceBefore=8, spaceAfter=4,
        ),
        "body": ParagraphStyle(
            "body", parent=base["Normal"], fontSize=9, leading=12,
        ),
        "mono": ParagraphStyle(
            "mono", parent=base["Code"], fontSize=8, leading=10,
            textColor=colors.HexColor("#0f172a"),
        ),
        "muted": ParagraphStyle(
            "muted", parent=base["Normal"], fontSize=8,
            textColor=colors.HexColor("#64748b"),
        ),
    }


# ── Blocks ────────────────────────────────────────────────────────────


def _block_header(result: AssessmentResult, s: dict) -> list:
    spec = result.spec
    title = f"Vulnerability Assessment — {spec.target}"
    sub = (
        f"Generated {datetime.now().isoformat(timespec='seconds')} · "
        f"target_type={spec.target_type} · "
        f"max_steps={spec.max_steps} · max_depth={spec.max_depth}"
    )
    return [Paragraph(title, s["title"]), Paragraph(sub, s["subtitle"])]


def _block_executive_summary(result: AssessmentResult, s: dict) -> list:
    sev_counts = Counter(f.severity for f in result.findings)
    high_plus = sev_counts.get("critical", 0) + sev_counts.get("high", 0)
    cve_count = len({c for f in result.findings for c in (f.cve_ids or [])})
    rows = [
        ["Engines ran",        ", ".join(result.engines_used) or "(none)"],
        ["Total findings",     str(len(result.findings))],
        ["Critical + High",    str(high_plus)],
        ["Unique CVEs cited",  str(cve_count)],
        ["Duration",           f"{result.duration_s:.1f}s"],
        ["Replans (closed loop)", str(result.replans)],
        ["Decisions recorded", str(len(result.decisions))],
    ]
    if result.aborted:
        rows.append(["Aborted", result.abort_reason or "(no reason)"])
    return [
        Paragraph("Executive Summary", s["h2"]),
        _kv_table(rows),
        Spacer(1, 0.15*inch),
    ]


def _block_engines(result: AssessmentResult, s: dict) -> list:
    """List which engines produced findings + how many."""
    by_engine = Counter(f.source for f in result.findings)
    rows = [["Engine", "Findings"]]
    for eng in result.engines_used:
        rows.append([eng, str(by_engine.get(eng, 0))])
    return [
        Paragraph("Engines fired", s["h2"]),
        _header_table(rows),
        Spacer(1, 0.1*inch),
    ]


def _block_severity(result: AssessmentResult, s: dict) -> list:
    sev_counts = Counter(f.severity for f in result.findings)
    rows = [["Severity", "Count"]]
    for sev in _SEV_ORDER:
        rows.append([sev.capitalize(), str(sev_counts.get(sev, 0))])
    t = _header_table(rows)
    # Color the severity cells.
    for i, sev in enumerate(_SEV_ORDER, start=1):
        t.setStyle(TableStyle([
            ("TEXTCOLOR", (0, i), (0, i), _SEV_COLORS[sev]),
            ("FONTNAME", (0, i), (0, i), "Helvetica-Bold"),
        ]))
    return [
        Paragraph("Severity breakdown", s["h2"]),
        t, Spacer(1, 0.1*inch),
    ]


def _block_cve_rollup(result: AssessmentResult, s: dict) -> list:
    cves = Counter()
    for f in result.findings:
        for c in (f.cve_ids or []):
            cves[c] += 1
    if not cves:
        return [Paragraph("CVEs cited: none", s["muted"]),
                Spacer(1, 0.1*inch)]
    rows = [["CVE", "Occurrences"]]
    for cve, n in cves.most_common(20):
        rows.append([cve, str(n)])
    out = [
        Paragraph("Top CVEs cited", s["h2"]),
        _header_table(rows),
    ]
    if len(cves) > 20:
        out.append(Paragraph(f"… and {len(cves) - 20} more CVEs",
                             s["muted"]))
    out.append(Spacer(1, 0.1*inch))
    return out


def _block_findings(result: AssessmentResult, s: dict) -> list:
    flow: list = [Paragraph("Findings (by engine, severity-sorted)",
                            s["h2"])]
    if not result.findings:
        return flow + [Paragraph("(no findings)", s["muted"])]
    by_engine: dict[str, list[Finding]] = {}
    for f in result.findings:
        by_engine.setdefault(f.source, []).append(f)
    for engine, findings in by_engine.items():
        findings.sort(
            key=lambda f: (_SEV_ORDER.index(f.severity)
                           if f.severity in _SEV_ORDER else 99),
        )
        flow.append(Paragraph(
            f"{engine} — {len(findings)} finding(s)", s["h3"],
        ))
        rows = [["Sev", "Finding", "CVEs / Evidence"]]
        for f in findings[:200]:  # cap per engine
            sev_cell = Paragraph(
                f"<font color='{_SEV_COLORS.get(f.severity, colors.black).hexval()}'>"
                f"<b>{f.severity}</b></font>",
                s["body"],
            )
            evidence_parts: list[str] = []
            if f.cve_ids:
                evidence_parts.append(
                    "CVE: " + ", ".join(f.cve_ids[:4])
                )
            for k in list((f.evidence or {}).keys())[:3]:
                v = str(f.evidence[k])
                if len(v) > 90:
                    v = v[:90] + "…"
                evidence_parts.append(f"{k}={v}")
            rows.append([
                sev_cell,
                Paragraph(_html_safe(f.title[:240]), s["body"]),
                Paragraph(_html_safe(" · ".join(evidence_parts)[:340]),
                          s["body"]),
            ])
        t = Table(
            rows,
            colWidths=[0.55*inch, 3.0*inch, 3.6*inch],
            repeatRows=1,
        )
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e2e8f0")),
            ("FONTNAME",  (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE",  (0, 0), (-1, -1), 8),
            ("VALIGN",    (0, 0), (-1, -1), "TOP"),
            ("GRID",      (0, 0), (-1, -1), 0.25, colors.HexColor("#cbd5e1")),
            ("LEFTPADDING",  (0, 0), (-1, -1), 4),
            ("RIGHTPADDING", (0, 0), (-1, -1), 4),
            ("TOPPADDING",   (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING",(0, 0), (-1, -1), 3),
        ]))
        flow.append(t)
        if len(findings) > 200:
            flow.append(Paragraph(
                f"(truncated to first 200 of {len(findings)} findings "
                f"from {engine})", s["muted"],
            ))
        flow.append(Spacer(1, 0.1*inch))
    return flow


# ── Helpers ───────────────────────────────────────────────────────────


def _kv_table(rows: list[list[str]]) -> Table:
    t = Table(rows, colWidths=[1.7*inch, 5.5*inch])
    t.setStyle(TableStyle([
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#f1f5f9")),
        ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#e2e8f0")),
        ("LEFTPADDING", (0, 0), (-1, -1), 5),
        ("RIGHTPADDING", (0, 0), (-1, -1), 5),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
    ]))
    return t


def _header_table(rows: list[list[str]]) -> Table:
    t = Table(rows, hAlign="LEFT")
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f172a")),
        ("TEXTCOLOR",  (0, 0), (-1, 0), colors.white),
        ("FONTNAME",   (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE",   (0, 0), (-1, -1), 9),
        ("GRID",       (0, 0), (-1, -1), 0.25, colors.HexColor("#cbd5e1")),
        ("LEFTPADDING",(0, 0), (-1, -1), 5),
        ("RIGHTPADDING",(0, 0), (-1, -1), 5),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING",(0, 0), (-1, -1), 3),
    ]))
    return t


def _html_safe(s: str) -> str:
    return (s.replace("&", "&amp;")
             .replace("<", "&lt;")
             .replace(">", "&gt;"))


def _dump(result: AssessmentResult) -> dict[str, Any]:
    """Recursive dataclass → dict so json.dump can serialise it."""
    def _conv(o):
        if is_dataclass(o):
            return {k: _conv(v) for k, v in asdict(o).items()}
        if isinstance(o, (list, tuple)):
            return [_conv(x) for x in o]
        if isinstance(o, dict):
            return {k: _conv(v) for k, v in o.items()}
        return o
    return _conv(result)
