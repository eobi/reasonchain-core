"""Render paper/paper_filled.md (or paper.md if filled doesn't exist)
as a PDF using reportlab's flowables + python-markdown for the heavy
lifting on inline formatting.

Output:
    paper/paper.pdf

We don't try to be LaTeX-quality — that's what pandoc + LaTeX is for.
This is a self-contained, no-external-binaries renderer that produces
a readable academic-style PDF for sharing the draft with advisors.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.pagesizes import LETTER
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import (
    PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle,
)

REPO_ROOT = Path(__file__).resolve().parent.parent
SOURCES = (
    REPO_ROOT / "paper" / "paper_filled.md",
    REPO_ROOT / "paper" / "paper.md",
)
OUT = REPO_ROOT / "paper" / "paper.pdf"


def _styles() -> dict[str, ParagraphStyle]:
    base = getSampleStyleSheet()
    return {
        "title": ParagraphStyle(
            "title", parent=base["Title"], fontSize=18, leading=22,
            spaceAfter=4, textColor=colors.HexColor("#0f172a"),
            alignment=1,
        ),
        "authors": ParagraphStyle(
            "authors", parent=base["Normal"], fontSize=10, leading=12,
            alignment=1, textColor=colors.HexColor("#334155"),
            spaceAfter=4,
        ),
        "affil": ParagraphStyle(
            "affil", parent=base["Normal"], fontSize=8, leading=10,
            alignment=1, textColor=colors.HexColor("#64748b"),
            spaceAfter=12,
        ),
        "abstract_label": ParagraphStyle(
            "abstract_label", parent=base["Heading4"], fontSize=10,
            leading=12, textColor=colors.HexColor("#0f172a"),
            spaceAfter=2,
        ),
        "abstract": ParagraphStyle(
            "abstract", parent=base["Normal"], fontSize=9, leading=12,
            leftIndent=10, rightIndent=10, textColor=colors.HexColor("#0f172a"),
            spaceAfter=8,
        ),
        "h1": ParagraphStyle(
            "h1", parent=base["Heading1"], fontSize=14, leading=18,
            textColor=colors.HexColor("#0f172a"),
            spaceBefore=14, spaceAfter=8,
        ),
        "h2": ParagraphStyle(
            "h2", parent=base["Heading2"], fontSize=11, leading=14,
            textColor=colors.HexColor("#0f172a"),
            spaceBefore=10, spaceAfter=4,
        ),
        "body": ParagraphStyle(
            "body", parent=base["Normal"], fontSize=9.5, leading=13,
            textColor=colors.HexColor("#0f172a"),
            spaceAfter=6, alignment=4,  # justify
        ),
        "code": ParagraphStyle(
            "code", parent=base["Code"], fontSize=8, leading=10,
            textColor=colors.HexColor("#0f172a"),
            leftIndent=18, backColor=colors.HexColor("#f1f5f9"),
        ),
        "bullet": ParagraphStyle(
            "bullet", parent=base["Normal"], fontSize=9.5, leading=12,
            leftIndent=14, bulletIndent=4, spaceAfter=3,
            textColor=colors.HexColor("#0f172a"),
        ),
    }


def _inline(text: str) -> str:
    """Convert minimal markdown inline syntax to reportlab Paragraph
    inline tags. Supports **bold**, *italic*, `code`, [link](url)."""
    text = escape(text)
    # Inline code: `x` → <font face=Courier>x</font>
    text = re.sub(r"`([^`]+)`",
                  r'<font face="Courier" size="9">\1</font>', text)
    text = re.sub(r"\*\*([^*]+)\*\*", r"<b>\1</b>", text)
    text = re.sub(r"(?<!\*)\*([^*\n]+)\*(?!\*)", r"<i>\1</i>", text)
    text = re.sub(r"\[([^\]]+)\]\(([^)]+)\)",
                  r'<link href="\2" color="#1e40af">\1</link>', text)
    return text


def _parse_yaml_frontmatter(md: str) -> tuple[dict, str]:
    """Strip the YAML frontmatter block (between leading ``---`` lines)
    and return (metadata, remaining markdown)."""
    if not md.startswith("---\n"):
        return {}, md
    end = md.find("\n---\n", 4)
    if end < 0:
        return {}, md
    header = md[4:end]
    body = md[end + 5:]
    meta: dict = {}
    cur_key: str | None = None
    buf: list[str] = []
    for line in header.split("\n"):
        if not line.strip():
            continue
        if not line.startswith(" "):
            if cur_key is not None:
                meta[cur_key] = "\n".join(buf).strip()
                buf = []
            if ":" in line:
                k, _, v = line.partition(":")
                cur_key = k.strip()
                v = v.strip()
                if v == "|":
                    buf = []
                elif v:
                    meta[cur_key] = v.strip()
                    cur_key = None
        else:
            buf.append(line.strip("- ").strip())
    if cur_key is not None:
        meta[cur_key] = "\n".join(buf).strip() if buf else meta.get(cur_key, "")
    return meta, body


def _md_to_flowables(body: str, s: dict) -> list:
    out: list = []
    lines = body.split("\n")
    i = 0
    in_code = False
    code_buf: list[str] = []
    para_buf: list[str] = []

    def flush_para():
        nonlocal para_buf
        if para_buf:
            out.append(Paragraph(_inline(" ".join(para_buf)), s["body"]))
            para_buf = []

    while i < len(lines):
        line = lines[i]
        if line.startswith("```"):
            if in_code:
                out.append(Paragraph(
                    "<font face='Courier' size='8'>"
                    + escape("\n".join(code_buf)).replace("\n", "<br/>")
                    + "</font>", s["code"],
                ))
                code_buf = []
                in_code = False
            else:
                flush_para()
                in_code = True
            i += 1
            continue
        if in_code:
            code_buf.append(line)
            i += 1
            continue

        if line.startswith("# "):
            flush_para()
            out.append(Paragraph(_inline(line[2:].strip()), s["h1"]))
        elif line.startswith("## "):
            flush_para()
            out.append(Paragraph(_inline(line[3:].strip()), s["h2"]))
        elif line.startswith("### "):
            flush_para()
            out.append(Paragraph(_inline(line[4:].strip()), s["h2"]))
        elif line.startswith("- "):
            flush_para()
            out.append(Paragraph(
                "&bull; " + _inline(line[2:].strip()), s["bullet"],
            ))
        elif line.startswith("|") and line.count("|") >= 2:
            # Markdown table — collect until non-table line.
            tbl_lines = []
            while i < len(lines) and lines[i].lstrip().startswith("|"):
                tbl_lines.append(lines[i])
                i += 1
            out.append(_md_table(tbl_lines, s))
            continue
        elif not line.strip():
            flush_para()
        else:
            para_buf.append(line.strip())
        i += 1
    flush_para()
    if in_code and code_buf:
        out.append(Paragraph(
            "<font face='Courier' size='8'>"
            + escape("\n".join(code_buf)).replace("\n", "<br/>")
            + "</font>", s["code"],
        ))
    return out


def _md_table(rows: list[str], s: dict) -> Table:
    parsed = []
    for r in rows:
        cells = [c.strip() for c in r.strip("|").split("|")]
        parsed.append(cells)
    # Drop separator row (---|---).
    parsed = [
        r for r in parsed
        if not all(re.fullmatch(r"[-:\s]+", c) for c in r if c)
    ]
    parsed = [
        [Paragraph(_inline(c), s["body"]) for c in row]
        for row in parsed
    ]
    t = Table(parsed, repeatRows=1)
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f172a")),
        ("TEXTCOLOR",  (0, 0), (-1, 0), colors.white),
        ("FONTNAME",   (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE",   (0, 0), (-1, -1), 8),
        ("VALIGN",     (0, 0), (-1, -1), "TOP"),
        ("GRID",       (0, 0), (-1, -1), 0.25, colors.HexColor("#cbd5e1")),
        ("LEFTPADDING",(0, 0), (-1, -1), 4),
        ("RIGHTPADDING",(0, 0), (-1, -1), 4),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING",(0, 0), (-1, -1), 3),
    ]))
    return t


def main() -> int:
    src = next((p for p in SOURCES if p.exists()), None)
    if src is None:
        print(f"no paper source at {SOURCES[0]} or {SOURCES[1]}",
              file=sys.stderr)
        return 1
    md = src.read_text()
    meta, body = _parse_yaml_frontmatter(md)
    s = _styles()

    doc = SimpleDocTemplate(
        str(OUT), pagesize=LETTER,
        leftMargin=0.85*inch, rightMargin=0.85*inch,
        topMargin=0.7*inch, bottomMargin=0.7*inch,
        title=meta.get("title", "ReasonChain"),
        author="; ".join(
            meta.get("author", "").split("\n")
            if isinstance(meta.get("author"), str) else []
        ),
    )
    flow: list = []
    flow.append(Paragraph(_inline(meta.get("title", "Paper")),
                          s["title"]))
    if "author" in meta:
        authors = meta["author"]
        # Strip caret-footnote markup for the printed line.
        authors_clean = re.sub(r"\^?\[[^\]]*\]", "", authors).strip()
        authors_clean = authors_clean.replace("\n", ", ")
        flow.append(Paragraph(authors_clean, s["authors"]))
        flow.append(Paragraph(
            "Department of Computer Science, University of Dayton, USA",
            s["affil"],
        ))
    if "abstract" in meta:
        flow.append(Paragraph("Abstract", s["abstract_label"]))
        flow.append(Paragraph(_inline(
            meta["abstract"].replace("\n", " ")
        ), s["abstract"]))
    if "keywords" in meta:
        flow.append(Paragraph(
            "<b>Keywords.</b> " + _inline(
                meta["keywords"].replace("\n", ", ")
            ), s["affil"],
        ))
    flow.append(Spacer(1, 0.15*inch))
    flow.extend(_md_to_flowables(body, s))
    doc.build(flow)
    print(f"Wrote {OUT}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
