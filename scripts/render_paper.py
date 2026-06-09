"""Render paper/paper_filled.md (or paper.md if filled doesn't exist)
as a PDF using reportlab.

Supports:
  - YAML frontmatter (title, author list, abstract, keywords) via PyYAML
  - Headings ## / ###
  - Bulleted lists ``- foo``
  - Bold ``**bold**``, italic ``*italic*``, inline ``code``,
    [text](url) links
  - Fenced code blocks ```...```
  - Markdown tables
  - Embedded figures via ``![caption](relative/path.png)``

This is not pandoc-quality typesetting — it produces a readable
academic draft PDF without external binary dependencies (pandoc,
LaTeX, etc.). For the camera-ready, the LaTeX path lives in
scripts/render_paper_latex.py.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path
from xml.sax.saxutils import escape

import yaml  # type: ignore[import-not-found]
from reportlab.lib import colors
from reportlab.lib.pagesizes import LETTER
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import (
    Image, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle,
)

REPO_ROOT = Path(__file__).resolve().parent.parent
SOURCES = (
    REPO_ROOT / "paper" / "paper_filled.md",
    REPO_ROOT / "paper" / "paper.md",
)
OUT = REPO_ROOT / "paper" / "paper.pdf"

# Inner column width available for embedded figures, given our
# default 0.85" left/right margins on a 8.5" page.
_INNER_WIDTH = (8.5 - 1.7) * inch  # ~6.8"


def _styles() -> dict[str, ParagraphStyle]:
    base = getSampleStyleSheet()
    return {
        "title": ParagraphStyle(
            "title", parent=base["Title"], fontSize=18, leading=22,
            spaceAfter=4, textColor=colors.HexColor("#0f172a"),
            alignment=1,
        ),
        "authors": ParagraphStyle(
            "authors", parent=base["Normal"], fontSize=11, leading=13,
            alignment=1, textColor=colors.HexColor("#0f172a"),
            spaceAfter=2,
        ),
        "affil": ParagraphStyle(
            "affil", parent=base["Normal"], fontSize=9, leading=11,
            alignment=1, textColor=colors.HexColor("#475569"),
            spaceAfter=10,
        ),
        "abstract_label": ParagraphStyle(
            "abstract_label", parent=base["Heading4"], fontSize=10,
            leading=12, textColor=colors.HexColor("#0f172a"),
            spaceAfter=2,
        ),
        "abstract": ParagraphStyle(
            "abstract", parent=base["Normal"], fontSize=9, leading=12,
            leftIndent=10, rightIndent=10,
            textColor=colors.HexColor("#0f172a"),
            spaceAfter=8,
        ),
        "keywords": ParagraphStyle(
            "keywords", parent=base["Normal"], fontSize=9, leading=11,
            leftIndent=10, rightIndent=10,
            textColor=colors.HexColor("#0f172a"),
            spaceAfter=10,
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
        "figcaption": ParagraphStyle(
            "figcaption", parent=base["Normal"], fontSize=8.5,
            leading=11, alignment=1, leftIndent=18, rightIndent=18,
            spaceBefore=2, spaceAfter=10,
            textColor=colors.HexColor("#475569"),
        ),
    }


def _inline(text: str) -> str:
    """Markdown inline → reportlab Paragraph tags."""
    text = escape(text)
    text = re.sub(r"`([^`]+)`",
                  r'<font face="Courier" size="9">\1</font>', text)
    text = re.sub(r"\*\*([^*]+)\*\*", r"<b>\1</b>", text)
    text = re.sub(r"(?<!\*)\*([^*\n]+)\*(?!\*)", r"<i>\1</i>", text)
    text = re.sub(r"\[([^\]]+)\]\(([^)]+)\)",
                  r'<link href="\2" color="#1e40af">\1</link>', text)
    return text


def _parse_yaml_frontmatter(md: str) -> tuple[dict, str]:
    """Use PyYAML to parse the leading ``---``-fenced block. Returns
    (metadata_dict, body). Robust to author lists, multi-line
    strings, keywords lists, etc."""
    if not md.startswith("---\n"):
        return {}, md
    end = md.find("\n---\n", 4)
    if end < 0:
        return {}, md
    header = md[4:end]
    body = md[end + 5:]
    try:
        meta = yaml.safe_load(header) or {}
    except yaml.YAMLError:
        meta = {}
    return meta, body


def _figure_flowables(
    alt_text: str, image_path: Path, s: dict,
) -> list:
    """Embed an image with its caption underneath, scaling to fit
    both the inner column width and a max single-page height."""
    if not image_path.exists():
        return [Paragraph(
            _inline(f"*[Figure missing: {image_path.name}]*"),
            s["body"],
        )]
    # Compute the native aspect ratio so we can clamp by height.
    from reportlab.lib.utils import ImageReader
    ir = ImageReader(str(image_path))
    iw, ih = ir.getSize()
    aspect = ih / iw if iw else 1.0
    max_w = _INNER_WIDTH
    max_h = 5.5 * inch  # leave room for caption + body around it
    target_w = max_w
    target_h = max_w * aspect
    if target_h > max_h:
        target_h = max_h
        target_w = max_h / aspect if aspect else max_w
    img = Image(str(image_path), width=target_w, height=target_h)
    img.hAlign = "CENTER"
    return [
        Spacer(1, 0.08 * inch),
        img,
        Paragraph(_inline(alt_text), s["figcaption"]),
    ]


_FIG_RE = re.compile(r"^!\[(?P<alt>[^\]]*)\]\((?P<path>[^)]+)\)\s*$")


def _md_to_flowables(body: str, s: dict, paper_dir: Path) -> list:
    out: list = []
    lines = body.split("\n")
    i = 0
    in_code = False
    code_buf: list[str] = []
    para_buf: list[str] = []

    def flush_para():
        nonlocal para_buf
        if para_buf:
            out.append(Paragraph(
                _inline(" ".join(para_buf)), s["body"],
            ))
            para_buf = []

    # Collect multi-line image syntax (caption can wrap).
    while i < len(lines):
        line = lines[i]

        # Multi-line image block — caption can wrap across lines
        # until the closing ``](path)``.
        if line.lstrip().startswith("![") and "](" not in line:
            # Accumulate caption lines until we hit the line that
            # closes the image with ``](path)``. The closing line is
            # detected by the presence of ``](`` — parentheses inside
            # the caption (e.g. ``(P1)``) are tolerated.
            buf = [line]
            while i + 1 < len(lines) and "](" not in lines[i + 1]:
                i += 1
                buf.append(lines[i])
            if i + 1 < len(lines):
                i += 1
                buf.append(lines[i])
            joined = " ".join(b.strip() for b in buf)
            joined = re.sub(r"\s+", " ", joined)
            m = _FIG_RE.match(joined)
            if m:
                flush_para()
                out.extend(_figure_flowables(
                    m.group("alt"),
                    (paper_dir / m.group("path")).resolve(),
                    s,
                ))
            i += 1
            continue

        # Single-line image block.
        m_img = _FIG_RE.match(line.strip())
        if m_img:
            flush_para()
            out.extend(_figure_flowables(
                m_img.group("alt"),
                (paper_dir / m_img.group("path")).resolve(),
                s,
            ))
            i += 1
            continue

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


def _format_authors(authors) -> tuple[str, str]:
    """Return (display_line, affiliation_line). Strips pandoc-style
    `^[Affiliation]` footnote markers but preserves the names."""
    if authors is None:
        return "", ""
    if isinstance(authors, str):
        authors = [authors]
    names = []
    for entry in authors:
        if not isinstance(entry, str):
            continue
        # Strip pandoc caret-footnotes like `^[Department of ...]`.
        name = re.sub(r"\s*\^?\[[^\]]*\]", "", entry).strip()
        if name:
            names.append(name)
    display = ", ".join(names)
    affil = (
        "Department of Computer Science, "
        "University of Dayton, USA"
    )
    return display, affil


def main() -> int:
    src = next((p for p in SOURCES if p.exists()), None)
    if src is None:
        print(f"no paper source at {SOURCES[0]} or {SOURCES[1]}",
              file=sys.stderr)
        return 1
    md = src.read_text()
    meta, body = _parse_yaml_frontmatter(md)
    s = _styles()
    paper_dir = src.parent

    doc = SimpleDocTemplate(
        str(OUT), pagesize=LETTER,
        leftMargin=0.85*inch, rightMargin=0.85*inch,
        topMargin=0.7*inch, bottomMargin=0.7*inch,
        title=meta.get("title", "ReasonChain"),
    )
    flow: list = []

    title = meta.get("title", "Paper")
    if isinstance(title, str):
        title = title.replace("\n", " ").strip()
    flow.append(Paragraph(_inline(title), s["title"]))

    authors_line, affil_line = _format_authors(meta.get("author"))
    if authors_line:
        flow.append(Paragraph(_inline(authors_line), s["authors"]))
    flow.append(Paragraph(affil_line, s["affil"]))

    if meta.get("abstract"):
        flow.append(Paragraph("Abstract", s["abstract_label"]))
        abstract_text = str(meta["abstract"]).replace("\n", " ")
        flow.append(Paragraph(_inline(abstract_text), s["abstract"]))

    kw = meta.get("keywords")
    if kw:
        if isinstance(kw, list):
            kw_text = "; ".join(str(k) for k in kw)
        else:
            kw_text = str(kw)
        flow.append(Paragraph(
            f"<b>Keywords:</b> {_inline(kw_text)}", s["keywords"],
        ))

    flow.append(Spacer(1, 0.12 * inch))
    flow.extend(_md_to_flowables(body, s, paper_dir))
    doc.build(flow)
    print(f"Wrote {OUT}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
