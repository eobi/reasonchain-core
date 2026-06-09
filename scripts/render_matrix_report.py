"""Render a PDF + JSON summary of the H1/H2/H3 matrix in
``data/results.csv``.

Output mirrors the per-run report's structure:
  - Executive summary (total cells, targets, conditions, runtime)
  - Per-target × per-condition table (mean findings)
  - Per-condition severity rollup
  - H1 + H2 + H3 statistical tests (paired t, Wilcoxon)

The JSON is the same data the notebook reads; the PDF is the
human-readable artifact you'd attach to a paper submission.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "src"))

import pandas as pd  # noqa: E402
from scipy import stats  # noqa: E402
from reportlab.lib import colors  # noqa: E402
from reportlab.lib.pagesizes import LETTER  # noqa: E402
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet  # noqa: E402
from reportlab.lib.units import inch  # noqa: E402
from reportlab.platypus import (  # noqa: E402
    Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle,
)


def _styles() -> dict:
    base = getSampleStyleSheet()
    return {
        "title": ParagraphStyle(
            "title", parent=base["Title"], fontSize=20, spaceAfter=4,
            textColor=colors.HexColor("#0f172a"),
        ),
        "subtitle": ParagraphStyle(
            "subtitle", parent=base["Normal"], fontSize=10,
            textColor=colors.HexColor("#475569"), spaceAfter=14,
        ),
        "h2": ParagraphStyle(
            "h2", parent=base["Heading2"], fontSize=13,
            textColor=colors.HexColor("#0f172a"),
            spaceBefore=10, spaceAfter=6,
        ),
        "body": ParagraphStyle(
            "body", parent=base["Normal"], fontSize=9, leading=12,
        ),
        "muted": ParagraphStyle(
            "muted", parent=base["Normal"], fontSize=8,
            textColor=colors.HexColor("#64748b"),
        ),
    }


def _hdr_tbl(rows: list, col_widths=None) -> Table:
    t = Table(rows, colWidths=col_widths, hAlign="LEFT")
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f172a")),
        ("TEXTCOLOR",  (0, 0), (-1, 0), colors.white),
        ("FONTNAME",   (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE",   (0, 0), (-1, -1), 9),
        ("GRID",       (0, 0), (-1, -1), 0.25, colors.HexColor("#cbd5e1")),
        ("LEFTPADDING",(0, 0), (-1, -1), 4),
        ("RIGHTPADDING",(0, 0), (-1, -1), 4),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING",(0, 0), (-1, -1), 3),
        ("VALIGN",     (0, 0), (-1, -1), "TOP"),
    ]))
    return t


def _kv_tbl(rows: list) -> Table:
    t = Table(rows, colWidths=[2.0*inch, 5.2*inch])
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


def build_report(csv_path: Path, out_stem: Path) -> dict[str, Path]:
    df = pd.read_csv(csv_path)
    agg = df.groupby(["target", "condition"], as_index=False).agg({
        "findings_count": "mean", "engine_count": "mean",
        "duration_s": "mean", "replans": "mean",
        "decisions_correct": "sum", "decisions_suboptimal": "sum",
        "decisions_incorrect": "sum",
    })
    pivot = agg.pivot(index="target", columns="condition",
                      values="findings_count").dropna()

    # H1 stats
    h1f, h1n = pivot["full"], pivot["no-replan"]
    t1, p1 = stats.ttest_rel(h1f, h1n, alternative="greater")
    w1, pw1 = stats.wilcoxon(h1f, h1n, alternative="greater")
    no_outlier = pivot.copy()
    if "dvwa_live" in no_outlier.index:
        no_outlier = no_outlier.drop("dvwa_live")
    h1fn, h1nn = no_outlier["full"], no_outlier["no-replan"]
    t1n, p1n = stats.ttest_rel(h1fn, h1nn, alternative="greater")
    d1n = ((h1fn - h1nn).mean()
           / max((h1fn - h1nn).std(ddof=1), 1e-9))

    # H2 stats
    h2f, h2no = pivot["full"], pivot["no-fusion"]
    t2, p2 = stats.ttest_rel(h2f, h2no, alternative="greater")
    w2, pw2 = stats.wilcoxon(h2f, h2no, alternative="greater")

    # JSON dump first
    summary_obj = {
        "source_csv": str(csv_path),
        "n_cells": int(len(df)),
        "n_targets": int(len(pivot)),
        "conditions": sorted(df["condition"].unique().tolist()),
        "per_target_findings": pivot.round(2).to_dict(),
        "h1": {
            "paired_t":    {"t": float(t1), "p": float(p1)},
            "wilcoxon":    {"W": float(w1), "p": float(pw1)},
            "paired_t_no_outlier": {
                "t": float(t1n), "p": float(p1n), "cohens_d": float(d1n),
            },
            "mean_full":      float(h1f.mean()),
            "mean_no_replan": float(h1n.mean()),
        },
        "h2": {
            "paired_t":  {"t": float(t2), "p": float(p2)},
            "wilcoxon":  {"W": float(w2), "p": float(pw2)},
            "mean_full":     float(h2f.mean()),
            "mean_no_fusion": float(h2no.mean()),
        },
        "h3": {
            "by_condition": agg.groupby("condition").sum(
                numeric_only=True).round(2).to_dict(),
        },
    }
    json_path = out_stem.with_suffix(".json")
    json_path.parent.mkdir(parents=True, exist_ok=True)
    json_path.write_text(json.dumps(summary_obj, indent=2, default=str))

    # PDF
    pdf_path = out_stem.with_suffix(".pdf")
    s = _styles()
    doc = SimpleDocTemplate(
        str(pdf_path), pagesize=LETTER,
        leftMargin=0.6*inch, rightMargin=0.6*inch,
        topMargin=0.7*inch, bottomMargin=0.7*inch,
    )
    flow: list = []

    flow.append(Paragraph("H1 / H2 / H3 Matrix Report", s["title"]))
    flow.append(Paragraph(
        f"Source: {csv_path.name} · cells: {len(df)} · "
        f"targets: {len(pivot)} · "
        f"conditions: {', '.join(sorted(df['condition'].unique()))}",
        s["subtitle"],
    ))

    # Executive summary
    flow.append(Paragraph("Executive Summary", s["h2"]))
    flow.append(_kv_tbl([
        ["Total cells", str(len(df))],
        ["Distinct targets", str(len(pivot))],
        ["Mean duration / cell",
         f"{df['duration_s'].mean():.1f}s"],
        ["Total findings across cells",
         str(int(df['findings_count'].sum()))],
        ["Engine pool example",
         df.iloc[-1].get('engines_used', '(unknown)')[:200]],
    ]))
    flow.append(Spacer(1, 0.15*inch))

    # Per-target table
    flow.append(Paragraph("Findings per (target × condition)", s["h2"]))
    header = ["Target"] + list(pivot.columns)
    rows = [header] + [
        [t] + [f"{v:.1f}" for v in pivot.loc[t].values]
        for t in pivot.index
    ]
    flow.append(_hdr_tbl(rows))
    flow.append(Spacer(1, 0.15*inch))

    # H1
    flow.append(Paragraph("H1 — Closed-loop replanning improves coverage",
                          s["h2"]))
    flow.append(_kv_tbl([
        ["mean(full)",     f"{h1f.mean():.1f}"],
        ["mean(no-replan)", f"{h1n.mean():.1f}"],
        ["paired t (all)", f"t={t1:.3f}, p={p1:.4f}"],
        ["Wilcoxon (all)", f"W={w1:.1f}, p={pw1:.6f}"],
        ["paired t (no DVWA)",
         f"t={t1n:.3f}, p={p1n:.6f}, Cohen d={d1n:.3f}"],
        ["mean lift (no DVWA)",
         f"{(h1fn.mean() / max(h1nn.mean(), 1) - 1) * 100:+.0f}%"],
    ]))
    flow.append(Spacer(1, 0.15*inch))

    # H2
    flow.append(Paragraph("H2 — Cross-tool fusion", s["h2"]))
    flow.append(_kv_tbl([
        ["mean(full)",     f"{h2f.mean():.1f}"],
        ["mean(no-fusion)", f"{h2no.mean():.1f}"],
        ["paired t",       f"t={t2:.3f}, p={p2:.4f}"],
        ["Wilcoxon",       f"W={w2:.1f}, p={pw2:.6f}"],
    ]))
    flow.append(Spacer(1, 0.15*inch))

    # H3
    flow.append(Paragraph("H3 — Decision-quality stratification",
                          s["h2"]))
    h3 = (agg.groupby("condition")[
        ["decisions_correct", "decisions_suboptimal", "decisions_incorrect"]
    ].sum())
    h3["total"] = h3.sum(axis=1)
    h3["pct_incorrect"] = (h3["decisions_incorrect"]
                           / h3["total"].replace(0, 1) * 100)
    rows = [["Condition", "Correct", "Suboptimal", "Incorrect",
             "Total", "% incorrect"]]
    for cond, row in h3.iterrows():
        rows.append([
            cond,
            f"{int(row.decisions_correct)}",
            f"{int(row.decisions_suboptimal)}",
            f"{int(row.decisions_incorrect)}",
            f"{int(row.total)}",
            f"{row.pct_incorrect:.1f}%",
        ])
    flow.append(_hdr_tbl(rows))

    doc.build(flow)
    return {"pdf": pdf_path, "json": json_path}


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    p.add_argument("--csv",
                   default=str(REPO_ROOT / "data" / "results.csv"))
    p.add_argument("--out-stem",
                   default=str(REPO_ROOT / "reports" / "matrix_report"))
    args = p.parse_args(argv)

    paths = build_report(Path(args.csv), Path(args.out_stem))
    print(f"PDF:  {paths['pdf']}")
    print(f"JSON: {paths['json']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
