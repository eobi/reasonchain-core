"""Render Figure 1 — the ReasonChain closed-loop architecture diagram.

Saves to ``notebooks/figures/fig1_closed_loop.png`` for inclusion
in the paper.
"""
from pathlib import Path

import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch
from matplotlib.path import Path as MplPath
from matplotlib.patches import PathPatch


REPO_ROOT = Path(__file__).resolve().parent.parent
OUT = REPO_ROOT / "notebooks" / "figures" / "fig1_closed_loop.png"


def _box(ax, x, y, w, h, label, sub=None, color="#0f172a",
         face="#e2e8f0"):
    ax.add_patch(FancyBboxPatch(
        (x, y), w, h, boxstyle="round,pad=0.05",
        linewidth=1.2, edgecolor=color, facecolor=face,
    ))
    ax.text(x + w/2, y + h*0.62, label,
            ha="center", va="center", fontsize=10,
            color=color, fontweight="bold")
    if sub:
        ax.text(x + w/2, y + h*0.28, sub,
                ha="center", va="center", fontsize=7.5,
                color="#475569", style="italic")


def _arrow(ax, x1, y1, x2, y2, color="#0f172a",
           style="-|>", lw=1.4, curve=0):
    if curve == 0:
        ax.add_patch(FancyArrowPatch(
            (x1, y1), (x2, y2), arrowstyle=style,
            mutation_scale=14, color=color, linewidth=lw,
        ))
    else:
        ax.add_patch(FancyArrowPatch(
            (x1, y1), (x2, y2), arrowstyle=style,
            mutation_scale=14, color=color, linewidth=lw,
            connectionstyle=f"arc3,rad={curve}",
        ))


def main() -> int:
    fig, ax = plt.subplots(figsize=(10, 5.5))
    ax.set_xlim(0, 11.5)
    ax.set_ylim(0, 6.2)
    ax.axis("off")
    ax.set_aspect("equal")

    # Title
    ax.text(5.75, 5.95, "ReasonChain: Closed-Loop Architecture",
            ha="center", va="center", fontsize=12,
            fontweight="bold", color="#0f172a")

    # Inputs
    _box(ax, 0.2, 4.5, 2.4, 0.85,
         "TARGET + TOOLS", sub="+ CVE / ExploitDB intel",
         color="#1e40af", face="#dbeafe")
    _box(ax, 0.2, 3.3, 2.4, 0.85,
         "PLANNER", sub="Heuristic / LLM",
         color="#1e40af", face="#dbeafe")

    # Closed-loop boxes (top row)
    _box(ax, 3.6, 4.5, 2.0, 0.85,
         "Pick Next",
         sub="(target, engine, args)",
         color="#0f172a", face="#f1f5f9")
    _box(ax, 6.2, 4.5, 2.0, 0.85,
         "Dispatch", sub="local or SSH→Kali",
         color="#0f172a", face="#f1f5f9")
    _box(ax, 8.8, 4.5, 2.4, 0.85,
         "Engine", sub="nmap · nuclei · nikto · ...",
         color="#0f172a", face="#f1f5f9")

    # bottom row
    _box(ax, 8.8, 2.85, 2.4, 0.85,
         "Parse Output", sub="findings + facts",
         color="#0f172a", face="#f1f5f9")
    _box(ax, 6.2, 2.85, 2.0, 0.85,
         "Knowledge Graph",
         sub='Facts() bag (shared)',
         color="#7c2d12", face="#fed7aa")
    _box(ax, 3.6, 2.85, 2.0, 0.85,
         "Replan?", sub="closed-loop hook",
         color="#0f172a", face="#f1f5f9")

    # Output box (bottom-left, exits the loop)
    _box(ax, 0.2, 1.2, 3.4, 0.85,
         "Findings + Decision Trace",
         sub="severity · CVEs · evidence · per-pick labels",
         color="#166534", face="#bbf7d0")

    # Decision annotator (H3)
    _box(ax, 4.5, 1.2, 3.0, 0.85,
         "H3 Annotator", sub="correct / suboptimal / incorrect",
         color="#7c2d12", face="#fed7aa")

    # Report renderer
    _box(ax, 8.0, 1.2, 3.2, 0.85,
         "Report", sub="PDF + JSON",
         color="#166534", face="#bbf7d0")

    # Inputs → planner
    _arrow(ax, 1.4, 4.5, 1.4, 4.15)

    # Planner → Pick Next
    _arrow(ax, 2.6, 3.72, 3.6, 4.6)

    # Closed loop arrows (top row)
    _arrow(ax, 5.6, 4.92, 6.2, 4.92)
    _arrow(ax, 8.2, 4.92, 8.8, 4.92)
    _arrow(ax, 10.0, 4.5, 10.0, 3.7)
    _arrow(ax, 8.8, 3.27, 8.2, 3.27)
    _arrow(ax, 6.2, 3.27, 5.6, 3.27)

    # Replan loop back to Pick Next
    _arrow(ax, 4.6, 3.7, 4.6, 4.5)

    # Knowledge graph back-edges (fusion)
    _arrow(ax, 7.2, 3.7, 7.2, 4.5, color="#7c2d12", lw=1.0)

    # Termination → outputs
    _arrow(ax, 4.6, 2.85, 3.0, 2.05, color="#166534")
    _arrow(ax, 3.6, 1.62, 4.5, 1.62, color="#7c2d12")
    _arrow(ax, 7.5, 1.62, 8.0, 1.62, color="#166534")

    # Legend
    ax.text(5.75, 0.55,
            ("Closed loop (P1) = the right rectangle; "
             "Cross-tool fusion (P2) = orange Knowledge Graph; "
             "Target-aware (P3) lives in the Planner's seed map."),
            ha="center", va="center", fontsize=8,
            color="#475569", style="italic",
            bbox=dict(boxstyle="round,pad=0.4",
                     facecolor="#fafafa",
                     edgecolor="#cbd5e1", linewidth=0.6))

    OUT.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(OUT, dpi=160, bbox_inches="tight")
    print(f"Wrote {OUT}")
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(main())
