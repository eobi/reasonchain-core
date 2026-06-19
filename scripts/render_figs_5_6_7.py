"""Render Figures 5, 6, and 7 for the paper.

Three additional figures per Dr. Arefin's 2026-06-17 feedback. Each
is Figure 1's closed-loop topology instantiated with the actual
content from a specific experimental run:

  Figure 5  Juice Shop, full condition, full Kali pool → finds
            CVE-2024-38476 (Apache mod_rewrite SSRF, CVSS 9.8).
  Figure 6  Same target, no-replan ablation. REPLAN block disabled.
            Chain dies at the seed pair.
  Figure 7  Cross-tool fusion mechanism (P2): nmap → Facts["open_ports"]
            → nmap_vuln scopes its NSE invocation to those ports.

All three are deliberately readable at single-column ICSE width.
Saved to ``notebooks/figures/fig5_full_run.png``,
``notebooks/figures/fig6_no_replan.png``,
``notebooks/figures/fig7_fusion_mechanism.png``.

Source data for every annotation traces to a committed file:
  · paper/deep_scan_juiceshop.json
  · paper/sample_run_juiceshop_full.txt
  · paper/sample_run_juiceshop_noreplan.txt
  · src/reasonchain/planner.py (seed map + chain rules)
"""
from __future__ import annotations

from pathlib import Path

import matplotlib.pyplot as plt
from matplotlib.patches import FancyArrowPatch, FancyBboxPatch


REPO_ROOT = Path(__file__).resolve().parent.parent
FIG_DIR = REPO_ROOT / "notebooks" / "figures"

# Shared palette — matches render_fig1.py so the new figures are
# visually consistent with Figure 1.
COL_INPUT_EDGE = "#1e40af"
COL_INPUT_FACE = "#dbeafe"
COL_NEUTRAL_EDGE = "#0f172a"
COL_NEUTRAL_FACE = "#f1f5f9"
COL_FUSION_EDGE = "#7c2d12"
COL_FUSION_FACE = "#fed7aa"
COL_OUTPUT_EDGE = "#166534"
COL_OUTPUT_FACE = "#bbf7d0"
COL_DISABLED_EDGE = "#94a3b8"
COL_DISABLED_FACE = "#e2e8f0"


def _box(ax, x, y, w, h, label, sub=None, *,
         edge=COL_NEUTRAL_EDGE, face=COL_NEUTRAL_FACE,
         label_size=9.5, sub_size=7, dashed=False,
         label_color=None, sub_color=None):
    style = "round,pad=0.05"
    ax.add_patch(FancyBboxPatch(
        (x, y), w, h, boxstyle=style,
        linewidth=1.2, edgecolor=edge, facecolor=face,
        linestyle="dashed" if dashed else "solid",
    ))
    lc = label_color or edge
    if sub:
        ax.text(x + w/2, y + h*0.66, label,
                ha="center", va="center", fontsize=label_size,
                color=lc, fontweight="bold")
        ax.text(x + w/2, y + h*0.30, sub,
                ha="center", va="center", fontsize=sub_size,
                color=sub_color or "#475569", style="italic")
    else:
        ax.text(x + w/2, y + h/2, label,
                ha="center", va="center", fontsize=label_size,
                color=lc, fontweight="bold")


def _arrow(ax, x1, y1, x2, y2, *,
           color=COL_NEUTRAL_EDGE, style="-|>",
           lw=1.4, curve=0, dashed=False):
    kwargs = dict(arrowstyle=style, mutation_scale=14,
                  color=color, linewidth=lw)
    if dashed:
        kwargs["linestyle"] = "dashed"
    if curve != 0:
        kwargs["connectionstyle"] = f"arc3,rad={curve}"
    ax.add_patch(FancyArrowPatch((x1, y1), (x2, y2), **kwargs))


def _section_title(ax, x, y, text, color="#0f172a"):
    ax.text(x, y, text, ha="left", va="center",
            fontsize=10.5, fontweight="bold", color=color)


# ───────────────────────────────────────────────────────────────────
# Figure 5 — Full closed-loop run finds a real CVE on Juice Shop
# ───────────────────────────────────────────────────────────────────


def render_fig5() -> None:
    fig, ax = plt.subplots(figsize=(11, 11))
    ax.set_xlim(0, 11)
    ax.set_ylim(0, 11)
    ax.axis("off")
    ax.set_aspect("equal")

    ax.text(5.5, 10.65,
            "Figure 5 — Full closed-loop run finds CVE-2024-38476 (CVSS 9.8) "
            "on OWASP Juice Shop",
            ha="center", va="center", fontsize=11,
            fontweight="bold", color="#0f172a")

    # ── Input panel ──
    _box(ax, 0.3, 9.6, 10.4, 0.8,
         "TARGET + TOOLS + CVE INTEL",
         sub="target='http://192.168.1.73:3000/' (web_api)  ·  "
             "engines: http_probe url_crawler header_vuln_check nmap "
             "nmap_vuln nuclei nikto sqlmap dalfox wpscan  ·  "
             "max_steps=25 max_depth=3  ·  "
             "AblationFlags(replanning=True, fusion=True)",
         edge=COL_INPUT_EDGE, face=COL_INPUT_FACE)
    _arrow(ax, 5.5, 9.6, 5.5, 9.25)

    # ── Context assembly ──
    _box(ax, 1.5, 8.5, 8.0, 0.75,
         "CONTEXT ASSEMBLY  (Facts={} at run start)",
         sub="available_engines=[http_probe, url_crawler, ..., nmap_vuln, "
             "nuclei, nikto] passed to planner",
         edge=COL_INPUT_EDGE, face=COL_INPUT_FACE,
         label_size=9, sub_size=7)
    _arrow(ax, 5.5, 8.5, 5.5, 8.2)

    # ── Initial planning ──
    _box(ax, 1.5, 7.45, 8.0, 0.75,
         "PLANNING (HeuristicPlanner.plan_initial)",
         sub="_SEEDS['web_api'] → [http_probe, url_crawler]  →  "
             "2 picks at depth 0",
         edge=COL_NEUTRAL_EDGE, face=COL_NEUTRAL_FACE,
         label_size=9, sub_size=7)

    # ── Closed loop container ──
    ax.add_patch(FancyBboxPatch(
        (0.25, 2.4), 10.5, 4.85, boxstyle="round,pad=0.05",
        linewidth=1.4, edgecolor=COL_FUSION_EDGE,
        facecolor="#fff7ed", linestyle="solid", alpha=0.35,
    ))
    ax.text(5.5, 7.05, "CLOSED LOOP  (P1)",
            ha="center", va="center", fontsize=10,
            color=COL_FUSION_EDGE, fontweight="bold")
    _arrow(ax, 5.5, 7.45, 5.5, 7.15, color=COL_FUSION_EDGE)

    # Iteration rows: y from 6.65 (top) down to 2.7 (bottom of last)
    # Each row: EXECUTE → PARSE → KG UPDATE  + REPLAN annotation
    iter_specs = [
        # (y_top, label, exec, parse, kg, replan)
        (6.55,
         "iter 1: http_probe",
         "urllib GET\nhttp://...:3000/",
         "200 OK · Server: nginx/1.18.0\nX-Powered-By: Express",
         "+ {server_header, x_powered_by}",
         "_CHAINS[http_probe] → [nmap, header_vuln_check, nikto]"),
        (5.40,
         "iter 2: nmap (over SSH→Kali)",
         "ssh kali 'nmap -sV -p- 192.168.1.73'",
         "10 open ports:  80, 443, 3000, 5000, 8080,\n"
         "8089, 8090, 8091, 8093, 8094",
         "+ {open_ports: [80,443,3000,5000,8080,\n"
         "  8089,8090,8091,8093,8094]}",
         "_CHAINS[nmap] → [nmap_vuln, nuclei]"),
        (4.25,
         "iter 3: nmap_vuln  (★ fact-coupled)",
         "ssh kali 'nmap --script vuln\n"
         "-p {facts[open_ports]} 192.168.1.73'",
         "317 findings · port 8089 → CVE-2024-38476 (9.8)\n"
         "  CVE-2024-38474 (9.8) · CVE-2023-25690 (9.8)",
         "+ {vulnerable_ports: [8089,8090,8091],\n"
         "  cve_matches: [CVE-2024-38476, ...]}",
         "_CHAINS[nmap_vuln] → []  (terminal)"),
    ]

    for y_top, label, ex, pa, kg, rp in iter_specs:
        # Iteration label band
        ax.text(0.6, y_top + 0.4, label,
                ha="left", va="center", fontsize=8.5,
                color="#7c2d12", fontweight="bold")
        # Three execution blocks
        _box(ax, 0.55, y_top - 0.55, 2.85, 0.85,
             "EXECUTE", sub=ex,
             edge=COL_NEUTRAL_EDGE, face=COL_NEUTRAL_FACE,
             label_size=8, sub_size=6.5)
        _box(ax, 3.65, y_top - 0.55, 3.6, 0.85,
             "PARSE → findings", sub=pa,
             edge=COL_NEUTRAL_EDGE, face=COL_NEUTRAL_FACE,
             label_size=8, sub_size=6.5)
        _box(ax, 7.45, y_top - 0.55, 3.2, 0.85,
             "KG UPDATE (Facts.merge)", sub=kg,
             edge=COL_FUSION_EDGE, face=COL_FUSION_FACE,
             label_size=8, sub_size=6.5)
        _arrow(ax, 3.4, y_top - 0.13, 3.65, y_top - 0.13,
               color=COL_NEUTRAL_EDGE, lw=1.0)
        _arrow(ax, 7.25, y_top - 0.13, 7.45, y_top - 0.13,
               color=COL_NEUTRAL_EDGE, lw=1.0)

        # Replan annotation (right of KG update, leftward arrow loops back)
        ax.text(5.5, y_top - 0.85, "REPLAN: " + rp,
                ha="center", va="center", fontsize=7.5,
                color="#475569", style="italic",
                bbox=dict(boxstyle="round,pad=0.25",
                          facecolor="#fefce8",
                          edgecolor="#facc15", linewidth=0.8))

    # Highlight the fusion arrow on iter 3 (KG bag → cmd_builder)
    _arrow(ax, 8.05, 4.85, 5.5, 4.55, color=COL_FUSION_EDGE,
           lw=1.6, curve=-0.3, style="-|>")
    ax.text(7.7, 4.95,
            "★ facts['open_ports'] read by\ncmd_builder at invocation time",
            ha="center", va="center", fontsize=7,
            color=COL_FUSION_EDGE, fontweight="bold")

    # ── Output panel ──
    _arrow(ax, 5.5, 2.4, 5.5, 2.1, color=COL_OUTPUT_EDGE)
    _box(ax, 0.3, 1.0, 10.4, 1.05,
         "OUTPUT — AssessmentResult",
         sub=("findings=336 (314 high, 18 medium, 4 info)  ·  "
              "engines_used=[http_probe, url_crawler, header_vuln_check, "
              "nmap, nmap_vuln, nuclei, nikto]\n"
              "duration_s=476.3  ·  "
              "CVE class hits: CVE-2024-38476, CVE-2024-38474, "
              "CVE-2023-25690 (all CVSS 9.8) + CVE-2022-31813 (CVSS 6.5)\n"
              "→ reports/juiceshop_deep.pdf  +  "
              "paper/deep_scan_juiceshop.json"),
         edge=COL_OUTPUT_EDGE, face=COL_OUTPUT_FACE,
         label_size=9.5, sub_size=7.5)

    # Footer legend
    ax.text(5.5, 0.55,
            ("Closed loop iterates 3 times before nmap_vuln_terminates. "
             "Without the REPLAN after nmap (iter 2), nmap_vuln never "
             "fires → CVE-2024-38476 never discovered. (See Fig 6 for "
             "the no-replan counterfactual.)"),
            ha="center", va="center", fontsize=7.5,
            color="#475569", style="italic",
            bbox=dict(boxstyle="round,pad=0.4",
                     facecolor="#fafafa",
                     edgecolor="#cbd5e1", linewidth=0.6))

    FIG_DIR.mkdir(parents=True, exist_ok=True)
    out = FIG_DIR / "fig5_full_run.png"
    fig.savefig(out, dpi=160, bbox_inches="tight")
    plt.close(fig)
    print(f"Wrote {out}")


# ───────────────────────────────────────────────────────────────────
# Figure 6 — No-replan ablation: chain dies at the seed pair
# ───────────────────────────────────────────────────────────────────


def render_fig6() -> None:
    fig, ax = plt.subplots(figsize=(11, 7))
    ax.set_xlim(0, 11)
    ax.set_ylim(0, 7)
    ax.axis("off")
    ax.set_aspect("equal")

    ax.text(5.5, 6.65,
            "Figure 6 — Same target, no-replan ablation (P1 disabled): "
            "chain dies at the seed pair",
            ha="center", va="center", fontsize=11,
            fontweight="bold", color="#0f172a")

    # Input panel (note the ablation flag highlighted)
    _box(ax, 0.3, 5.6, 10.4, 0.8,
         "TARGET + TOOLS + CVE INTEL  (identical to Fig 5)",
         sub="same target, same 10-engine pool, same caps  ·  "
             "AblationFlags(replanning=★False★, fusion=True)",
         edge=COL_INPUT_EDGE, face=COL_INPUT_FACE)
    _arrow(ax, 5.5, 5.6, 5.5, 5.25)

    _box(ax, 1.5, 4.45, 8.0, 0.75,
         "PLANNING (HeuristicPlanner.plan_initial)",
         sub="_SEEDS['web_api'] → [http_probe, url_crawler]  →  "
             "2 picks at depth 0  (same as Fig 5)",
         edge=COL_NEUTRAL_EDGE, face=COL_NEUTRAL_FACE,
         label_size=9, sub_size=7)
    _arrow(ax, 5.5, 4.45, 5.5, 4.15)

    # Closed loop container (smaller — only 2 iterations)
    ax.add_patch(FancyBboxPatch(
        (0.25, 2.0), 10.5, 2.1, boxstyle="round,pad=0.05",
        linewidth=1.4, edgecolor=COL_FUSION_EDGE,
        facecolor="#fff7ed", linestyle="solid", alpha=0.35,
    ))
    ax.text(5.5, 3.95, "CLOSED LOOP  (REPLAN DISABLED)",
            ha="center", va="center", fontsize=10,
            color=COL_FUSION_EDGE, fontweight="bold")

    # Iter 1
    _box(ax, 0.55, 2.95, 2.85, 0.7,
         "EXECUTE: http_probe",
         sub="urllib GET http://...:3000/",
         edge=COL_NEUTRAL_EDGE, face=COL_NEUTRAL_FACE,
         label_size=8, sub_size=6.5)
    _box(ax, 3.65, 2.95, 3.0, 0.7,
         "PARSE",
         sub="200 OK · nginx/1.18.0",
         edge=COL_NEUTRAL_EDGE, face=COL_NEUTRAL_FACE,
         label_size=8, sub_size=6.5)
    _box(ax, 6.9, 2.95, 2.5, 0.7,
         "KG UPDATE",
         sub="+ {server_header, ...}",
         edge=COL_FUSION_EDGE, face=COL_FUSION_FACE,
         label_size=8, sub_size=6.5)
    _box(ax, 9.65, 2.95, 1.05, 0.7,
         "REPLAN",
         sub="✗ DISABLED",
         edge=COL_DISABLED_EDGE, face=COL_DISABLED_FACE,
         label_size=8, sub_size=6.5, dashed=True,
         label_color="#64748b", sub_color="#94a3b8")
    _arrow(ax, 3.4, 3.30, 3.65, 3.30, color=COL_NEUTRAL_EDGE, lw=1.0)
    _arrow(ax, 6.65, 3.30, 6.9, 3.30, color=COL_NEUTRAL_EDGE, lw=1.0)
    _arrow(ax, 9.4, 3.30, 9.65, 3.30, color=COL_DISABLED_EDGE, lw=1.0,
           dashed=True)

    # Iter 2
    _box(ax, 0.55, 2.15, 2.85, 0.7,
         "EXECUTE: url_crawler",
         sub="anchor extraction, BFS depth-1",
         edge=COL_NEUTRAL_EDGE, face=COL_NEUTRAL_FACE,
         label_size=8, sub_size=6.5)
    _box(ax, 3.65, 2.15, 3.0, 0.7,
         "PARSE",
         sub="12 URLs surfaced",
         edge=COL_NEUTRAL_EDGE, face=COL_NEUTRAL_FACE,
         label_size=8, sub_size=6.5)
    _box(ax, 6.9, 2.15, 2.5, 0.7,
         "KG UPDATE",
         sub="+ {discovered_urls}",
         edge=COL_FUSION_EDGE, face=COL_FUSION_FACE,
         label_size=8, sub_size=6.5)
    _box(ax, 9.65, 2.15, 1.05, 0.7,
         "REPLAN",
         sub="✗ DISABLED",
         edge=COL_DISABLED_EDGE, face=COL_DISABLED_FACE,
         label_size=8, sub_size=6.5, dashed=True,
         label_color="#64748b", sub_color="#94a3b8")
    _arrow(ax, 3.4, 2.50, 3.65, 2.50, color=COL_NEUTRAL_EDGE, lw=1.0)
    _arrow(ax, 6.65, 2.50, 6.9, 2.50, color=COL_NEUTRAL_EDGE, lw=1.0)
    _arrow(ax, 9.4, 2.50, 9.65, 2.50, color=COL_DISABLED_EDGE, lw=1.0,
           dashed=True)

    # Output panel — empty/sparse
    _arrow(ax, 5.5, 2.0, 5.5, 1.75, color=COL_OUTPUT_EDGE)
    _box(ax, 0.3, 0.6, 10.4, 1.15,
         "OUTPUT — AssessmentResult",
         sub=("findings=2 (0 high, 0 medium, 2 info)  ·  "
              "engines_used=[http_probe, url_crawler] (2/7 unreached: "
              "nmap, nmap_vuln, nuclei, nikto, header_vuln_check)\n"
              "duration_s=0.016  ·  CVE class hits: ✗ none\n"
              "★ The 314 high-severity findings from Fig 5 — including "
              "CVE-2024-38476 — are unreachable from this configuration."),
         edge=COL_OUTPUT_EDGE, face=COL_OUTPUT_FACE,
         label_size=9.5, sub_size=7.5)

    FIG_DIR.mkdir(parents=True, exist_ok=True)
    out = FIG_DIR / "fig6_no_replan.png"
    fig.savefig(out, dpi=160, bbox_inches="tight")
    plt.close(fig)
    print(f"Wrote {out}")


# ───────────────────────────────────────────────────────────────────
# Figure 7 — Cross-tool fusion mechanism
# ───────────────────────────────────────────────────────────────────


def render_fig7() -> None:
    fig, ax = plt.subplots(figsize=(11, 8.5))
    ax.set_xlim(0, 11)
    ax.set_ylim(0, 8.5)
    ax.axis("off")
    ax.set_aspect("equal")

    ax.text(5.5, 8.15,
            "Figure 7 — Cross-tool fusion (P2): Facts['open_ports'] activates "
            "nmap_vuln on the right ports",
            ha="center", va="center", fontsize=11,
            fontweight="bold", color="#0f172a")

    # Block A — nmap completes (top)
    _box(ax, 1.0, 7.05, 9.0, 0.85,
         "Block A — nmap completes",
         sub="EXECUTE: ssh kali 'nmap -sV -p- 192.168.1.73 -oX -'  ·  "
             "PARSE: 10 open ports (80, 443, 3000, 5000, 8080, "
             "8089, 8090, 8091, 8093, 8094) · 6 tech versions",
         edge=COL_NEUTRAL_EDGE, face=COL_NEUTRAL_FACE,
         label_size=9.5, sub_size=7.5)
    _arrow(ax, 5.5, 7.05, 5.5, 6.65, color=COL_FUSION_EDGE, lw=1.6)

    # Block B — KG update (Facts bag, the substrate)
    _box(ax, 1.5, 5.45, 8.0, 1.20,
         "Block B — KG UPDATE  (Facts.merge)",
         sub=("Before: {server_header, content_type, x_powered_by}\n"
              "After:  + {open_ports: [80, 443, 3000, 5000, 8080, "
              "8089, 8090, 8091, 8093, 8094],\n"
              "          tech_versions: [nginx/1.18.0, Express, "
              "Apache httpd 2.4.7 (Ubuntu), ...]}"),
         edge=COL_FUSION_EDGE, face=COL_FUSION_FACE,
         label_size=10, sub_size=8)

    # Two parallel arrows down to Block C (full path = solid, no-fusion = dashed)
    _arrow(ax, 3.5, 5.45, 3.0, 4.7, color=COL_FUSION_EDGE, lw=1.6)
    _arrow(ax, 7.5, 5.45, 8.0, 4.7, color=COL_DISABLED_EDGE, lw=1.4,
           dashed=True)
    ax.text(2.5, 5.05, "Full path", ha="center", va="center",
            fontsize=8.5, color=COL_FUSION_EDGE, fontweight="bold")
    ax.text(8.5, 5.05, "no-fusion path\n(ablation, dashed)",
            ha="center", va="center", fontsize=8.5,
            color=COL_DISABLED_EDGE, fontweight="bold", style="italic")

    # Block C left — FULL path
    _box(ax, 0.3, 2.7, 5.0, 2.0,
         "FULL — nmap_vuln  (fact-coupled)",
         sub=("cmd_builder reads facts['open_ports']:\n"
              "  ports = '80,443,3000,5000,8080,\n"
              "           8089,8090,8091,8093,8094'\n"
              "command:\n"
              "  ssh kali 'nmap --script vuln \\\n"
              "    -p {ports} 192.168.1.73 -oX -'\n"
              "→ 317 findings  ·  CVE-2024-38476 (9.8)\n"
              "  CVE-2024-38474 (9.8) · CVE-2023-25690 (9.8)"),
         edge=COL_FUSION_EDGE, face=COL_FUSION_FACE,
         label_size=9.5, sub_size=7.5)

    # Block C right — NO-FUSION path
    _box(ax, 5.7, 2.7, 5.0, 2.0,
         "no-fusion — nmap_vuln receives empty facts",
         sub=("facts = {}  →  cmd_builder falls back:\n"
              "  ports = '80,443'  (default)\n\n"
              "command:\n"
              "  ssh kali 'nmap --script vuln \\\n"
              "    -p 80,443 192.168.1.73 -oX -'\n\n"
              "→ 2 findings  ·  high CVSS: —\n"
              "  Apache instances on 8089/8090/8091 invisible"),
         edge=COL_DISABLED_EDGE, face=COL_DISABLED_FACE,
         label_size=9.5, sub_size=7.5, dashed=True,
         label_color="#64748b", sub_color="#475569")

    # Outcome row — bottom contrast
    _arrow(ax, 2.8, 2.7, 2.8, 2.0, color=COL_OUTPUT_EDGE)
    _arrow(ax, 8.2, 2.7, 8.2, 2.0, color=COL_DISABLED_EDGE, dashed=True)

    _box(ax, 0.3, 0.7, 5.0, 1.3,
         "OUTCOME  ·  nmap_vuln findings: 317",
         sub=("Highest CVSS: 9.8 ×3 (Apache CVE chain)\n"
              "New CVEs surfaced:\n"
              "  · CVE-2024-38476 (mod_rewrite SSRF)\n"
              "  · CVE-2024-38474\n"
              "  · CVE-2023-25690 (HTTP smuggling)"),
         edge=COL_OUTPUT_EDGE, face=COL_OUTPUT_FACE,
         label_size=9, sub_size=7.5)

    _box(ax, 5.7, 0.7, 5.0, 1.3,
         "OUTCOME  ·  nmap_vuln findings: 2",
         sub=("Highest CVSS: —  (no high-severity)\n"
              "New CVEs: ✗ none\n"
              "Apache instances on 8089/8090/8091 not\n"
              "scanned (fact bag was empty)"),
         edge=COL_DISABLED_EDGE, face=COL_DISABLED_FACE,
         label_size=9, sub_size=7.5, dashed=True,
         label_color="#64748b", sub_color="#475569")

    FIG_DIR.mkdir(parents=True, exist_ok=True)
    out = FIG_DIR / "fig7_fusion_mechanism.png"
    fig.savefig(out, dpi=160, bbox_inches="tight")
    plt.close(fig)
    print(f"Wrote {out}")


def main() -> int:
    render_fig5()
    render_fig6()
    render_fig7()
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(main())
