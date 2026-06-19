"""Render Figures 5, 6, and 7 for the paper.

Three additional figures per Dr. Arefin's 2026-06-17 feedback. Each
figure is Figure 1's closed-loop topology instantiated with the
actual content from one specific experimental run; the three runs
span three different targets to demonstrate the architecture
operates across distinct application stacks and surface sizes:

  Figure 5  OWASP Juice Shop, full condition, Kali pool.
            Closed loop iterates three times. Fact-coupled nmap_vuln
            reads Facts["open_ports"] and surfaces CVE-2024-38476
            (Apache mod_rewrite SSRF, CVSS 9.8) on the embedded
            Apache 2.4.7 instance sibling container.

  Figure 6  Damn Vulnerable Web App (DVWA), full condition.
            The same closed loop produces 2347 findings (the
            outlier of the matrix). nikto's content discovery against
            DVWA's teaching-app endpoint surface contributes 2012
            of these; nmap_vuln supplies 314 of severity high.

  Figure 7  VAMPI (Vulnerable API), full condition. A smaller
            attack surface than the web apps — VAMPI exposes only
            the API endpoints. Same engine pool produces 133 findings
            with nmap_vuln dominating (102) and nikto reduced to
            12 (the API surface offers fewer paths to enumerate).

The three figures together cover three operating regimes:
showcase CVE discovery (Fig 5), scale on teaching-app surfaces
(Fig 6), and precision on a thinner API target (Fig 7). Source
data for every annotation traces to a committed file:

  · paper/deep_scan_juiceshop.json
  · reports/dvwa_live_full_heuristic_kali-fast_seed0_*.json
  · reports/vampi_full_heuristic_kali-fast_seed0_*.json
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

    # Iteration rows. Spacing tuned so iter labels sit fully above the
    # EXECUTE box top and the box bottom sits clearly above the next
    # iter's label. REPLAN content moved to the caption (was an
    # in-figure annotation, but the yellow tooltip crowded the next
    # iter's label band).
    iter_specs = [
        # (y_top, label, exec, parse, kg)
        (6.20,
         "iter 1: http_probe",
         "urllib GET\nhttp://...:3000/",
         "200 OK · Server: nginx/1.18.0\nX-Powered-By: Express",
         "+ {server_header, x_powered_by}"),
        (4.85,
         "iter 2: nmap (over SSH→Kali)",
         "ssh kali 'nmap -sV -p- 192.168.1.73'",
         "10 open ports:  80, 443, 3000, 5000, 8080,\n"
         "8089, 8090, 8091, 8093, 8094",
         "+ {open_ports: [80,443,3000,5000,8080,\n"
         "  8089,8090,8091,8093,8094]}"),
        (3.50,
         "iter 3: nmap_vuln  (★ fact-coupled)",
         "ssh kali 'nmap --script vuln\n"
         "-p {facts[open_ports]} 192.168.1.73'",
         "317 findings · port 8089 → CVE-2024-38476 (9.8)\n"
         "  CVE-2024-38474 (9.8) · CVE-2023-25690 (9.8)",
         "+ {vulnerable_ports: [8089,8090,8091],\n"
         "  cve_matches: [CVE-2024-38476, ...]}"),
    ]

    for y_top, label, ex, pa, kg in iter_specs:
        # Iteration label (well above the box top to avoid edge overlap)
        ax.text(0.6, y_top + 0.55, label,
                ha="left", va="center", fontsize=8.5,
                color="#7c2d12", fontweight="bold")
        # Three execution blocks
        _box(ax, 0.55, y_top - 0.55, 2.85, 0.95,
             "EXECUTE", sub=ex,
             edge=COL_NEUTRAL_EDGE, face=COL_NEUTRAL_FACE,
             label_size=8, sub_size=6.5)
        _box(ax, 3.65, y_top - 0.55, 3.6, 0.95,
             "PARSE → findings", sub=pa,
             edge=COL_NEUTRAL_EDGE, face=COL_NEUTRAL_FACE,
             label_size=8, sub_size=6.5)
        _box(ax, 7.45, y_top - 0.55, 3.2, 0.95,
             "KG UPDATE (Facts.merge)", sub=kg,
             edge=COL_FUSION_EDGE, face=COL_FUSION_FACE,
             label_size=8, sub_size=6.5)
        _arrow(ax, 3.4, y_top - 0.08, 3.65, y_top - 0.08,
               color=COL_NEUTRAL_EDGE, lw=1.0)
        _arrow(ax, 7.25, y_top - 0.08, 7.45, y_top - 0.08,
               color=COL_NEUTRAL_EDGE, lw=1.0)

    # (fusion star annotation removed — was overlapping iter 3 label
    # band; caption + the iter 3 box content already make the fact-
    # coupling visible.)

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
            ("Closed loop iterates three times. The fact-coupled "
             "nmap_vuln (iter 3) reads Facts['open_ports'] written by "
             "nmap (iter 2) and scopes its --script vuln dispatch to "
             "those ten ports, surfacing the Apache CVE chain on 8089."),
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
# Figure 6 — DVWA, full condition: scale via nikto path enumeration
# ───────────────────────────────────────────────────────────────────


def render_fig6() -> None:
    fig, ax = plt.subplots(figsize=(11, 11))
    ax.set_xlim(0, 11)
    ax.set_ylim(0, 11)
    ax.axis("off")
    ax.set_aspect("equal")

    ax.text(5.5, 10.6,
            "Figure 6 — DVWA full run: scale on a teaching-app surface "
            "(2347 findings, the matrix outlier)",
            ha="center", va="center", fontsize=11,
            fontweight="bold", color="#0f172a")

    # Input panel
    _box(ax, 0.3, 9.55, 10.4, 0.8,
         "TARGET + TOOLS + CVE INTEL",
         sub="target='http://192.168.1.73:8081/' (DVWA, web_api)  ·  "
             "engines: nmap, nmap_vuln, nuclei, nikto, "
             "header_vuln_check, http_probe, url_crawler  ·  "
             "max_steps=25, max_depth=3  ·  "
             "AblationFlags(replanning=True, fusion=True)",
         edge=COL_INPUT_EDGE, face=COL_INPUT_FACE)
    _arrow(ax, 5.5, 9.55, 5.5, 9.2)

    # Context assembly
    _box(ax, 1.5, 8.5, 8.0, 0.7,
         "CONTEXT ASSEMBLY  (Facts={} at run start)",
         sub="available_engines=[6 enabled in 'fast' Kali pool] passed "
             "to HeuristicPlanner",
         edge=COL_INPUT_EDGE, face=COL_INPUT_FACE,
         label_size=9, sub_size=7)
    _arrow(ax, 5.5, 8.5, 5.5, 8.2)

    # Planning
    _box(ax, 1.5, 7.45, 8.0, 0.7,
         "PLANNING (HeuristicPlanner.plan_initial)",
         sub="DVWA's content surface fans out: seed pair "
             "[http_probe, url_crawler] + nmap front-loaded "
             "(per 'web_api' seed map)",
         edge=COL_NEUTRAL_EDGE, face=COL_NEUTRAL_FACE,
         label_size=9, sub_size=7)

    # Closed loop container (expanded to fit the four iter rows
    # comfortably; spans y=1.6 to y=7.0)
    ax.add_patch(FancyBboxPatch(
        (0.25, 1.6), 10.5, 5.4, boxstyle="round,pad=0.05",
        linewidth=1.4, edgecolor=COL_FUSION_EDGE,
        facecolor="#fff7ed", linestyle="solid", alpha=0.35,
    ))
    ax.text(5.5, 6.85, "CLOSED LOOP  (P1) — 4 decision steps",
            ha="center", va="center", fontsize=10,
            color=COL_FUSION_EDGE, fontweight="bold")
    _arrow(ax, 5.5, 7.45, 5.5, 7.0, color=COL_FUSION_EDGE)

    # Iter rows — spacing widened (1.3 units between rows) so iter
    # labels sit clearly above box tops and don't collide with the
    # previous iter's bottom annotations. REPLAN annotations dropped
    # in favour of the caption explaining the chain map.
    iter_specs = [
        (5.85,
         "iter 1: nmap (Kali)",
         "ssh kali 'nmap -sV -p- 192.168.1.73'",
         "12 open ports: 22, 80, 443, 3000, 8080,\n"
         "8081 (DVWA), 8089, 8090, ...",
         "+ {open_ports: [22, 80, 443, ..., 8081, 8089, ...],\n"
         "  tech_versions: [...nginx, Apache 2.4.7, ...]}"),
        (4.55,
         "iter 2: http_probe (local urllib)",
         "urllib GET http://...:8081/",
         "200 OK · Server: Apache/2.4.7 (Ubuntu)\n"
         "PHP/5.5.9-1ubuntu4.29",
         "+ {server_header: 'Apache/2.4.7', php_version}"),
        (3.25,
         "iter 3: nmap_vuln + nikto (parallel-equivalent)",
         "nmap --script vuln -p {facts[open_ports]}\n"
         "nikto -h http://...:8081/  -timeout 120",
         "nmap_vuln → 314 findings (Apache CVE chain)\n"
         "nikto    → 2012 findings (DVWA endpoint enum)",
         "+ {vulnerable_ports, cve_matches,\n"
         "  discovered_paths: [40+ DVWA endpoints]}"),
        (2.30,
         "iter 4: header_vuln_check (terminal)",
         "urllib HEAD http://...:8081/",
         "Missing: CSP, STS, X-Frame-Options,\n"
         "X-Content-Type-Options (7 findings)",
         "+ {missing_headers: [4 entries]}"),
    ]
    for y_top, label, ex, pa, kg in iter_specs:
        ax.text(0.6, y_top + 0.55, label,
                ha="left", va="center", fontsize=8.5,
                color="#7c2d12", fontweight="bold")
        _box(ax, 0.55, y_top - 0.45, 2.85, 0.90,
             "EXECUTE", sub=ex,
             edge=COL_NEUTRAL_EDGE, face=COL_NEUTRAL_FACE,
             label_size=8, sub_size=6.5)
        _box(ax, 3.65, y_top - 0.45, 3.6, 0.90,
             "PARSE → findings", sub=pa,
             edge=COL_NEUTRAL_EDGE, face=COL_NEUTRAL_FACE,
             label_size=8, sub_size=6.5)
        _box(ax, 7.45, y_top - 0.45, 3.2, 0.90,
             "KG UPDATE", sub=kg,
             edge=COL_FUSION_EDGE, face=COL_FUSION_FACE,
             label_size=8, sub_size=6.5)
        _arrow(ax, 3.4, y_top, 3.65, y_top,
               color=COL_NEUTRAL_EDGE, lw=1.0)
        _arrow(ax, 7.25, y_top, 7.45, y_top,
               color=COL_NEUTRAL_EDGE, lw=1.0)

    # Output panel (sits below the expanded closed-loop container)
    _arrow(ax, 5.5, 1.6, 5.5, 1.30, color=COL_OUTPUT_EDGE)
    _box(ax, 0.3, 0.15, 10.4, 1.15,
         "OUTPUT — AssessmentResult",
         sub=("findings=2347 (314 critical, 566 high, 1453 medium, "
              "14 low, 6 info)  ·  duration_s=293.2\n"
              "engine breakdown:  nikto=2012  ·  nmap_vuln=314  ·  "
              "nmap=12  ·  header_vuln_check=7  ·  http_probe=1  ·  "
              "url_crawler=1\n"
              "DVWA's deliberately exposed endpoint surface (~40 unauth "
              "teaching pages) is what nikto's content-discovery list is "
              "calibrated against → the matrix outlier."),
         edge=COL_OUTPUT_EDGE, face=COL_OUTPUT_FACE,
         label_size=9.5, sub_size=7.5)

    FIG_DIR.mkdir(parents=True, exist_ok=True)
    out = FIG_DIR / "fig6_dvwa_run.png"
    fig.savefig(out, dpi=160, bbox_inches="tight")
    plt.close(fig)
    print(f"Wrote {out}")


# ───────────────────────────────────────────────────────────────────
# Figure 7 — VAMPI, full condition: thin API surface
# ───────────────────────────────────────────────────────────────────


def render_fig7() -> None:
    fig, ax = plt.subplots(figsize=(11, 11))
    ax.set_xlim(0, 11)
    ax.set_ylim(0, 11)
    ax.axis("off")
    ax.set_aspect("equal")

    ax.text(5.5, 10.6,
            "Figure 7 — VAMPI full run: thinner API surface "
            "(133 findings, nmap_vuln dominates)",
            ha="center", va="center", fontsize=11,
            fontweight="bold", color="#0f172a")

    # Input panel
    _box(ax, 0.3, 9.55, 10.4, 0.8,
         "TARGET + TOOLS + CVE INTEL",
         sub="target='http://192.168.1.73:5000/' (VAMPI, web_api)  ·  "
             "engines: nmap, nmap_vuln, nuclei, nikto, "
             "header_vuln_check, http_probe, url_crawler  ·  "
             "max_steps=25, max_depth=3  ·  "
             "AblationFlags(replanning=True, fusion=True)",
         edge=COL_INPUT_EDGE, face=COL_INPUT_FACE)
    _arrow(ax, 5.5, 9.55, 5.5, 9.2)

    # Context assembly
    _box(ax, 1.5, 8.5, 8.0, 0.7,
         "CONTEXT ASSEMBLY  (Facts={} at run start)",
         sub="available_engines=[6 in fast Kali pool]  ·  "
             "VAMPI exposes only the api endpoint tree — no static "
             "teaching pages",
         edge=COL_INPUT_EDGE, face=COL_INPUT_FACE,
         label_size=9, sub_size=7)
    _arrow(ax, 5.5, 8.5, 5.5, 8.2)

    # Planning
    _box(ax, 1.5, 7.45, 8.0, 0.7,
         "PLANNING (HeuristicPlanner.plan_initial)",
         sub="_SEEDS[web_api] → [nmap, http_probe, url_crawler]",
         edge=COL_NEUTRAL_EDGE, face=COL_NEUTRAL_FACE,
         label_size=9, sub_size=7)

    # Closed loop container (expanded for 4 iter rows)
    ax.add_patch(FancyBboxPatch(
        (0.25, 1.6), 10.5, 5.4, boxstyle="round,pad=0.05",
        linewidth=1.4, edgecolor=COL_FUSION_EDGE,
        facecolor="#fff7ed", linestyle="solid", alpha=0.35,
    ))
    ax.text(5.5, 6.85, "CLOSED LOOP  (P1) — 4 decision steps",
            ha="center", va="center", fontsize=10,
            color=COL_FUSION_EDGE, fontweight="bold")
    _arrow(ax, 5.5, 7.45, 5.5, 7.0, color=COL_FUSION_EDGE)

    iter_specs = [
        (5.85,
         "iter 1: nmap (Kali)",
         "ssh kali 'nmap -sV -p- 192.168.1.73'",
         "12 open ports surfaced: 22, 80, 443,\n"
         "3000, 5000 (VAMPI), 8080, ...",
         "+ {open_ports: [22, 80, 443, ...,\n"
         "  5000, 8080, ...], tech_versions: [...]}"),
        (4.55,
         "iter 2: http_probe (local urllib)",
         "urllib GET http://...:5000/",
         "200 OK · Server: Werkzeug/2.0.3 Python/3.8\n"
         "Content-Type: application/json",
         "+ {server_header, content_type='application/json'}"),
        (3.25,
         "iter 3: nmap_vuln + nikto (fact-coupled)",
         "nmap --script vuln -p {facts[open_ports]}\n"
         "nikto -h http://...:5000/ -timeout 120",
         "nmap_vuln → 102 findings (CVE chain on sibling\n"
         "  Apache containers reachable via Kali host)\n"
         "nikto    → 12 findings (thin API surface)",
         "+ {vulnerable_ports, cve_matches}"),
        (2.30,
         "iter 4: header_vuln_check (terminal)",
         "urllib HEAD http://...:5000/",
         "Missing: CSP, STS, X-Frame-Options,\n"
         "X-Content-Type-Options, Referrer-Policy",
         "+ {missing_headers: [5 entries]}"),
    ]
    for y_top, label, ex, pa, kg in iter_specs:
        ax.text(0.6, y_top + 0.55, label,
                ha="left", va="center", fontsize=8.5,
                color="#7c2d12", fontweight="bold")
        _box(ax, 0.55, y_top - 0.45, 2.85, 0.90,
             "EXECUTE", sub=ex,
             edge=COL_NEUTRAL_EDGE, face=COL_NEUTRAL_FACE,
             label_size=8, sub_size=6.5)
        _box(ax, 3.65, y_top - 0.45, 3.6, 0.90,
             "PARSE → findings", sub=pa,
             edge=COL_NEUTRAL_EDGE, face=COL_NEUTRAL_FACE,
             label_size=8, sub_size=6.5)
        _box(ax, 7.45, y_top - 0.45, 3.2, 0.90,
             "KG UPDATE", sub=kg,
             edge=COL_FUSION_EDGE, face=COL_FUSION_FACE,
             label_size=8, sub_size=6.5)
        _arrow(ax, 3.4, y_top, 3.65, y_top,
               color=COL_NEUTRAL_EDGE, lw=1.0)
        _arrow(ax, 7.25, y_top, 7.45, y_top,
               color=COL_NEUTRAL_EDGE, lw=1.0)

    # Output panel (sits below the expanded closed-loop container)
    _arrow(ax, 5.5, 1.6, 5.5, 1.30, color=COL_OUTPUT_EDGE)
    _box(ax, 0.3, 0.15, 10.4, 1.15,
         "OUTPUT — AssessmentResult",
         sub=("findings=133 (102 critical, 2 high, 15 medium, 14 low)  ·  "
              "duration_s=218.2\n"
              "engine breakdown:  nmap_vuln=102  ·  nmap=12  ·  "
              "nikto=12  ·  header_vuln_check=5  ·  http_probe=1  ·  "
              "url_crawler=1\n"
              "VAMPI's API-only surface inverts DVWA's ratio: nikto's "
              "endpoint enumeration finds 12 vs DVWA's 2012, while "
              "nmap_vuln (CVE matches on the LAN host) stays dominant."),
         edge=COL_OUTPUT_EDGE, face=COL_OUTPUT_FACE,
         label_size=9.5, sub_size=7.5)

    FIG_DIR.mkdir(parents=True, exist_ok=True)
    out = FIG_DIR / "fig7_vampi_run.png"
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
