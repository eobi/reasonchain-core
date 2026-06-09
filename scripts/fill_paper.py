"""Auto-fill the paper.md TBAs from data/results.csv.

Reads the matrix CSV, computes the statistics referenced in
``paper/paper.md`` (Wilcoxon + paired t with and without DVWA
outlier, mean lifts, decision-quality rates), and substitutes the
``**TBA**`` placeholders with the actual numbers. Output is
``paper/paper_filled.md``.

Usage:
    python scripts/fill_paper.py
"""
from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "src"))

import pandas as pd  # noqa: E402
from scipy import stats  # noqa: E402

PAPER = REPO_ROOT / "paper" / "paper.md"
PAPER_FILLED = REPO_ROOT / "paper" / "paper_filled.md"
RESULTS = REPO_ROOT / "data" / "results.csv"


def main() -> int:
    if not RESULTS.exists():
        print(f"missing {RESULTS} — run scripts/run_matrix.py first",
              file=sys.stderr)
        return 1
    df = pd.read_csv(RESULTS)
    agg = df.groupby(["target", "condition"])[
        "findings_count"
    ].mean().unstack()

    n_cells = len(df)
    n_targets = len(agg)
    duration_h = df["duration_s"].sum() / 3600

    # H1
    h1f, h1n = agg["full"], agg["no-replan"]
    t1, p1 = stats.ttest_rel(h1f, h1n, alternative="greater")
    w1, pw1 = stats.wilcoxon(h1f, h1n, alternative="greater")
    no_outlier = agg.copy()
    for outlier in ("dvwa_live", "dvwa"):
        if outlier in no_outlier.index:
            no_outlier = no_outlier.drop(outlier)
    h1fn, h1nn = no_outlier["full"], no_outlier["no-replan"]
    t1n, p1n = stats.ttest_rel(h1fn, h1nn, alternative="greater")
    d1n = ((h1fn - h1nn).mean()
           / max((h1fn - h1nn).std(ddof=1), 1e-9))

    # H2
    h2f, h2no = agg["full"], agg["no-fusion"]
    t2, p2 = stats.ttest_rel(h2f, h2no, alternative="greater")
    w2, pw2 = stats.wilcoxon(h2f, h2no, alternative="greater")
    h2_lift_pct = ((h2f.mean() - h2no.mean()) / max(h2f.mean(), 1)) * 100

    # Means
    mean_full = h1f.mean()
    mean_no_replan = h1n.mean()
    mean_no_fusion = h2no.mean()
    mean_random = agg["random-order"].mean()
    median_full = h1f.median()
    median_delta = (h1f - h1n).median()

    # H3
    decisions = df.groupby("condition")[
        ["decisions_correct", "decisions_suboptimal", "decisions_incorrect"]
    ].sum()
    decisions["total"] = decisions.sum(axis=1)
    decisions["pct_incorrect"] = (decisions["decisions_incorrect"]
                                  / decisions["total"].replace(0, 1)
                                  * 100)
    pct_inc = {c: decisions.loc[c, "pct_incorrect"]
               for c in decisions.index}

    # Substitutions table — each key is the placeholder text in
    # paper.md, value is the replacement. Apply in order.
    subs: list[tuple[str, str]] = [
        ("median **N**-fold",
         f"**{(h1f / h1n.replace(0, 1)).median():.1f}-fold**"),
        ("Wilcoxon p=**X**",      f"Wilcoxon W={w1:.0f}, p={pw1:.4f}"),
        ("paired t with outlier excluded, p=**Y**",
         f"paired t excluding the DVWA outlier, p={p1n:.4g}"),
        ("Cohen d=**Z**",         f"Cohen d={d1n:.2f}"),
        ("18 OWASP-class deliberately-vulnerable web applications",
         f"{n_targets} OWASP-class deliberately-vulnerable web applications"),
        ("18 OWASP-class targets",
         f"{n_targets} OWASP-class targets"),
        ("72 matrix cells",       f"{n_cells} matrix cells"),
        ("72 cells", f"{n_cells} cells"),
        ("Each (target, condition) pair runs once with seed 0.",
         "Each (target, condition) pair runs once with seed 0."),
        ("18 OWASP-class targets and 72 matrix cells",
         f"{n_targets} OWASP-class targets and {n_cells} matrix cells"),

        # Headline
        ("mean(full) = **TBA** findings per cell",
         f"mean(full) = {mean_full:.1f} findings per cell"),
        ("mean(no-replan) = **TBA**",
         f"mean(no-replan) = {mean_no_replan:.1f}"),
        ("mean(no-fusion) = **TBA**",
         f"mean(no-fusion) = {mean_no_fusion:.1f}"),
        ("mean(random-order) = **TBA**",
         f"mean(random-order) = {mean_random:.1f}"),
        ("The 72-cell matrix completes in approximately 5 hours of wall-clock\ntime.",
         f"The {n_cells}-cell matrix completed in {duration_h:.1f} hours of "
         f"wall-clock time."),
        ("yields\nW = **TBA**, p = **TBA**.",
         f"yields W = {w1:.0f}, p = {pw1:.4f}."),
        ("yields t = **TBA**, p = **TBA**,\nCohen d = **TBA**.",
         f"yields t = {t1n:.2f}, p = {p1n:.4g}, Cohen d = {d1n:.2f}."),

        # H1 figure mechanism
        ("the median delta is **TBA** findings per target.",
         f"the median delta is {median_delta:.1f} findings per target."),

        # H2
        ("the no-fusion condition produces\n**TBA** % fewer findings",
         f"the no-fusion condition produces {h2_lift_pct:.1f}% fewer "
         f"findings"),
        ("The paired t-test yields t = **TBA**, p = **TBA**; Wilcoxon p =\n**TBA**.",
         f"The paired t-test yields t = {t2:.2f}, p = {p2:.4f}; "
         f"Wilcoxon p = {pw2:.4f}."),

        # H3
        ("The incorrect rate is **TBA** % under full, **TBA** % under no-fusion,\nand **TBA** % under random-order.",
         f"The incorrect rate is {pct_inc.get('full', 0):.1f}% under full, "
         f"{pct_inc.get('no-fusion', 0):.1f}% under no-fusion, and "
         f"{pct_inc.get('random-order', 0):.1f}% under random-order."),
        ("reduces the\nincorrect rate to **TBA** %",
         "is to be reported in the camera-ready (subset experiment "
         "pending; see Limitations §8)"),
    ]

    text = PAPER.read_text()
    for needle, replacement in subs:
        text = text.replace(needle, replacement)

    PAPER_FILLED.write_text(text)
    print(f"Wrote {PAPER_FILLED}")
    print(f"  n_targets    = {n_targets}")
    print(f"  n_cells      = {n_cells}")
    print(f"  mean(full)   = {mean_full:.1f}")
    print(f"  mean(no-replan) = {mean_no_replan:.1f}")
    print(f"  H1 Wilcoxon  = W={w1:.0f}, p={pw1:.4f}")
    print(f"  H1 no-outlier t = t={t1n:.2f}, p={p1n:.4g}, d={d1n:.2f}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
