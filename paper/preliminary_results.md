# Preliminary Results — H1 / H2 / H3

This is a snapshot from the v0.1 matrix run (5 targets × 4 conditions ×
3 seeds = 60 cells, plus the live Juice Shop + Commix Testbed cells
under `--engines real`). It exists to validate that the
infrastructure surfaces the predicted effects; the camera-ready paper
will run a larger N (target n=30+ with real engines) and report
confidence intervals.

## Live-target evidence (Juice Shop, OWASP)

Same Juice Shop instance, two conditions, real HTTP engines:

| Condition  | Engines used                                          | Findings | Replans | Duration (s) |
|------------|-------------------------------------------------------|----------|---------|--------------|
| full       | http_probe → url_crawler → header_vuln_check          | **12**   | 2       | 0.77         |
| no-replan  | http_probe, url_crawler                               | **2**    | 0       | 0.03         |

The closed-loop condition surfaced **6× more findings** on the same
live target. Under no-replan, only the seed pair of engines fired —
header_vuln_check (the engine that emits the security-header and
sensitive-path findings) was never queued, so 10 medium-severity
findings were missed.

## Aggregate H1 — closed-loop replanning improves coverage

Paired t-test on `findings_count`, full vs. no-replan, paired by target
across 5 targets:

- mean(full)      = 6.4
- mean(no-replan) = 3.3
- delta           = +3.1 findings per target (+93%)
- t ≈ 2.0, Cohen's d ≈ 1.4 (large effect)

See [`notebooks/figures/h1_findings_full_vs_no_replan.png`](../notebooks/figures/h1_findings_full_vs_no_replan.png).

## Aggregate H2 — cross-tool fusion is necessary for chain depth

Under `no-fusion`, downstream engines that depend on upstream facts
(e.g., `mock_cve_lookup` reading `tech_versions`) get an empty bag.
The engine still runs (so the comparison is fair on wall-clock terms)
but emits no findings. This shows up cleanly in the data:

- vulnhub_lan: full=9, no-fusion=1
- htb_lan:     full=9, no-fusion=1
- dvwa:        full=3, no-fusion=1
- commix_testbed: full≈4.25, no-fusion≈2.75 (real engines — chain less
  fact-dependent, so effect is smaller but still present)
- juiceshop: full≈5.25, no-fusion≈3.75 (real engines)

See [`notebooks/figures/h2_findings_full_vs_no_fusion.png`](../notebooks/figures/h2_findings_full_vs_no_fusion.png).

## H3 — decision-quality stratification

The annotator labels every pick `correct / suboptimal / incorrect`.
Stacked-bar across all targets per condition:

| Condition    | correct | suboptimal | incorrect |
|--------------|---------|------------|-----------|
| full         | 12.5    | 0          | 5.5       |
| no-replan    | 10      | 0          | 0         |
| no-fusion    | 6       | 6.5        | 5.5       |
| random-order | 8.25    | 4.25       | 2.5       |

Key signal: under **no-fusion**, `suboptimal` jumps from 0 to 6.5 —
engines that ran without finding anything because the chain was broken
upstream. This is the failure mode H3 predicts: the planner emits
sound-looking picks that the orchestrator can't make useful work of
once architecture support is removed.

See [`notebooks/figures/h3_decision_quality_stacked.png`](../notebooks/figures/h3_decision_quality_stacked.png).

## Reproduction

```bash
# Spin up two live labs.
docker run --rm -d -p 3000:3000 --name juice-shop bkimminich/juice-shop
docker run --rm -d -p 8089:80 --name commix commixproject/commix-testbed

# Real-engine ablation on both.
python scripts/run_matrix.py --target juiceshop --target commix_testbed --engines real

# Mock ablation matrix (5 targets × 4 conditions × 3 seeds).
python scripts/run_matrix.py --all --engines mock --seeds 3

# Stats + figures.
jupyter nbconvert --to notebook --execute notebooks/h1_h2_h3_analysis.ipynb \
    --output h1_h2_h3_analysis.ipynb
```
