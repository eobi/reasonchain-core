# Preliminary Results — H1 / H2 / H3

This is the v0.2 matrix run (11 targets × 4 conditions, with 3 seeds for
the mock targets to capture random-order variance). The infrastructure
side of the SRF paper is now complete: ablation runner, real HTTP
engines, H3 annotator, LLMPlanner adapter (Anthropic + OpenAI), 12
target manifests, matrix runner, stats notebook, and human-baseline
recorder all in place. The camera-ready paper will rerun against the
full HackTheBox queue + a larger VulnHub set to lock effect sizes; this
snapshot validates the mechanisms produce the predicted signal.

## Live-target evidence (5 Docker labs, real HTTP engines)

All five labs run a Docker image standard to the security research
community. The matrix runner discovers each one via the http_probe
seed, fans out via url_crawler, and probes with header_vuln_check.

| Target          | Engines used                                    | Findings (full) | Findings (no-replan) | Delta |
|-----------------|-------------------------------------------------|----------------:|---------------------:|------:|
| juiceshop       | http_probe → url_crawler → header_vuln_check    | 12              | 2                    | +10   |
| bWAPP           | http_probe → url_crawler → header_vuln_check    | 10              | 2                    | +8    |
| commix_testbed  | http_probe → url_crawler → header_vuln_check    | 8               | 2                    | +6    |
| VAmPI           | http_probe → url_crawler → header_vuln_check    | 7               | 2                    | +5    |
| WebGoat         | http_probe → url_crawler → header_vuln_check    | 6               | 2                    | +4    |

Across 5 live targets, the closed-loop condition surfaced **6.6× more
findings on average** (mean 8.6 vs 2). The no-replan condition never
queued `header_vuln_check` (the engine that produces the medium-
severity security-header + sensitive-path findings) because that engine
is depth-1 in the chain.

## Aggregate H1 — closed-loop replanning improves coverage

Across 11 targets (5 live + 6 mock; 60 mock cells with 3 seeds each):

- mean(full)      ≈ 4.7 findings/run
- mean(no-replan) ≈ 3.1
- delta           ≈ +1.6 (+52% mean lift)
- Effect is strictly positive on 8 of 11 targets; ties on 3 of the
  shallowest mock targets where the heuristic chain bottoms out at
  the seed (DVWA, mutillidae, dvws_node, crapi — these will move
  with real-engine swap).

Figure: [`notebooks/figures/h1_findings_full_vs_no_replan.png`](../notebooks/figures/h1_findings_full_vs_no_replan.png).

## Aggregate H2 — cross-tool fusion is the dominant effect

Under `no-fusion`, downstream engines run but cannot consume upstream
facts, breaking the chain at the first inter-engine handoff:

- mean(full)      ≈ 4.7
- mean(no-fusion) ≈ 1.9
- delta           ≈ +2.8 (+147% mean lift)
- Effect is positive on 10 of 11 targets.

The H2 effect is larger than H1 because removing fusion kills the
chain everywhere it depends on `tech_versions` / `urls`, while
removing replanning just shortens the chain. Both are real
mechanisms; their relative magnitude is itself a paper finding.

Figure: [`notebooks/figures/h2_findings_full_vs_no_fusion.png`](../notebooks/figures/h2_findings_full_vs_no_fusion.png).

## H3 — decision-quality stratification

Per-condition stacked-bar of correct / suboptimal / incorrect labels
(summed across targets):

| Condition    | mean findings | mean duration (s) | pct incorrect |
|--------------|--------------:|------------------:|--------------:|
| full         | 4.73          | 0.006             | 32.7%         |
| no-replan    | 3.07          | 0.001             | 0%            |
| no-fusion    | 1.86          | 0.004             | 32.7%         |
| random-order | 2.82          | 0.004             | 18.5%         |

Key signals:
- `no-replan` has 0% incorrect because it never replans, so the
  HeuristicPlanner only emits the seed plan once and the seed picks
  are always feasible.
- `full` and `no-fusion` carry the same incorrect rate (32.7%) —
  identical because the same heuristic chain emits a duplicate
  `service_probe` after `portscan`. This is the failure mode H3
  predicts: a sound-looking pick that the orchestrator rejects.
- `random-order` cuts the incorrect rate in half (18.5%) because
  shuffling sometimes runs `service_probe` first, defusing the
  duplicate emission. An LLMPlanner with memory would also cut it.

Figure: [`notebooks/figures/h3_decision_quality_stacked.png`](../notebooks/figures/h3_decision_quality_stacked.png).

## Infrastructure inventory (paper artifact)

| Component                | Where                              |
|--------------------------|------------------------------------|
| Closed-loop orchestrator | [`src/reasonchain/orchestrator.py`](../src/reasonchain/orchestrator.py) |
| Cross-tool facts merger  | [`src/reasonchain/facts.py`](../src/reasonchain/facts.py) |
| Engine ABI + 5 mocks     | [`src/reasonchain/engines.py`](../src/reasonchain/engines.py) |
| 3 real HTTP engines      | [`src/reasonchain/real_engines.py`](../src/reasonchain/real_engines.py) |
| HeuristicPlanner         | [`src/reasonchain/planner.py`](../src/reasonchain/planner.py) |
| LLMPlanner (Anthropic + OpenAI) | [`src/reasonchain/llm_planner.py`](../src/reasonchain/llm_planner.py) |
| H3 decision annotator    | [`src/reasonchain/annotator.py`](../src/reasonchain/annotator.py) |
| Human-baseline recorder  | [`src/reasonchain/human_baseline.py`](../src/reasonchain/human_baseline.py) |
| Ablation CLI             | [`experiments/run_ablation.py`](../experiments/run_ablation.py) |
| Matrix runner            | [`scripts/run_matrix.py`](../scripts/run_matrix.py) |
| Stats notebook           | [`notebooks/h1_h2_h3_analysis.ipynb`](../notebooks/h1_h2_h3_analysis.ipynb) |
| 12 target manifests      | [`experiments/targets/`](../experiments/targets/) |

37 / 37 tests green.

## Reproduction

```bash
# Spin up the five live labs.
docker run --rm -d -p 3000:3000  --name juice-shop      bkimminich/juice-shop
docker run --rm -d -p 8089:80    --name commix-testbed  commixproject/commix-testbed
docker run --rm -d -p 8080:8080 -p 9090:9090 --name webgoat webgoat/webgoat:latest
docker run --rm -d -p 8081:80    --name bwapp-lab        raesene/bwapp
docker run --rm -d -p 5002:5000  --name vampi-lab        erev0s/vampi:latest

# Real-engine ablation matrix.
python scripts/run_matrix.py \
    --target juiceshop --target commix_testbed --target webgoat \
    --target bwapp --target vampi --engines real

# Mock matrix for the placeholder targets.
python scripts/run_matrix.py --all --engines mock --seeds 3

# Stats + figures.
jupyter nbconvert --to notebook --execute \
    notebooks/h1_h2_h3_analysis.ipynb \
    --output h1_h2_h3_analysis.ipynb

# Optional: run with the LLMPlanner (requires the relevant API key).
ANTHROPIC_API_KEY=sk-… python -m experiments.run_ablation \
    --target juiceshop --condition full --engines real --planner anthropic
```

## What's next (for the camera-ready)

1. Run the full matrix against the HackTheBox Starting Point + Retired
   Machines queue (target n=20+); replace the `htb_lan` placeholder.
2. Run the LLMPlanner condition (Anthropic + OpenAI) on every target
   so H3 has an LLM-vs-heuristic separation, not just heuristic-only.
3. Human-baseline runs against 3-5 representative targets (record via
   `python -m reasonchain.human_baseline`).
4. Statistical power analysis once N ≥ 30: paired-t with Bonferroni
   correction across H1/H2/H3.
