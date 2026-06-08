# ReasonChain Core

Reference implementation of **ReasonChain** — a closed-loop LLM architecture for autonomous multi-tool cybersecurity assessment — and the empirical evaluation that backs the research paper:

> **Obi Ebuka David, Sayed Erfan Arefin.** *PENTAGON: Can Closed-Loop LLM Reasoning Achieve Autonomous Multi-Tool Cybersecurity Assessment?* (in submission).
>
> University of Dayton, Department of Computer Science.

This repo is the **public, MIT-licensed core** of the architecture. Production extensions, premium engines, multi-tenant auth, SSH-to-Kali execution, and other commercial-only features live in a separate private repository (Pentagon).

## Architecture (the three claims under test)

1. **Closed-Loop Reasoning** — after each tool execution, the LLM receives parsed output and re-evaluates the remaining plan.
2. **Cross-Tool Intelligence Fusion** — findings from one tool inform decisions for subsequent tools.
3. **Target-Aware Methodology** — strategy selection adapts to target type (IP / domain / URL / subnet).

```
TARGET + TOOLS + CVE Intel
        ↓
  CONTEXT ASSEMBLY (≤30K tokens)
        ↓
  LLM PLANNING (8-15 step plan)
        ↓
  ┌──────────── CLOSED LOOP ────────────┐
  │   EXECUTE  →  PARSE  →  KG UPDATE   │
  │                                      │
  │                       LLM REPLAN ←──┘
  └──────────────────────────────────────┘
```

## Repository layout

| Path | Contents |
|---|---|
| [`src/reasonchain/`](src/reasonchain/) | Minimal core — orchestrator + planner + facts merger + engine ABI. |
| [`experiments/`](experiments/) | Ablation runners (full / no-replan / no-fusion / random-order) + target manifests. |
| [`notebooks/`](notebooks/) | Statistical analysis (paired t-tests, effect sizes) for H1–H3. |
| [`paper/`](paper/) | Paper draft + figures. |
| [`data/`](data/) | Anonymized per-condition results (gitignored; share via Zenodo for camera-ready). |

## Hypotheses

- **H1** — Closed-loop replanning improves coverage (full vs. `no-replan` ablation; vulnerability discovery delta).
- **H2** — Cross-tool fusion reduces redundancy (full vs. `no-fusion`; assessment time + coverage).
- **H3** — LLM reasoning degrades predictably (per-decision classification → failure-mode taxonomy).

## Quickstart

Every engine in this repo makes real network requests; there are no
mock engines and no synthetic data. To run an ablation you need a
live target. The easiest is OWASP Juice Shop via Docker:

```bash
pip install -e ".[experiments]"

# Spin up a live target (Juice Shop on port 3000).
docker run --rm -d -p 3000:3000 --name juice-shop bkimminich/juice-shop

# Four conditions against the live target.
python -m experiments.run_ablation --target juiceshop --condition full
python -m experiments.run_ablation --target juiceshop --condition no-replan
python -m experiments.run_ablation --target juiceshop --condition no-fusion
python -m experiments.run_ablation --target juiceshop --condition random-order

# Open the analysis notebook.
jupyter notebook notebooks/h1_h2_h3_analysis.ipynb
```

To sweep all 10 bundled OWASP target manifests, see the recipe in
[`paper/preliminary_results.md`](paper/preliminary_results.md).

## License

MIT — see [LICENSE](LICENSE). Use, modify, redistribute freely; please cite the paper.

## Citation

```bibtex
@inproceedings{david2026reasonchain,
  title  = {PENTAGON: Can Closed-Loop LLM Reasoning Achieve Autonomous Multi-Tool Cybersecurity Assessment?},
  author = {David, Obi Ebuka and Arefin, Sayed Erfan},
  year   = {2026},
  note   = {In submission}
}
```
