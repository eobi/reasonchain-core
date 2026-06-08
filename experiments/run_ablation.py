"""H1/H2/H3 ablation runner.

Usage:
    python -m experiments.run_ablation --target juiceshop --condition full
    python -m experiments.run_ablation --target juiceshop --condition no-replan
    python -m experiments.run_ablation --target juiceshop --condition no-fusion
    python -m experiments.run_ablation --target juiceshop --condition random-order

Writes one CSV row to data/results.csv per (target, condition) pair so
notebook analysis can aggregate runs across the bundled target manifest.

The runner uses the real HTTP engines in ``reasonchain.real_engines``
to assess a live target — there is no offline mode. Every row in the
CSV is the result of an actual network round-trip.
"""
from __future__ import annotations

import argparse
import csv
import json
import sys
import time
from pathlib import Path

import yaml  # type: ignore[import-not-found]

from reasonchain import (
    AblationFlags, AssessmentSpec, HeuristicPlanner, Orchestrator,
    REAL_ENGINES,
)
from reasonchain.annotator import annotate


CONDITIONS = ("full", "no-replan", "no-fusion", "random-order")
PLANNERS = ("heuristic", "anthropic", "openai")
TARGETS_DIR = Path(__file__).parent / "targets"
RESULTS_CSV = Path(__file__).parent.parent / "data" / "results.csv"


def _make_planner(planner_name: str):
    if planner_name == "heuristic":
        return HeuristicPlanner()
    if planner_name == "anthropic":
        from reasonchain.llm_planner import AnthropicClient, LLMPlanner
        return LLMPlanner(client=AnthropicClient())
    if planner_name == "openai":
        from reasonchain.llm_planner import LLMPlanner, OpenAIClient
        return LLMPlanner(client=OpenAIClient())
    raise SystemExit(f"unknown planner: {planner_name}")


def _flags_for(condition: str, seed: int) -> AblationFlags:
    if condition == "full":
        return AblationFlags(replanning=True, fusion=True, random_order=False)
    if condition == "no-replan":
        return AblationFlags(replanning=False, fusion=True, random_order=False)
    if condition == "no-fusion":
        return AblationFlags(replanning=True, fusion=False, random_order=False)
    if condition == "random-order":
        return AblationFlags(
            replanning=True, fusion=True,
            random_order=True, random_seed=seed,
        )
    raise SystemExit(f"unknown condition: {condition}")


def _load_target(name: str) -> dict:
    p = TARGETS_DIR / f"{name}.yaml"
    if not p.exists():
        raise SystemExit(f"no target manifest at {p}")
    return yaml.safe_load(p.read_text())


def _make_orchestrator(
    flags: AblationFlags, planner_name: str = "heuristic",
) -> Orchestrator:
    return Orchestrator(
        engines=REAL_ENGINES, planner=_make_planner(planner_name),
        flags=flags,
    )


def run_one(
    target_name: str, condition: str, seed: int,
    planner_name: str = "heuristic",
) -> dict:
    manifest = _load_target(target_name)
    spec = AssessmentSpec(
        target=manifest["target"],
        target_type=manifest["target_type"],
        max_steps=int(manifest.get("max_steps", 25)),
        max_depth=int(manifest.get("max_depth", 3)),
    )
    flags = _flags_for(condition, seed)
    orch = _make_orchestrator(flags, planner_name=planner_name)
    t0 = time.perf_counter()
    result = orch.run(spec)
    wall_s = time.perf_counter() - t0

    sev_counts: dict[str, int] = {}
    for f in result.findings:
        sev_counts[f.severity] = sev_counts.get(f.severity, 0) + 1

    # H3 substrate: label every decision.
    annotated = annotate(result, engines_registry=orch.engines)

    return {
        "target": target_name,
        "condition": condition,
        "planner": planner_name,
        "seed": seed,
        "duration_s": round(wall_s, 4),
        "engines_used": ",".join(result.engines_used),
        "engine_count": len(result.engines_used),
        "findings_count": len(result.findings),
        "replans": result.replans,
        "decisions": len(result.decisions),
        "critical": sev_counts.get("critical", 0),
        "high":     sev_counts.get("high", 0),
        "medium":   sev_counts.get("medium", 0),
        "low":      sev_counts.get("low", 0),
        "info":     sev_counts.get("info", 0),
        "decisions_correct":    annotated.counts.get("correct", 0),
        "decisions_suboptimal": annotated.counts.get("suboptimal", 0),
        "decisions_incorrect":  annotated.counts.get("incorrect", 0),
        "decisions_total":      annotated.total,
        "aborted":  result.aborted,
    }


def _append_csv(row: dict) -> None:
    RESULTS_CSV.parent.mkdir(parents=True, exist_ok=True)
    new = not RESULTS_CSV.exists()
    with RESULTS_CSV.open("a", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(row.keys()))
        if new:
            w.writeheader()
        w.writerow(row)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    p.add_argument("--target", required=True,
                   help="target manifest stem under experiments/targets/")
    p.add_argument("--condition", required=True, choices=CONDITIONS)
    p.add_argument("--seed", type=int, default=0,
                   help="random seed for the random-order condition")
    p.add_argument("--planner", choices=PLANNERS, default="heuristic",
                   help="planner to drive picks. anthropic/openai need "
                        "their respective API key in env.")
    p.add_argument("--no-csv", action="store_true",
                   help="print result as JSON and skip the CSV append")
    args = p.parse_args(argv)

    row = run_one(args.target, args.condition, args.seed,
                  planner_name=args.planner)
    print(json.dumps(row, indent=2))
    if not args.no_csv:
        _append_csv(row)
        print(f"\n→ appended to {RESULTS_CSV}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
