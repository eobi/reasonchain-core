"""H1/H2/H3 ablation runner.

Usage:
    python -m experiments.run_ablation --target dvwa --condition full
    python -m experiments.run_ablation --target dvwa --condition no-replan
    python -m experiments.run_ablation --target dvwa --condition no-fusion
    python -m experiments.run_ablation --target dvwa --condition random-order

Writes one CSV row to data/results.csv per (target, condition) pair so
notebook analysis can aggregate runs across the bundled target manifest.

Defaults to MOCK_ENGINES so the entire harness runs offline (no real
network probes, no LLM calls). To swap in real engines, register them
on the returned ``engines`` dict in ``_make_orchestrator``.
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
    AblationFlags, AssessmentSpec, HeuristicPlanner, MOCK_ENGINES,
    Orchestrator,
)


CONDITIONS = ("full", "no-replan", "no-fusion", "random-order")
TARGETS_DIR = Path(__file__).parent / "targets"
RESULTS_CSV = Path(__file__).parent.parent / "data" / "results.csv"


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


def _make_orchestrator(flags: AblationFlags) -> Orchestrator:
    # MOCK_ENGINES is the default offline harness. Real-engine setups
    # register their own dict here (private Pentagon does this).
    return Orchestrator(
        engines=MOCK_ENGINES, planner=HeuristicPlanner(), flags=flags,
    )


def run_one(target_name: str, condition: str, seed: int) -> dict:
    manifest = _load_target(target_name)
    spec = AssessmentSpec(
        target=manifest["target"],
        target_type=manifest["target_type"],
        max_steps=int(manifest.get("max_steps", 25)),
        max_depth=int(manifest.get("max_depth", 3)),
    )
    flags = _flags_for(condition, seed)
    orch = _make_orchestrator(flags)
    t0 = time.perf_counter()
    result = orch.run(spec)
    wall_s = time.perf_counter() - t0

    sev_counts: dict[str, int] = {}
    for f in result.findings:
        sev_counts[f.severity] = sev_counts.get(f.severity, 0) + 1

    return {
        "target": target_name,
        "condition": condition,
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
    p.add_argument("--no-csv", action="store_true",
                   help="print result as JSON and skip the CSV append")
    args = p.parse_args(argv)

    row = run_one(args.target, args.condition, args.seed)
    print(json.dumps(row, indent=2))
    if not args.no_csv:
        _append_csv(row)
        print(f"\n→ appended to {RESULTS_CSV}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
