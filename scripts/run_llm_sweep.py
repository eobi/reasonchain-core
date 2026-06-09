"""Run a small LLM-planner sweep on a representative subset of
targets so the paper can report an LLM-vs-heuristic comparison.

Default subset: juiceshop + bWAPP + commix_testbed + pygoat + dvga
(modern SPA + classic LAMP + injection sandbox + Django + GraphQL).
That's 5 targets × 4 conditions = 20 cells. With the Anthropic
planner running on top of the Kali fast pool, each cell makes
2-3 Claude API calls (~$0.01-0.02 per cell, total ~$0.20-0.40).

Usage (requires ANTHROPIC_API_KEY in env):
    python scripts/run_llm_sweep.py
"""
from __future__ import annotations

import os
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "src"))

DEFAULT_SUBSET = (
    "juiceshop", "bwapp", "commix_testbed", "pygoat", "dvga",
)
CONDITIONS = ("full", "no-replan", "no-fusion", "random-order")
LLM_CSV = REPO_ROOT / "data" / "llm_sweep.csv"


def main(argv: list[str] | None = None) -> int:
    import argparse
    p = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    p.add_argument("--target", action="append", default=[],
                   help="target name (repeat). Defaults to the 5-target subset.")
    p.add_argument("--planner", default="anthropic",
                   choices=("anthropic", "openai"))
    args = p.parse_args(argv)

    targets = args.target or list(DEFAULT_SUBSET)
    # Try to load .env if present.
    env_path = REPO_ROOT / ".env"
    if env_path.exists():
        for line in env_path.read_text().splitlines():
            if "=" in line and not line.startswith("#"):
                k, _, v = line.partition("=")
                os.environ.setdefault(k.strip(), v.strip())

    from experiments.run_ablation import run_one

    if LLM_CSV.exists():
        LLM_CSV.unlink()

    import csv
    print(f"LLM sweep · planner={args.planner} · "
          f"{len(targets)} targets × {len(CONDITIONS)} conditions")
    t0 = time.perf_counter()
    rows: list[dict] = []
    for ti, target in enumerate(targets, 1):
        for ci, condition in enumerate(CONDITIONS, 1):
            cell = (ti - 1) * len(CONDITIONS) + ci
            total = len(targets) * len(CONDITIONS)
            try:
                row = run_one(
                    target, condition, seed=0,
                    planner_name=args.planner, kali_mode="fast",
                )
            except Exception as e:
                row = {
                    "target": target, "condition": condition,
                    "planner": args.planner, "kali": "fast",
                    "seed": 0, "error": f"{type(e).__name__}: {e}",
                }
            row.setdefault("error", "")
            rows.append(row)
            print(f"  [{cell}/{total}] {target:15s} {condition:13s} "
                  f"engines={row.get('engine_count', '?'):>2} "
                  f"findings={row.get('findings_count', '?'):>3} "
                  f"incorrect={row.get('decisions_incorrect', '?'):>2}")

    fieldnames = sorted({k for r in rows for k in r.keys()})
    LLM_CSV.parent.mkdir(parents=True, exist_ok=True)
    with LLM_CSV.open("w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=fieldnames)
        w.writeheader()
        w.writerows(rows)
    elapsed = time.perf_counter() - t0
    print(f"\ndone in {elapsed:.0f}s → {LLM_CSV}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
