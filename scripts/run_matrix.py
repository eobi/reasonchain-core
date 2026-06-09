"""Matrix runner — sweeps every (target, condition, seed) combination.

Usage:
    # Sweep every bundled target × 4 conditions, 5 seeds each
    python scripts/run_matrix.py --all --seeds 5

    # One target × all conditions, default 1 seed
    python scripts/run_matrix.py --target juiceshop

Writes one row per run into ``data/results.csv``. The H1/H2/H3 stats
notebook reads that file and computes the paired-t / Cohen's d /
confusion-matrix figures for the paper.

Every run is a live network round-trip against the target. The
pre-flight reachability check pings each target once with a 5s GET;
targets that don't respond are skipped so the CSV doesn't get
polluted with unreachable-target zeros.
"""
from __future__ import annotations

import argparse
import csv
import itertools
import socket
import sys
import time
from pathlib import Path
from urllib.error import URLError
from urllib.request import Request, urlopen

REPO_ROOT = Path(__file__).resolve().parent.parent
TARGETS_DIR = REPO_ROOT / "experiments" / "targets"
RESULTS_CSV = REPO_ROOT / "data" / "results.csv"

# Add repo root + src/ to sys.path so this script runs from a clean
# checkout without needing PYTHONPATH set externally.
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "src"))

from experiments.run_ablation import (  # noqa: E402
    CONDITIONS, PLANNERS, run_one,
)


def _all_targets() -> list[str]:
    return sorted(p.stem for p in TARGETS_DIR.glob("*.yaml"))


def _reachable(target_url: str) -> bool:
    """Return True if a 5s GET against ``target_url`` succeeds (any
    HTTP response — even a 404 means the host is up)."""
    try:
        req = Request(target_url, headers={"User-Agent": "rc-matrix/0.1"})
        with urlopen(req, timeout=5) as r:
            return r.status < 600
    except URLError:
        return False
    except (socket.timeout, ConnectionError):
        return False
    except Exception:
        return False


def _read_target_url(target_name: str) -> str:
    import yaml  # type: ignore[import-not-found]
    return yaml.safe_load(
        (TARGETS_DIR / f"{target_name}.yaml").read_text()
    )["target"]


def _append(row: dict) -> None:
    RESULTS_CSV.parent.mkdir(parents=True, exist_ok=True)
    new = not RESULTS_CSV.exists()
    with RESULTS_CSV.open("a", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(row.keys()))
        if new:
            w.writeheader()
        w.writerow(row)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    p.add_argument("--target", action="append", default=[],
                   help="target name (repeat for multiple); empty = all")
    p.add_argument("--condition", action="append", default=[],
                   choices=CONDITIONS,
                   help="condition (repeat); empty = all 4")
    p.add_argument("--planner", choices=PLANNERS, default="heuristic")
    p.add_argument("--kali", choices=("off", "fast", "all"),
                   default="off",
                   help="register Kali engines via SSH for every cell.")
    p.add_argument("--seeds", type=int, default=1,
                   help="how many random-order seeds to sample (1..N)")
    p.add_argument("--all", action="store_true",
                   help="sweep every target × condition")
    p.add_argument("--skip-reachability", action="store_true",
                   help="skip the pre-flight reachability check")
    args = p.parse_args(argv)

    targets = args.target or _all_targets()
    conditions = args.condition or list(CONDITIONS)
    if args.all:
        targets = _all_targets()
        conditions = list(CONDITIONS)

    if not args.skip_reachability:
        before = list(targets)
        targets = [
            t for t in targets if _reachable(_read_target_url(t))
        ]
        skipped = sorted(set(before) - set(targets))
        if skipped:
            print(f"[skip] unreachable: {', '.join(skipped)}",
                  file=sys.stderr)
        if not targets:
            print("no reachable targets; aborting", file=sys.stderr)
            return 1

    total = len(targets) * len(conditions) * args.seeds
    print(f"running {total} cell(s): "
          f"{len(targets)} target(s) × {len(conditions)} condition(s) "
          f"× {args.seeds} seed(s) (planner={args.planner})")
    t0 = time.perf_counter()
    n_done = 0
    for target, condition in itertools.product(targets, conditions):
        for seed in range(args.seeds):
            n_done += 1
            try:
                row = run_one(
                    target, condition, seed,
                    planner_name=args.planner,
                    kali_mode=args.kali,
                )
            except Exception as e:
                row = {
                    "target": target, "condition": condition,
                    "planner": args.planner, "kali": args.kali,
                    "seed": seed,
                    "error": f"{type(e).__name__}: {e}",
                }
            row.setdefault("error", "")
            _append(row)
            short = (
                f"  [{n_done}/{total}] {target:14s} {condition:13s} "
                f"seed={seed} "
                f"engines={row.get('engine_count', '?'):>2} "
                f"findings={row.get('findings_count', '?'):>3} "
                f"replans={row.get('replans', '?')}"
            )
            print(short)

    elapsed = time.perf_counter() - t0
    print(f"\ndone in {elapsed:.1f}s → {RESULTS_CSV}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
