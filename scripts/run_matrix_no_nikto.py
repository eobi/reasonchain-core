"""Tier B.2 — run the matrix WITHOUT nikto in the engine pool.

Why: nikto enumerates every endpoint under DVWA's teaching surface
and produces a 2000-finding outlier. To defend the architectural
claim against the "this is just nikto" critique, we re-run the
matrix with nikto excluded from the registered engine pool and
verify that the H1 effect survives. If Wilcoxon p stays < 0.01
on the no-nikto matrix, the architecture's effect cannot be
attributed solely to nikto.

Writes ``data/results_no_nikto.csv`` (separate CSV so the main
matrix data stays intact).

Usage:
    python scripts/run_matrix_no_nikto.py --all
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
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "src"))

from experiments.run_ablation import (  # noqa: E402
    CONDITIONS, PLANNERS, _flags_for, _load_target,
    _make_planner, _rewrite_target_for_kali,
)
from reasonchain import (  # noqa: E402
    AssessmentSpec, Orchestrator, REAL_ENGINES,
)
from reasonchain.annotator import annotate  # noqa: E402


RESULTS_CSV = REPO_ROOT / "data" / "results_no_nikto.csv"
TARGETS_DIR = REPO_ROOT / "experiments" / "targets"


def _all_targets() -> list[str]:
    return sorted(p.stem for p in TARGETS_DIR.glob("*.yaml"))


def _reachable(target_url: str) -> bool:
    try:
        req = Request(target_url, headers={"User-Agent": "rc-no-nikto/0.1"})
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


def _make_orchestrator_no_nikto(flags, planner_name="heuristic"):
    """Same as the main runner but drops the 'nikto' engine from the
    Kali pool before constructing the Orchestrator."""
    from reasonchain.kali_engine import (
        Kali, KaliProfile, build_kali_engines,
    )
    kali = Kali(KaliProfile.from_ini())
    engines = dict(REAL_ENGINES)
    engines.update(build_kali_engines(kali))
    # Tier B.2 surgery: remove nikto.
    engines.pop("nikto", None)
    # Also drop the slow engines that the fast Kali pool excludes,
    # to stay in time-parity with the main matrix.
    for slow in ("nuclei", "sqlmap", "wpscan"):
        engines.pop(slow, None)
    return Orchestrator(
        engines=engines, planner=_make_planner(planner_name),
        flags=flags,
    )


def run_one_no_nikto(target_name: str, condition: str, seed: int) -> dict:
    manifest = _load_target(target_name)
    target_url = _rewrite_target_for_kali(manifest["target"])
    spec = AssessmentSpec(
        target=target_url,
        target_type=manifest["target_type"],
        max_steps=int(manifest.get("max_steps", 25)),
        max_depth=int(manifest.get("max_depth", 3)),
    )
    flags = _flags_for(condition, seed)
    orch = _make_orchestrator_no_nikto(flags)
    t0 = time.perf_counter()
    result = orch.run(spec)
    wall_s = time.perf_counter() - t0
    result.duration_s = wall_s

    sev_counts: dict[str, int] = {}
    for f in result.findings:
        sev_counts[f.severity] = sev_counts.get(f.severity, 0) + 1

    annotated = annotate(result, engines_registry=orch.engines)

    return {
        "target": target_name,
        "condition": condition,
        "planner": "heuristic",
        "kali": "fast-no-nikto",
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
    p.add_argument("--target", action="append", default=[])
    p.add_argument("--condition", action="append", default=[],
                   choices=CONDITIONS)
    p.add_argument("--all", action="store_true")
    p.add_argument("--skip-reachability", action="store_true")
    args = p.parse_args(argv)

    targets = args.target or _all_targets()
    conditions = args.condition or list(CONDITIONS)
    if args.all:
        targets = _all_targets()
        conditions = list(CONDITIONS)

    if not args.skip_reachability:
        before = list(targets)
        targets = [t for t in targets if _reachable(_read_target_url(t))]
        skipped = sorted(set(before) - set(targets))
        if skipped:
            print(f"[skip] unreachable: {', '.join(skipped)}",
                  file=sys.stderr)
        if not targets:
            print("no reachable targets; aborting", file=sys.stderr)
            return 1

    total = len(targets) * len(conditions)
    print(f"no-nikto matrix: {total} cells "
          f"({len(targets)} targets × {len(conditions)} conditions)")
    t0 = time.perf_counter()
    n = 0
    for target, condition in itertools.product(targets, conditions):
        n += 1
        try:
            row = run_one_no_nikto(target, condition, seed=0)
        except Exception as e:
            row = {
                "target": target, "condition": condition,
                "planner": "heuristic", "kali": "fast-no-nikto",
                "seed": 0, "error": f"{type(e).__name__}: {e}",
            }
        row.setdefault("error", "")
        _append(row)
        print(f"  [{n}/{total}] {target:30s} {condition:13s} "
              f"engines={row.get('engine_count', '?'):>2} "
              f"findings={row.get('findings_count', '?'):>3}")

    elapsed = time.perf_counter() - t0
    print(f"\ndone in {elapsed:.1f}s → {RESULTS_CSV}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
