"""Render a single live deep-scan run as a PDF + JSON report.

This is the same kind of artifact Pentagon ships at
``data/audits/assessor/<run_id>/report.pdf``: the full
``AssessmentResult`` with executive summary, severity breakdown, CVE
roll-up, and per-engine findings.

Usage:
    # Assumes a Kali profile at ./kali_profile.ini and labs running.
    python scripts/render_deep_scan.py \\
        --target http://192.168.1.73:3000/ \\
        --name juiceshop_deep
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "src"))

from reasonchain import (  # noqa: E402
    AblationFlags, AssessmentSpec, HeuristicPlanner,
    Orchestrator, REAL_ENGINES, render_both,
)
from reasonchain.kali_engine import (  # noqa: E402
    Kali, KaliProfile, build_kali_engines,
)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    p.add_argument("--target", required=True,
                   help="URL of the live target (must be reachable from Kali).")
    p.add_argument("--name", required=True,
                   help="Stem for the output filenames (e.g. juiceshop_deep).")
    p.add_argument("--out-dir", default="reports",
                   help="Directory under repo root for the artifacts.")
    p.add_argument("--target-type", default="web_api")
    p.add_argument("--max-steps", type=int, default=25)
    p.add_argument("--max-depth", type=int, default=2)
    args = p.parse_args(argv)

    print("Connecting to Kali ...", flush=True)
    kali = Kali(KaliProfile.from_ini())
    engines = {**REAL_ENGINES, **build_kali_engines(kali)}
    print(f"   pool ({len(engines)}): {list(engines.keys())}")
    print()

    spec = AssessmentSpec(
        target=args.target, target_type=args.target_type,
        max_steps=args.max_steps, max_depth=args.max_depth,
    )
    orch = Orchestrator(
        engines=engines, planner=HeuristicPlanner(),
        flags=AblationFlags(),
    )
    print(f"Target: {spec.target}")
    t0 = time.perf_counter()
    result = orch.run(spec)
    result.duration_s = time.perf_counter() - t0

    print(f"{result.duration_s:.0f}s | engines ran: {result.engines_used}")
    print(f"   findings: {len(result.findings)} | "
          f"high+critical: {sum(1 for f in result.findings if f.severity in ('high', 'critical'))}")
    print()

    out_dir = REPO_ROOT / args.out_dir
    stem = out_dir / args.name
    paths = render_both(result, stem)
    print(f"PDF:  {paths['pdf']}")
    print(f"JSON: {paths['json']}")
    kali.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
