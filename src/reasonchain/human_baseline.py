"""Human-expert baseline recording schema + CLI.

The SRF paper compares ReasonChain's autonomous runs against a HUMAN
expert performing the same assessment manually. This module:

- Defines the ``HumanBaseline`` dataclass (per-target, per-expert).
- Provides ``record_baseline()`` — a small CLI that writes one
  baseline YAML to ``data/human_baselines/<target>/<expert>.yaml`` so
  the stats notebook can read them alongside ``data/results.csv``.

The format is deliberately minimal so an expert can fill it in 60s
after their assessment without setting up tooling.
"""
from __future__ import annotations

import argparse
import sys
from dataclasses import dataclass, field
from pathlib import Path

import yaml  # type: ignore[import-not-found]


REPO_ROOT = Path(__file__).resolve().parents[2]
BASELINES_DIR = REPO_ROOT / "data" / "human_baselines"


@dataclass
class HumanBaseline:
    """One human expert's record of one assessment."""
    target: str                       # e.g. "juiceshop"
    expert_id: str                    # anonymized ("E01", "E02", ...)
    findings_count: int               # total distinct vuln findings
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    info_count: int = 0
    duration_minutes: float = 0.0
    tools_used: list[str] = field(default_factory=list)
    notes: str = ""

    @classmethod
    def from_yaml(cls, p: Path) -> "HumanBaseline":
        d = yaml.safe_load(p.read_text())
        return cls(**d)

    def to_yaml(self, p: Path) -> None:
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(yaml.safe_dump(self.__dict__, sort_keys=False))


def record_baseline(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    p.add_argument("--target", required=True,
                   help="target manifest stem (e.g. juiceshop)")
    p.add_argument("--expert-id", required=True,
                   help="anonymized expert identifier (E01, E02, ...)")
    p.add_argument("--findings", type=int, required=True,
                   dest="findings_count")
    p.add_argument("--critical", type=int, default=0,
                   dest="critical_count")
    p.add_argument("--high", type=int, default=0, dest="high_count")
    p.add_argument("--medium", type=int, default=0, dest="medium_count")
    p.add_argument("--low", type=int, default=0, dest="low_count")
    p.add_argument("--info", type=int, default=0, dest="info_count")
    p.add_argument("--duration-minutes", type=float, default=0.0)
    p.add_argument("--tools", default="",
                   help="comma-separated list of tools used")
    p.add_argument("--notes", default="")
    args = p.parse_args(argv)

    baseline = HumanBaseline(
        target=args.target, expert_id=args.expert_id,
        findings_count=args.findings_count,
        critical_count=args.critical_count,
        high_count=args.high_count, medium_count=args.medium_count,
        low_count=args.low_count, info_count=args.info_count,
        duration_minutes=args.duration_minutes,
        tools_used=[t.strip() for t in args.tools.split(",") if t.strip()],
        notes=args.notes,
    )
    out = BASELINES_DIR / args.target / f"{args.expert_id}.yaml"
    baseline.to_yaml(out)
    print(f"wrote {out}")
    return 0


def load_all_baselines() -> list[HumanBaseline]:
    """Walk ``data/human_baselines/`` and load every recorded baseline."""
    out: list[HumanBaseline] = []
    if not BASELINES_DIR.exists():
        return out
    for p in sorted(BASELINES_DIR.rglob("*.yaml")):
        try:
            out.append(HumanBaseline.from_yaml(p))
        except Exception as e:
            print(f"warn: {p}: {e}", file=sys.stderr)
    return out


if __name__ == "__main__":
    sys.exit(record_baseline())
