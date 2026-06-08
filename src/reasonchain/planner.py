"""Planner — the LLM (or a heuristic stand-in) that picks the next engines.

The Planner protocol exposes two methods:

- ``plan_initial(spec, available)`` — the seed plan, called once at
  step 0.
- ``replan(spec, completed, last_result, facts, available)`` — called
  after every engine completes IF the orchestrator's ``replanning``
  ablation flag is on. The plan can grow OR shrink (the planner may
  return an empty list when no useful follow-up exists).

We ship a HeuristicPlanner that implements the target-aware seed sets
+ a tiny static chain map. It's enough to run the entire H1/H2/H3
ablation suite against the bundled real HTTP engines, against any
running OWASP-class web target. Production Pentagon swaps in an
LLMPlanner that wraps a richer model client; the architecture is
identical, only the prompt content differs.
"""
from __future__ import annotations

from typing import Protocol

from reasonchain.models import AssessmentSpec, EngineResult, Pick


class Planner(Protocol):
    def plan_initial(
        self, spec: AssessmentSpec, available: list[str],
    ) -> list[Pick]:
        ...

    def replan(
        self, spec: AssessmentSpec, completed: list[str],
        last_result: EngineResult, facts: dict, available: list[str],
    ) -> list[Pick]:
        ...


# Target-type → ordered list of seed engines. The HeuristicPlanner
# picks every entry whose engine is registered in the orchestrator,
# preserving order.
_SEEDS: dict[str, list[str]] = {
    "web_api": ["http_probe", "url_crawler"],
}

# Predecessor engine → list of follow-up engines (1-hop heuristic
# chain). The chain drives the depth-1 picks in the closed-loop
# condition; ablating replanning (H1) cuts this whole map out of
# the run.
_CHAINS: dict[str, list[str]] = {
    "http_probe":  ["url_crawler", "header_vuln_check"],
    "url_crawler": ["header_vuln_check"],
}


class HeuristicPlanner:
    """Static seed + 1-hop chain planner.

    Deliberately small — its job is to give the orchestrator something
    real to drive the closed loop with, not to be smart. The H1/H2/H3
    ablations are about the architecture's BEHAVIOR, not the planner's
    intelligence; for an apples-to-apples comparison the planner has to
    be deterministic.
    """

    def plan_initial(
        self, spec: AssessmentSpec, available: list[str],
    ) -> list[Pick]:
        seeds = _SEEDS.get(spec.target_type, [])
        return [
            Pick(engine=e, target=spec.target,
                 rationale=f"Seed {spec.target_type} recon",
                 depth=0)
            for e in seeds if e in available
        ]

    def replan(
        self, spec: AssessmentSpec, completed: list[str],
        last_result: EngineResult, facts: dict, available: list[str],
    ) -> list[Pick]:
        out: list[Pick] = []
        for nxt in _CHAINS.get(last_result.engine, []):
            if nxt not in available:
                continue
            if nxt in completed:
                # Skip duplicates — the orchestrator also dedups, this
                # is a hint not a guard.
                continue
            out.append(Pick(
                engine=nxt, target=spec.target,
                rationale=f"Heuristic follow-up to {last_result.engine}",
                depth=1,
            ))
        return out


class NullPlanner:
    """No-op planner.

    Used in tests + as a paranoia check: if the orchestrator works with
    a planner that returns nothing, it can't be relying on side effects
    of plan_initial / replan beyond the returned picks.
    """

    def plan_initial(self, spec, available):
        return []

    def replan(self, spec, completed, last_result, facts, available):
        return []
