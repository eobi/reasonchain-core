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
ablation suite on the bundled mock engines without any LLM calls — so
the repo runs offline and CI tests are deterministic. Production
Pentagon swaps in an LLMPlanner that wraps the model client; that class
lives in the private repo because it carries the production prompts.
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


# Target-type → ordered list of seed engines.
_SEEDS: dict[str, list[str]] = {
    "network": ["mock_portscan", "mock_service_probe"],
    "ip":      ["mock_portscan", "mock_service_probe"],
    "domain":  ["mock_portscan", "mock_service_probe"],
    "web_api": ["mock_crawler", "mock_web_vulnscan"],
}

# Predecessor engine → list of follow-up engines (1-hop heuristic chain).
_CHAINS: dict[str, list[str]] = {
    "mock_portscan":      ["mock_service_probe"],
    "mock_service_probe": ["mock_cve_lookup"],
    "mock_crawler":       ["mock_web_vulnscan"],
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
