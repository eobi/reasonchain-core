"""Closed-loop orchestrator + ablation flags.

This is the file that embodies the paper's three claims:

  - **Closed-loop reasoning**: after each engine completes, ``replan()``
    is called (gated by ``AblationFlags.replanning``).
  - **Cross-tool intelligence fusion**: each engine's facts are merged
    into a shared ``Facts`` bag (gated by ``AblationFlags.fusion``).
  - **Target-aware methodology**: ``plan_initial()`` receives the
    target_type, so the planner's seed set is target-aware (the
    HeuristicPlanner makes this explicit; an LLMPlanner would too).

The three ablations are flipped via ``AblationFlags``:

  | flag           | True (default)             | False / ablation                    |
  |----------------|----------------------------|-------------------------------------|
  | replanning     | replan after each engine   | execute initial plan only           |
  | fusion         | shared Facts bag           | each engine gets a fresh empty bag  |
  | random_order   | preserve planner order     | shuffle initial plan                |

random_order is a SEPARATE ablation that tests whether the
target-aware ordering matters. The first three (full, no-replan,
no-fusion) all keep planner-defined order; random_order is its own
condition.
"""
from __future__ import annotations

import random
import time
from dataclasses import dataclass

from reasonchain.engines import Engine
from reasonchain.facts import Facts
from reasonchain.models import (
    AssessmentResult, AssessmentSpec, DecisionRecord, Pick,
)
from reasonchain.planner import Planner


@dataclass
class AblationFlags:
    replanning: bool = True
    fusion: bool = True
    random_order: bool = False
    # Seed for random_order shuffling so per-condition runs are
    # reproducible. Tests + experiments must set this explicitly.
    random_seed: int = 0


class Orchestrator:
    """Drives ``planner`` over ``engines`` against one assessment spec."""

    def __init__(
        self, engines: dict[str, Engine], planner: Planner,
        flags: AblationFlags | None = None,
    ) -> None:
        self.engines = engines
        self.planner = planner
        self.flags = flags or AblationFlags()

    def run(self, spec: AssessmentSpec) -> AssessmentResult:
        result = AssessmentResult(spec=spec)
        facts = Facts()
        completed: list[str] = []
        run_started = time.perf_counter()

        # Step 0 — initial plan.
        plan: list[Pick] = self.planner.plan_initial(
            spec, available=list(self.engines.keys()),
        )
        if self.flags.random_order and plan:
            rng = random.Random(self.flags.random_seed)
            rng.shuffle(plan)
        result.decisions.append(DecisionRecord(
            step=0, predecessor=None, picks=list(plan),
            facts_snapshot_keys=facts.snapshot_keys(),
        ))

        queue: list[Pick] = list(plan)
        step = 0
        while queue:
            step += 1
            if step > spec.max_steps:
                result.aborted = True
                result.abort_reason = (
                    f"max_steps={spec.max_steps} exceeded"
                )
                break

            pick = queue.pop(0)
            if pick.depth > spec.max_depth:
                continue
            if pick.engine in completed:
                continue
            engine = self.engines.get(pick.engine)
            if engine is None:
                continue
            if spec.target_type not in engine.target_types:
                continue

            # FUSION switch: under fusion=False, hand the engine a
            # completely empty facts dict so it can't benefit from
            # anything previous engines learned.
            engine_facts = facts.as_dict() if self.flags.fusion else {}
            engine_result = engine.run(pick.target, engine_facts)
            engine_result.engine = pick.engine

            completed.append(pick.engine)
            result.engines_used.append(pick.engine)
            result.findings.extend(engine_result.findings)

            # Always merge into the shared bag so the orchestrator can
            # observe what was found, even when fusion=False (under
            # fusion=False the merge is irrelevant to future engines
            # because they get an empty dict, but the trace is still
            # the truthful record of what got produced).
            if engine_result.facts:
                facts.merge(engine_result.facts)

            # REPLANNING switch.
            if self.flags.replanning:
                follow_ups = self.planner.replan(
                    spec, completed=list(completed),
                    last_result=engine_result, facts=facts.as_dict(),
                    available=list(self.engines.keys()),
                )
                # New picks inherit pick.depth + 1.
                for f in follow_ups:
                    f.depth = pick.depth + 1
                queue.extend(follow_ups)
                if follow_ups:
                    result.replans += 1
                    result.decisions.append(DecisionRecord(
                        step=step,
                        predecessor=pick.engine,
                        picks=list(follow_ups),
                        facts_snapshot_keys=facts.snapshot_keys(),
                    ))

        result.duration_s = time.perf_counter() - run_started
        return result
