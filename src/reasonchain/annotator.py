"""H3 decision-quality annotator.

H3 hypothesis: "LLM reasoning degrades predictably."

To test this, we need a labeling rule that assigns one of three labels
to every ``DecisionRecord.picks[i]`` produced during a run:

  - ``correct``    — the pick was sound and yielded NEW signal
                     (added facts, surfaced findings, or unlocked a
                     downstream chain).
  - ``suboptimal`` — the pick was valid but redundant: the engine ran
                     but produced no new facts AND no findings
                     (wasted budget without breaking anything).
  - ``incorrect``  — the pick was infeasible from the start: target_type
                     mismatch, engine missing from the registry,
                     duplicate of an already-completed pick, or exceeded
                     the depth budget.

This labeling is intentionally **conservative + heuristic**, not LLM-
judged. The H3 paper claim is about CHARACTERIZING failure modes, not
inventing a new LLM judge — and a heuristic labeler keeps the labels
deterministic across re-runs so per-condition comparisons are fair.

Returns an ``AnnotatedRun`` with the original result + a parallel list
of per-pick label dicts, plus aggregate counts ready for confusion-
matrix plotting in the stats notebook.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from reasonchain.models import AssessmentResult, Pick


@dataclass
class PickLabel:
    decision_step: int
    pick_index: int
    engine: str
    target: str
    label: str          # "correct" | "suboptimal" | "incorrect"
    reason: str         # short, machine-parseable WHY


@dataclass
class AnnotatedRun:
    result: AssessmentResult
    labels: list[PickLabel] = field(default_factory=list)
    counts: dict[str, int] = field(default_factory=dict)

    @property
    def total(self) -> int:
        return sum(self.counts.values())

    def rate(self, label: str) -> float:
        return self.counts.get(label, 0) / self.total if self.total else 0.0


def annotate(
    result: AssessmentResult,
    engines_registry: dict | None = None,
) -> AnnotatedRun:
    """Label every pick in ``result.decisions``.

    Walks decisions in temporal order. For each pick we check four
    feasibility conditions first (engine registered, target_type match,
    depth budget, not a duplicate of an already-completed engine). If a
    pick passes all four and actually executed, we check whether the
    engine surfaced at least one finding (counted from ``result.findings``
    via ``source``). Findings ⇒ correct; no findings ⇒ suboptimal.

    ``engines_registry`` is optional. When None, the
    ``engine_not_registered`` and ``target_type_mismatch`` checks are
    skipped (handy for synthetic test fixtures).
    """
    findings_by_source: dict[str, int] = {}
    for f in result.findings:
        findings_by_source[f.source] = findings_by_source.get(f.source, 0) + 1

    spec = result.spec
    run_engines_used: set[str] = set(result.engines_used)
    completed_so_far: set[str] = set()
    out: list[PickLabel] = []

    for decision in result.decisions:
        for idx, pick in enumerate(decision.picks):
            label, reason = _label_pick(
                pick=pick, completed=completed_so_far,
                spec=spec, engines_registry=engines_registry,
                findings_by_source=findings_by_source,
                run_engines_used=run_engines_used,
            )
            out.append(PickLabel(
                decision_step=decision.step, pick_index=idx,
                engine=pick.engine, target=pick.target,
                label=label, reason=reason,
            ))
            if pick.engine in run_engines_used:
                completed_so_far.add(pick.engine)

    counts: dict[str, int] = {}
    for lbl in out:
        counts[lbl.label] = counts.get(lbl.label, 0) + 1
    return AnnotatedRun(result=result, labels=out, counts=counts)


def _label_pick(
    *, pick: Pick, completed: set[str], spec,
    engines_registry: dict | None,
    findings_by_source: dict[str, int],
    run_engines_used: set[str],
) -> tuple[str, str]:
    """Single-pick label rule. Cheap to read; cheaper to audit."""
    if engines_registry is not None and pick.engine not in engines_registry:
        return "incorrect", "engine_not_registered"

    if engines_registry is not None:
        eng = engines_registry[pick.engine]
        target_types = getattr(eng, "target_types", set())
        if spec.target_type not in target_types:
            return "incorrect", "target_type_mismatch"

    if pick.depth > spec.max_depth:
        return "incorrect", "exceeded_max_depth"

    if pick.engine in completed:
        return "incorrect", "duplicate_of_completed"

    if pick.engine not in run_engines_used:
        # Pick was queued but never executed — orchestrator dropped it
        # (depth filter, max_steps, target_type filter). The planner
        # emitted something the orchestrator wouldn't accept, so from
        # the planner's perspective this is an incorrect decision.
        return "incorrect", "dropped_by_orchestrator"

    n_findings = findings_by_source.get(pick.engine, 0)
    if n_findings > 0:
        return "correct", f"surfaced_{n_findings}_finding(s)"
    return "suboptimal", "ran_but_no_findings"
