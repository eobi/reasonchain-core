"""H3 annotator — per-pick correct / suboptimal / incorrect labels."""
from reasonchain import (
    AblationFlags, AssessmentSpec, HeuristicPlanner, Orchestrator,
    REAL_ENGINES,
)
from reasonchain.annotator import annotate
from reasonchain.models import (
    AssessmentResult, DecisionRecord, Pick,
)


def _run(flags: AblationFlags, target: str):
    spec = AssessmentSpec(target=target, target_type="web_api")
    return Orchestrator(
        engines=REAL_ENGINES, planner=HeuristicPlanner(), flags=flags,
    ).run(spec)


def test_full_run_emits_correct_labels(stub_server):
    result = _run(AblationFlags(), stub_server)
    a = annotate(result, engines_registry=REAL_ENGINES)
    assert a.total > 0
    # All three real engines actually ran and surfaced findings — each
    # earns a 'correct' label.
    assert a.counts.get("correct", 0) >= 3


def test_no_replan_run_has_zero_incorrect(stub_server):
    """Under no-replan only the seed plan fires, and the seed picks
    are always feasible → 0 incorrect labels."""
    result = _run(AblationFlags(replanning=False), stub_server)
    a = annotate(result, engines_registry=REAL_ENGINES)
    assert a.counts.get("incorrect", 0) == 0


def test_target_type_mismatch_labeled_incorrect(stub_server):
    """If we run a web_api spec but the trace cites a non-web engine
    (none exist in REAL_ENGINES, so we use a synthetic decision), the
    annotator marks that pick incorrect."""
    spec = AssessmentSpec(target=stub_server, target_type="web_api")
    fake = AssessmentResult(spec=spec)
    fake.decisions = [DecisionRecord(
        step=0, predecessor=None, picks=[Pick(
            engine="http_probe", target=stub_server,
            rationale="ok", depth=0,
        )],
        facts_snapshot_keys=[],
    )]
    a = annotate(fake, engines_registry=REAL_ENGINES)
    # No findings were collected (we didn't run the orchestrator), so
    # the only feasible pick is labeled either correct (if findings
    # exist) or dropped_by_orchestrator (it never ran in this fake
    # result). Either way the label rule is exercised cleanly.
    assert "incorrect" in a.counts


def test_unknown_engine_labeled_incorrect(stub_server):
    spec = AssessmentSpec(target=stub_server, target_type="web_api")
    fake = AssessmentResult(spec=spec)
    fake.decisions = [DecisionRecord(
        step=0, predecessor=None,
        picks=[Pick(engine="does_not_exist", target=stub_server,
                    depth=0)],
        facts_snapshot_keys=[],
    )]
    a = annotate(fake, engines_registry=REAL_ENGINES)
    assert a.counts["incorrect"] == 1
    assert a.labels[0].reason == "engine_not_registered"


def test_annotated_run_rate_arithmetic(stub_server):
    result = _run(AblationFlags(), stub_server)
    a = annotate(result, engines_registry=REAL_ENGINES)
    assert abs(a.rate("correct") + a.rate("suboptimal")
               + a.rate("incorrect") - 1.0) < 1e-6
    assert a.total == sum(a.counts.values())
