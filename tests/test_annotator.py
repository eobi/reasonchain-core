"""H3 annotator — per-pick correct / suboptimal / incorrect labels."""
from reasonchain import (
    AblationFlags, AssessmentSpec, HeuristicPlanner, MOCK_ENGINES,
    Orchestrator,
)
from reasonchain.annotator import annotate


def _run(flags: AblationFlags, target_type: str = "ip"):
    spec = AssessmentSpec(target="x", target_type=target_type)
    return Orchestrator(
        engines=MOCK_ENGINES, planner=HeuristicPlanner(), flags=flags,
    ).run(spec)


def test_full_run_has_mostly_correct_labels():
    result = _run(AblationFlags())
    a = annotate(result, engines_registry=MOCK_ENGINES)
    assert a.total > 0
    # Three engines actually ran and each surfaced findings → 3 correct.
    assert a.counts.get("correct", 0) >= 3
    # The HeuristicPlanner re-emits service_probe at step 1 because
    # the chain is "portscan → service_probe" but service_probe was
    # also in the initial seed plan. The annotator correctly catches
    # that as duplicate_of_completed. This is desirable behavior —
    # H3's whole point is to surface failure modes like this.
    incorrect_reasons = [
        l.reason for l in a.labels if l.label == "incorrect"
    ]
    assert all("duplicate" in r for r in incorrect_reasons), (
        f"unexpected incorrect reasons: {incorrect_reasons}"
    )


def test_no_fusion_run_increases_suboptimal_or_incorrect():
    """Under no-fusion, the cve_lookup pick still gets queued but the
    engine produces no new facts (the chain is broken upstream) — that
    pick lands as suboptimal."""
    full = annotate(_run(AblationFlags()), engines_registry=MOCK_ENGINES)
    no_fusion = annotate(
        _run(AblationFlags(fusion=False)),
        engines_registry=MOCK_ENGINES,
    )
    full_subopt = full.counts.get("suboptimal", 0)
    nf_subopt = no_fusion.counts.get("suboptimal", 0)
    assert nf_subopt > full_subopt


def test_target_type_mismatch_labeled_incorrect():
    """If we run a web_api spec but the trace cites a network-only
    engine, the annotator marks that pick incorrect."""
    from reasonchain.models import (
        AssessmentResult, AssessmentSpec, DecisionRecord, Pick,
    )
    spec = AssessmentSpec(target="http://x/", target_type="web_api")
    fake = AssessmentResult(spec=spec)
    fake.decisions = [DecisionRecord(
        step=0, predecessor=None, picks=[Pick(
            engine="mock_portscan", target="http://x/",
            rationale="confused planner", depth=0,
        )],
        facts_snapshot_keys=[],
    )]
    a = annotate(fake, engines_registry=MOCK_ENGINES)
    assert a.counts.get("incorrect") == 1
    assert "target_type_mismatch" in a.labels[0].reason


def test_unknown_engine_labeled_incorrect():
    from reasonchain.models import (
        AssessmentResult, AssessmentSpec, DecisionRecord, Pick,
    )
    spec = AssessmentSpec(target="x", target_type="ip")
    fake = AssessmentResult(spec=spec)
    fake.decisions = [DecisionRecord(
        step=0, predecessor=None,
        picks=[Pick(engine="does_not_exist", target="x", depth=0)],
        facts_snapshot_keys=[],
    )]
    a = annotate(fake, engines_registry=MOCK_ENGINES)
    assert a.counts["incorrect"] == 1
    assert a.labels[0].reason == "engine_not_registered"


def test_annotated_run_rate_arithmetic():
    result = _run(AblationFlags())
    a = annotate(result, engines_registry=MOCK_ENGINES)
    total = a.total
    assert abs(a.rate("correct") + a.rate("suboptimal")
               + a.rate("incorrect") - 1.0) < 1e-6
    assert total == sum(a.counts.values())
