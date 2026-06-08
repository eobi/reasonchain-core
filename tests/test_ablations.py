"""H1/H2/H3 ablation pin tests.

Every test runs the bundled REAL_ENGINES against a local stub HTTP
server with two different AblationFlags configurations and asserts
the resulting deltas match the hypothesis under test.

There is no synthetic engine in the test pool: the engines make real
HTTP calls over loopback to the stub server defined in conftest.py.
"""
from reasonchain import (
    AblationFlags, AssessmentSpec, HeuristicPlanner, Orchestrator,
    REAL_ENGINES,
)


def _run(flags: AblationFlags, target: str):
    spec = AssessmentSpec(target=target, target_type="web_api")
    return Orchestrator(
        engines=REAL_ENGINES, planner=HeuristicPlanner(), flags=flags,
    ).run(spec)


# ── H1: closed-loop replanning improves coverage ──────────────────────


def test_h1_replanning_increases_engines_used(stub_server):
    """Without replanning, only the seed pair fires. With replanning,
    the chain extends into header_vuln_check."""
    full = _run(AblationFlags(replanning=True, fusion=True), stub_server)
    no_replan = _run(
        AblationFlags(replanning=False, fusion=True), stub_server,
    )
    assert len(full.engines_used) > len(no_replan.engines_used)
    assert "header_vuln_check" in full.engines_used
    assert "header_vuln_check" not in no_replan.engines_used


def test_h1_replanning_increases_findings(stub_server):
    """Replanning surfaces the medium-severity findings the seed plan
    misses (missing headers, sensitive paths, etc.)."""
    full = _run(AblationFlags(replanning=True, fusion=True), stub_server)
    no_replan = _run(
        AblationFlags(replanning=False, fusion=True), stub_server,
    )
    assert len(full.findings) > len(no_replan.findings)


# ── H2: cross-tool fusion behavior ────────────────────────────────────


def test_h2_no_fusion_still_runs_all_engines(stub_server):
    """Engines still EXECUTE under fusion=False; only their inputs
    differ. The orchestrator must not skip engines just because they'd
    be useless without fusion — that's what makes the comparison fair."""
    no_fusion = _run(
        AblationFlags(replanning=True, fusion=False), stub_server,
    )
    assert "header_vuln_check" in no_fusion.engines_used


def test_h2_full_finds_at_least_as_many_as_no_fusion(stub_server):
    """Full ≥ no-fusion on findings. On the bundled HTTP engines
    these are typically equal (engines are loosely coupled);
    re-running on a fact-coupled engine pool widens the gap."""
    full = _run(AblationFlags(replanning=True, fusion=True), stub_server)
    no_fusion = _run(
        AblationFlags(replanning=True, fusion=False), stub_server,
    )
    assert len(full.findings) >= len(no_fusion.findings)


# ── H3 substrate: decisions are recorded for labeling ─────────────────


def test_decisions_recorded_per_planner_call(stub_server):
    """Every plan_initial and replan call appends a DecisionRecord.
    The H3 annotator walks this list to label decisions correct /
    suboptimal / incorrect."""
    full = _run(AblationFlags(replanning=True, fusion=True), stub_server)
    assert full.decisions, "step-0 plan must be recorded"
    assert full.decisions[0].step == 0
    assert full.decisions[0].predecessor is None
    follow_ups = [d for d in full.decisions if d.predecessor is not None]
    assert follow_ups
    for d in follow_ups:
        assert d.predecessor in full.engines_used


def test_random_order_reproducible_with_seed(stub_server):
    """Same seed → same shuffle; needed for the random-order condition
    to be reproducible."""
    a = _run(AblationFlags(
        replanning=True, fusion=True, random_order=True, random_seed=42,
    ), stub_server)
    b = _run(AblationFlags(
        replanning=True, fusion=True, random_order=True, random_seed=42,
    ), stub_server)
    assert a.engines_used == b.engines_used


def test_full_condition_finds_at_least_as_many_as_ablations(stub_server):
    """The full configuration should never produce STRICTLY FEWER
    findings than any single ablation. Pins the claim that each
    ablation removes capability rather than adding it."""
    full = _run(AblationFlags(), stub_server)
    for ablated in [
        AblationFlags(replanning=False, fusion=True),
        AblationFlags(replanning=True, fusion=False),
    ]:
        ablation_result = _run(ablated, stub_server)
        assert len(full.findings) >= len(ablation_result.findings)
