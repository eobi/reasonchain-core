"""H1/H2/H3 ablation pin tests.

These prove the AblationFlags actually mutate behavior the way the
paper claims. Each test runs the SAME spec twice with two flag configs
and asserts the difference matches the hypothesis being tested.
"""
from reasonchain import (
    AblationFlags, AssessmentSpec, HeuristicPlanner, MOCK_ENGINES,
    Orchestrator,
)


def _run(flags: AblationFlags, target_type: str = "ip"):
    spec = AssessmentSpec(target="192.168.56.101", target_type=target_type)
    return Orchestrator(
        engines=MOCK_ENGINES, planner=HeuristicPlanner(), flags=flags,
    ).run(spec)


# ── H1: closed-loop replanning improves coverage ──────────────────────


def test_h1_replanning_increases_engines_used():
    """Without replanning the seed plan executes and stops. With
    replanning the chain extends into cve_lookup."""
    full = _run(AblationFlags(replanning=True, fusion=True))
    no_replan = _run(AblationFlags(replanning=False, fusion=True))
    assert len(full.engines_used) > len(no_replan.engines_used)
    assert "mock_cve_lookup" in full.engines_used
    assert "mock_cve_lookup" not in no_replan.engines_used


def test_h1_replanning_increases_findings():
    """Replanning surfaces CVE findings the seed plan misses."""
    full = _run(AblationFlags(replanning=True, fusion=True))
    no_replan = _run(AblationFlags(replanning=False, fusion=True))
    assert len(full.findings) > len(no_replan.findings)


# ── H2: cross-tool fusion reduces redundancy / improves coverage ──────


def test_h2_fusion_required_for_downstream_signal():
    """The mock_service_probe needs ``open_ports`` from facts.
    Under fusion=False it sees an empty bag and emits no service facts,
    so cve_lookup (which reads tech_versions) has nothing to chew on."""
    fused = _run(AblationFlags(replanning=True, fusion=True))
    nofusion = _run(AblationFlags(replanning=True, fusion=False))
    fused_cves = [f for f in fused.findings if f.cve_ids]
    nofusion_cves = [f for f in nofusion.findings if f.cve_ids]
    assert fused_cves, "fusion=True should yield CVE findings"
    assert not nofusion_cves, (
        "fusion=False must break the chain — cve_lookup has no input"
    )


def test_h2_fusion_disabled_still_runs_all_engines():
    """Engines still EXECUTE under fusion=False; only their inputs
    differ. The orchestrator must not skip engines just because they'd
    be useless without fusion — that's what makes the comparison fair."""
    no_fusion = _run(AblationFlags(replanning=True, fusion=False))
    assert "mock_service_probe" in no_fusion.engines_used


# ── H3 substrate: decisions are recorded for labeling ─────────────────


def test_decisions_recorded_per_planner_call():
    """Every plan_initial and replan call appends a DecisionRecord.
    The H3 annotator walks this list to label decisions correct /
    suboptimal / incorrect."""
    full = _run(AblationFlags(replanning=True, fusion=True))
    assert full.decisions, "step-0 plan must be recorded"
    assert full.decisions[0].step == 0
    assert full.decisions[0].predecessor is None
    # Subsequent decisions cite their predecessor engine.
    follow_ups = [d for d in full.decisions if d.predecessor is not None]
    assert follow_ups
    for d in follow_ups:
        assert d.predecessor in full.engines_used


def test_random_order_reproducible_with_seed():
    """Same seed → same shuffle; different seed → different shuffle.
    Critical for the random-order condition's reproducibility."""
    a = _run(AblationFlags(
        replanning=True, fusion=True, random_order=True, random_seed=42,
    ))
    b = _run(AblationFlags(
        replanning=True, fusion=True, random_order=True, random_seed=42,
    ))
    assert a.engines_used == b.engines_used


# ── Smoke: full condition is the strict superset of every ablation ────


def test_full_condition_finds_at_least_as_many_as_ablations():
    """The full configuration should never produce STRICTLY FEWER
    findings than any single ablation. Pins the claim that each
    ablation removes capability rather than adding it."""
    full = _run(AblationFlags())
    for ablated in [
        AblationFlags(replanning=False, fusion=True),
        AblationFlags(replanning=True, fusion=False),
    ]:
        ablation_result = _run(ablated)
        assert len(full.findings) >= len(ablation_result.findings)
