"""Orchestrator end-to-end behavior under the default (full) config."""
from reasonchain import (
    AblationFlags, AssessmentSpec, HeuristicPlanner, MOCK_ENGINES,
    Orchestrator,
)


def _full() -> Orchestrator:
    return Orchestrator(
        engines=MOCK_ENGINES, planner=HeuristicPlanner(),
        flags=AblationFlags(),
    )


def test_full_pipeline_runs_seed_plus_chain():
    """Seed (portscan + service_probe) chains into cve_lookup via the
    replan() hook. End state: 3 engines used, CVE findings present."""
    spec = AssessmentSpec(target="192.168.56.101", target_type="ip")
    result = _full().run(spec)
    assert result.engines_used == [
        "mock_portscan", "mock_service_probe", "mock_cve_lookup",
    ]
    cve_findings = [f for f in result.findings if f.cve_ids]
    assert cve_findings, "cve_lookup should surface at least one CVE finding"
    assert any(f.severity == "high" for f in cve_findings)
    # Replans counted — initial plan + one replan after each of 3 engines
    # but cve_lookup's chain is empty, so we expect 2 productive replans.
    assert result.replans == 2


def test_web_api_pipeline_uses_target_aware_seeds():
    spec = AssessmentSpec(
        target="http://localhost:8080/", target_type="web_api",
    )
    result = _full().run(spec)
    # crawler (depth 0) → web_vulnscan (depth 1)
    assert "mock_crawler" in result.engines_used
    assert "mock_web_vulnscan" in result.engines_used
    # No network-side engines fire on web_api spec.
    assert "mock_portscan" not in result.engines_used


def test_engine_target_type_filter():
    """Engines whose target_types don't include the spec's type are
    silently skipped — never run, never break the loop."""
    spec = AssessmentSpec(target="x", target_type="ip")
    result = _full().run(spec)
    assert "mock_crawler" not in result.engines_used


def test_max_steps_abort():
    """A spec with max_steps=1 stops after the first engine even though
    the planner queues follow-ups."""
    spec = AssessmentSpec(
        target="x", target_type="ip", max_steps=1, max_depth=3,
    )
    result = _full().run(spec)
    assert result.aborted is True
    assert len(result.engines_used) <= 1


def test_max_depth_dropped_picks():
    """Picks beyond max_depth get dropped rather than executed."""
    spec = AssessmentSpec(
        target="x", target_type="ip", max_steps=25, max_depth=0,
    )
    result = _full().run(spec)
    # depth=0 picks only — seed engines run, but their depth-1 follow-ups
    # get dropped.
    assert "mock_cve_lookup" not in result.engines_used
