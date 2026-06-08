"""Orchestrator end-to-end behavior under the default (full) config.

Drives the bundled REAL_ENGINES against a session-scoped local stub
HTTP server (see ``conftest.py``). Every assertion is on real engine
output produced by real network I/O over loopback.
"""
from reasonchain import (
    AblationFlags, AssessmentSpec, HeuristicPlanner, Orchestrator,
    REAL_ENGINES,
)


def _full() -> Orchestrator:
    return Orchestrator(
        engines=REAL_ENGINES, planner=HeuristicPlanner(),
        flags=AblationFlags(),
    )


def test_full_pipeline_runs_seed_plus_chain(stub_server):
    """Seed (http_probe + url_crawler) chains into header_vuln_check
    via the replan() hook. End state: 3 engines used, multiple
    medium-severity findings present."""
    spec = AssessmentSpec(target=stub_server, target_type="web_api")
    result = _full().run(spec)
    assert "http_probe" in result.engines_used
    assert "url_crawler" in result.engines_used
    assert "header_vuln_check" in result.engines_used
    medium = [f for f in result.findings if f.severity == "medium"]
    assert medium, "header_vuln_check should surface medium findings"
    # Replans counted — each successful engine's chain triggers one.
    assert result.replans >= 1


def test_full_pipeline_emits_findings_from_each_engine(stub_server):
    spec = AssessmentSpec(target=stub_server, target_type="web_api")
    result = _full().run(spec)
    sources = {f.source for f in result.findings}
    assert "http_probe" in sources
    assert "url_crawler" in sources
    assert "header_vuln_check" in sources


def test_max_steps_abort(stub_server):
    """A spec with max_steps=1 stops after the first engine even though
    the planner queues follow-ups."""
    spec = AssessmentSpec(
        target=stub_server, target_type="web_api",
        max_steps=1, max_depth=3,
    )
    result = _full().run(spec)
    assert result.aborted is True
    assert len(result.engines_used) <= 1


def test_max_depth_dropped_picks(stub_server):
    """Picks beyond max_depth get dropped rather than executed."""
    spec = AssessmentSpec(
        target=stub_server, target_type="web_api",
        max_steps=25, max_depth=0,
    )
    result = _full().run(spec)
    # depth=0 picks (seed pair) only — depth-1 follow-ups are dropped.
    assert "header_vuln_check" not in result.engines_used


def test_facts_merge_across_engines(stub_server):
    """url_crawler writes urls into facts; header_vuln_check then has
    them available — this is the cross-tool fusion path tested by H2."""
    spec = AssessmentSpec(target=stub_server, target_type="web_api")
    result = _full().run(spec)
    # The orchestrator's facts bag is internal, but we can verify the
    # outcome: header_vuln_check produced findings beyond its default
    # path probes, which only happens when it sees crawler URLs.
    assert any("Probed endpoint reachable" in f.title
               or "Sensitive path reachable" in f.title
               for f in result.findings)
