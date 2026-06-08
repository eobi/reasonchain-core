"""LLMPlanner — provider-agnostic + offline-testable."""
import pytest

from reasonchain import (
    AblationFlags, AssessmentSpec, MOCK_ENGINES, Orchestrator,
)
from reasonchain.llm_planner import LLMPlanner, MockLLMClient
from reasonchain.models import EngineResult


def test_planner_parses_llm_json_into_picks():
    client = MockLLMClient(responses=[
        (r"mock_portscan",
         '{"picks": [{"engine": "mock_service_probe", "target": "x", '
         '"rationale": "fingerprint open ports"}]}'),
    ])
    planner = LLMPlanner(client=client)
    spec = AssessmentSpec(target="x", target_type="ip")
    picks = planner.replan(
        spec=spec, completed=["mock_portscan"],
        last_result=EngineResult(engine="mock_portscan", target="x"),
        facts={"open_ports": [80, 443]},
        available=list(MOCK_ENGINES.keys()),
    )
    assert len(picks) == 1
    assert picks[0].engine == "mock_service_probe"
    assert "fingerprint" in picks[0].rationale


def test_planner_falls_back_to_heuristic_on_unparseable_json():
    client = MockLLMClient(responses=[
        (r"mock_portscan", "not even close to JSON"),
    ])
    planner = LLMPlanner(client=client)
    spec = AssessmentSpec(target="x", target_type="ip")
    picks = planner.replan(
        spec=spec, completed=["mock_portscan"],
        last_result=EngineResult(engine="mock_portscan", target="x"),
        facts={}, available=list(MOCK_ENGINES.keys()),
    )
    # HeuristicPlanner.replan for mock_portscan suggests mock_service_probe.
    assert any(p.engine == "mock_service_probe" for p in picks)


def test_planner_drops_hallucinated_engines():
    client = MockLLMClient(responses=[
        (r"mock_portscan",
         '{"picks": [{"engine": "this_engine_does_not_exist", '
         '"target": "x", "rationale": "vibes"}]}'),
    ])
    planner = LLMPlanner(client=client)
    spec = AssessmentSpec(target="x", target_type="ip")
    picks = planner.replan(
        spec=spec, completed=["mock_portscan"],
        last_result=EngineResult(engine="mock_portscan", target="x"),
        facts={}, available=list(MOCK_ENGINES.keys()),
    )
    assert picks == []
    # Mock client still got called once (we didn't fall back this time).
    assert client.calls == 1


def test_planner_respects_max_calls_budget():
    client = MockLLMClient(responses=[
        (r".*",
         '{"picks": [{"engine": "mock_service_probe", "target": "x", '
         '"rationale": "x"}]}'),
    ])
    planner = LLMPlanner(client=client, max_calls=1)
    spec = AssessmentSpec(target="x", target_type="ip")
    last = EngineResult(engine="mock_portscan", target="x")
    available = list(MOCK_ENGINES.keys())
    planner.replan(spec, ["mock_portscan"], last, {}, available)
    planner.replan(spec, ["mock_portscan"], last, {}, available)
    planner.replan(spec, ["mock_portscan"], last, {}, available)
    # max_calls=1 → the LLM client should have been hit at most once;
    # subsequent calls go to the heuristic fallback.
    assert client.calls == 1


def test_planner_in_full_orchestrator_run():
    """End-to-end: build an orchestrator with LLMPlanner + MockLLMClient
    and verify it drives the closed loop through to cve_lookup. Regex
    anchors on "LAST ENGINE: …" so each replan matches its own prompt
    and not the one before it (the predecessor's name also appears in
    later prompts under "COMPLETED ENGINES:")."""
    client = MockLLMClient(responses=[
        (r"LAST ENGINE: mock_portscan",
         '{"picks": [{"engine": "mock_service_probe", "target": "x", '
         '"rationale": "fingerprint"}]}'),
        (r"LAST ENGINE: mock_service_probe",
         '{"picks": [{"engine": "mock_cve_lookup", "target": "x", '
         '"rationale": "search NVD"}]}'),
        (r"LAST ENGINE: mock_cve_lookup", '{"picks": []}'),
    ])
    planner = LLMPlanner(client=client)
    spec = AssessmentSpec(target="x", target_type="ip")
    orch = Orchestrator(
        engines=MOCK_ENGINES, planner=planner, flags=AblationFlags(),
    )
    result = orch.run(spec)
    assert "mock_cve_lookup" in result.engines_used
    assert client.calls >= 1


def test_anthropic_client_requires_sdk():
    """Without the anthropic SDK installed (or env var), constructor
    raises a clean RuntimeError rather than crashing later."""
    from reasonchain.llm_planner import AnthropicClient
    try:
        import anthropic  # noqa: F401
        has_sdk = True
    except ImportError:
        has_sdk = False

    if has_sdk:
        # SDK present: missing key should raise.
        import os
        key = os.environ.pop("ANTHROPIC_API_KEY", None)
        try:
            with pytest.raises(RuntimeError, match="ANTHROPIC_API_KEY"):
                AnthropicClient()
        finally:
            if key:
                os.environ["ANTHROPIC_API_KEY"] = key
    else:
        # SDK absent: clear ImportError-style message.
        with pytest.raises(RuntimeError, match="anthropic"):
            AnthropicClient()
