"""LLMPlanner — provider-agnostic + offline-testable.

Uses StubLLMClient (a test double that returns canned JSON) so the
LLMPlanner code path runs without an API key in CI. The engines in
the orchestrator are the same REAL_ENGINES used in production runs.
"""
import pytest

from reasonchain import (
    AblationFlags, AssessmentSpec, Orchestrator, REAL_ENGINES,
)
from reasonchain.llm_planner import LLMPlanner, StubLLMClient
from reasonchain.models import EngineResult


def test_planner_parses_llm_json_into_picks(stub_server):
    client = StubLLMClient(responses=[
        (r"LAST ENGINE: http_probe",
         '{"picks": [{"engine": "url_crawler", "target": "X", '
         '"rationale": "crawl for endpoints"}]}'),
    ])
    planner = LLMPlanner(client=client)
    spec = AssessmentSpec(target=stub_server, target_type="web_api")
    picks = planner.replan(
        spec=spec, completed=["http_probe"],
        last_result=EngineResult(engine="http_probe", target=stub_server),
        facts={"http_status": 200},
        available=list(REAL_ENGINES.keys()),
    )
    assert len(picks) == 1
    assert picks[0].engine == "url_crawler"
    assert "crawl" in picks[0].rationale


def test_planner_falls_back_to_heuristic_on_unparseable_json(stub_server):
    client = StubLLMClient(responses=[
        (r"LAST ENGINE: http_probe", "not even close to JSON"),
    ])
    planner = LLMPlanner(client=client)
    spec = AssessmentSpec(target=stub_server, target_type="web_api")
    picks = planner.replan(
        spec=spec, completed=["http_probe"],
        last_result=EngineResult(engine="http_probe", target=stub_server),
        facts={}, available=list(REAL_ENGINES.keys()),
    )
    # HeuristicPlanner.replan for http_probe suggests url_crawler +
    # header_vuln_check via the chain map.
    assert any(p.engine == "url_crawler" for p in picks)


def test_planner_drops_hallucinated_engines(stub_server):
    client = StubLLMClient(responses=[
        (r"LAST ENGINE: http_probe",
         '{"picks": [{"engine": "this_engine_does_not_exist", '
         '"target": "X", "rationale": "vibes"}]}'),
    ])
    planner = LLMPlanner(client=client)
    spec = AssessmentSpec(target=stub_server, target_type="web_api")
    picks = planner.replan(
        spec=spec, completed=["http_probe"],
        last_result=EngineResult(engine="http_probe", target=stub_server),
        facts={}, available=list(REAL_ENGINES.keys()),
    )
    assert picks == []
    assert client.calls == 1


def test_planner_respects_max_calls_budget(stub_server):
    client = StubLLMClient(responses=[
        (r".*",
         '{"picks": [{"engine": "url_crawler", "target": "X", '
         '"rationale": "x"}]}'),
    ])
    planner = LLMPlanner(client=client, max_calls=1)
    spec = AssessmentSpec(target=stub_server, target_type="web_api")
    last = EngineResult(engine="http_probe", target=stub_server)
    available = list(REAL_ENGINES.keys())
    planner.replan(spec, ["http_probe"], last, {}, available)
    planner.replan(spec, ["http_probe"], last, {}, available)
    planner.replan(spec, ["http_probe"], last, {}, available)
    # max_calls=1 → the LLM client is hit at most once.
    assert client.calls == 1


def test_planner_in_full_orchestrator_run(stub_server):
    """End-to-end: build an orchestrator with LLMPlanner + StubLLMClient
    and verify it drives the closed loop through to header_vuln_check.
    Regex anchors on LAST ENGINE: so each replan matches its own
    prompt and not the prior one."""
    client = StubLLMClient(responses=[
        (r"LAST ENGINE: http_probe",
         '{"picks": [{"engine": "url_crawler", "target": "'
         + stub_server + '", "rationale": "crawl"}]}'),
        (r"LAST ENGINE: url_crawler",
         '{"picks": [{"engine": "header_vuln_check", "target": "'
         + stub_server + '", "rationale": "check headers"}]}'),
        (r"LAST ENGINE: header_vuln_check", '{"picks": []}'),
    ])
    planner = LLMPlanner(client=client)
    spec = AssessmentSpec(target=stub_server, target_type="web_api")
    orch = Orchestrator(
        engines=REAL_ENGINES, planner=planner, flags=AblationFlags(),
    )
    result = orch.run(spec)
    assert "header_vuln_check" in result.engines_used
    assert client.calls >= 1


def test_anthropic_client_requires_sdk():
    """Constructor surfaces a clean RuntimeError when the SDK is
    missing or no API key is in env."""
    from reasonchain.llm_planner import AnthropicClient
    try:
        import anthropic  # noqa: F401
        has_sdk = True
    except ImportError:
        has_sdk = False

    if has_sdk:
        import os
        key = os.environ.pop("ANTHROPIC_API_KEY", None)
        try:
            with pytest.raises(RuntimeError, match="ANTHROPIC_API_KEY"):
                AnthropicClient()
        finally:
            if key:
                os.environ["ANTHROPIC_API_KEY"] = key
    else:
        with pytest.raises(RuntimeError, match="anthropic"):
            AnthropicClient()
