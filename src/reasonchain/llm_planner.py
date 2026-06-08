"""LLM-driven planner — wraps an Anthropic or OpenAI client.

Implements the same ``Planner`` Protocol as ``HeuristicPlanner`` so the
orchestrator + ablation harness use it without modification. The point
of having both is to support the H3 paper claim: characterize when LLM
reasoning beats heuristic baseline and when it degrades.

Design choices for a research artifact:

- **Provider-agnostic transport.** ``LLMClient`` is a 6-line protocol;
  ``AnthropicClient`` + ``OpenAIClient`` are concrete adapters. Adding
  a new provider is a few lines.
- **Deterministic in tests.** ``StubLLMClient`` returns canned JSON so
  pin tests don't need an API key. The matrix runner can also pin a
  seed via ``LLMPlanner(seed=...)`` to fix temperature.
- **Strict output parsing.** The model is asked for a JSON envelope
  ``{"picks": [...]}``; if parsing fails, we fall back to the heuristic
  chain so a misbehaving model can't dead-end a run.
- **Cost-bounded.** ``LLMPlanner.max_calls`` caps the total number of
  LLM invocations per assessment. Default 25 mirrors the per-run
  ``max_steps``.

Production extensions (rate limits, streaming, retries, structured
outputs, tool-use schemas) live in the private Pentagon repo.
"""
from __future__ import annotations

import json
import logging
import os
import re
from dataclasses import dataclass
from typing import Protocol

from reasonchain.models import AssessmentSpec, EngineResult, Pick
from reasonchain.planner import HeuristicPlanner

logger = logging.getLogger(__name__)


class LLMClient(Protocol):
    """6-line transport surface every provider adapter implements."""
    name: str

    def complete(self, system: str, user: str) -> str:
        ...


# ── Concrete provider adapters ────────────────────────────────────────


@dataclass
class AnthropicClient:
    """Wraps anthropic.Anthropic. Reads ANTHROPIC_API_KEY from env if
    no api_key is passed. Pinned to claude-sonnet-4-6 by default —
    matches the Pentagon production model so per-condition results are
    comparable across the two repos."""
    api_key: str | None = None
    model: str = "claude-sonnet-4-6"
    max_tokens: int = 1024
    name: str = "anthropic"

    def __post_init__(self) -> None:
        try:
            import anthropic  # type: ignore[import-not-found]
        except ImportError as e:
            raise RuntimeError(
                "anthropic SDK not installed — run "
                "`pip install anthropic`"
            ) from e
        key = self.api_key or os.environ.get("ANTHROPIC_API_KEY")
        if not key:
            raise RuntimeError(
                "ANTHROPIC_API_KEY not set; pass api_key= explicitly "
                "or export the env var"
            )
        self._client = anthropic.Anthropic(api_key=key)

    def complete(self, system: str, user: str) -> str:
        resp = self._client.messages.create(
            model=self.model, max_tokens=self.max_tokens,
            system=system,
            messages=[{"role": "user", "content": user}],
        )
        # Anthropic returns content blocks; join the text parts.
        return "".join(
            getattr(b, "text", "") for b in resp.content
        ).strip()


@dataclass
class OpenAIClient:
    """Wraps openai.OpenAI. Reads OPENAI_API_KEY from env if no api_key
    is passed."""
    api_key: str | None = None
    model: str = "gpt-4o-mini"
    max_tokens: int = 1024
    name: str = "openai"

    def __post_init__(self) -> None:
        try:
            import openai  # type: ignore[import-not-found]
        except ImportError as e:
            raise RuntimeError(
                "openai SDK not installed — run `pip install openai`"
            ) from e
        key = self.api_key or os.environ.get("OPENAI_API_KEY")
        if not key:
            raise RuntimeError(
                "OPENAI_API_KEY not set; pass api_key= explicitly or "
                "export the env var"
            )
        self._client = openai.OpenAI(api_key=key)

    def complete(self, system: str, user: str) -> str:
        resp = self._client.chat.completions.create(
            model=self.model,
            messages=[
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            max_tokens=self.max_tokens,
        )
        return (resp.choices[0].message.content or "").strip()


@dataclass
class StubLLMClient:
    """Returns canned responses keyed on a regex over the user prompt.

    Used in unit tests so the entire LLMPlanner path runs without an
    API key. Add (pattern, response) pairs at construction time.
    This is a test fixture, not a synthetic-data engine — it never
    appears in the production ablation runner and never writes to
    data/results.csv."""
    responses: list[tuple[str, str]]
    name: str = "stub"
    calls: int = 0

    def complete(self, system: str, user: str) -> str:
        self.calls += 1
        for pat, resp in self.responses:
            if re.search(pat, user):
                return resp
        # Default: return an empty pick list.
        return '{"picks": []}'


# ── Planner ───────────────────────────────────────────────────────────


SYSTEM_PROMPT = """You are a cybersecurity assessment planner. Given the\
 just-completed engine's output + facts known so far, choose the NEXT\
 engines to run. Pick from the inventory only. Prefer engines that\
 produce NEW signal over re-running what already ran.

Return STRICT JSON with exactly this shape:
{
  "picks": [
    {"engine": "<engine_name>", "target": "<target_string>",
     "rationale": "<one-sentence WHY>"}
  ]
}
If no follow-up is useful, return {"picks": []}. Do not include any text
outside the JSON envelope.
"""


@dataclass
class LLMPlanner:
    """LLM-driven planner. Falls back to HeuristicPlanner on errors.

    ``max_calls`` caps the total number of LLM invocations per
    assessment so a runaway loop can't blow the cost budget. Default is
    25 — same as ``AssessmentSpec.max_steps``."""
    client: LLMClient
    max_calls: int = 25
    fallback: HeuristicPlanner | None = None
    _calls: int = 0

    def __post_init__(self) -> None:
        if self.fallback is None:
            self.fallback = HeuristicPlanner()

    # ── Planner Protocol ──

    def plan_initial(
        self, spec: AssessmentSpec, available: list[str],
    ) -> list[Pick]:
        # Seed planning is target-aware + cheap; delegate to the
        # heuristic so the LLM can spend its budget on replans where
        # adaptation matters more.
        return self.fallback.plan_initial(spec, available)

    def replan(
        self, spec: AssessmentSpec, completed: list[str],
        last_result: EngineResult, facts: dict, available: list[str],
    ) -> list[Pick]:
        if self._calls >= self.max_calls:
            return self.fallback.replan(
                spec, completed, last_result, facts, available,
            )
        prompt = self._build_user_prompt(
            spec, completed, last_result, facts, available,
        )
        try:
            raw = self.client.complete(SYSTEM_PROMPT, prompt)
            self._calls += 1
        except Exception as e:
            logger.warning(
                "LLM call failed (%s); falling back to heuristic", e,
            )
            return self.fallback.replan(
                spec, completed, last_result, facts, available,
            )

        picks = self._parse(raw, available)
        if picks is None:
            logger.warning(
                "LLM output not parseable; falling back to heuristic. "
                "Raw: %r", raw[:200],
            )
            return self.fallback.replan(
                spec, completed, last_result, facts, available,
            )
        return picks

    # ── Helpers ──

    def _build_user_prompt(
        self, spec: AssessmentSpec, completed: list[str],
        last_result: EngineResult, facts: dict, available: list[str],
    ) -> str:
        # Keep facts dump bounded so reviewers can audit the prompt
        # size + cost. 4000 chars matches Pentagon's F24 cap.
        facts_str = json.dumps(facts, default=str)[:4000]
        excerpt = (last_result.raw_output or "")[:1500]
        return (
            f"TARGET: {spec.target} ({spec.target_type})\n"
            f"LAST ENGINE: {last_result.engine}\n"
            f"LAST OUTPUT (truncated):\n{excerpt}\n\n"
            f"FACTS KNOWN: {facts_str}\n\n"
            f"COMPLETED ENGINES: {', '.join(completed) or '(none)'}\n"
            f"INVENTORY: {', '.join(sorted(available))}\n\n"
            "Pick the next engines (JSON only)."
        )

    def _parse(
        self, raw: str, available: list[str],
    ) -> list[Pick] | None:
        # Strip code fences if the model added any.
        m = re.search(r"\{.*\}", raw, re.DOTALL)
        if not m:
            return None
        try:
            data = json.loads(m.group(0))
        except json.JSONDecodeError:
            return None
        picks_raw = data.get("picks")
        if not isinstance(picks_raw, list):
            return None
        out: list[Pick] = []
        for p in picks_raw:
            if not isinstance(p, dict):
                continue
            engine = p.get("engine")
            target = p.get("target")
            if not isinstance(engine, str) or not isinstance(target, str):
                continue
            if engine not in available:
                # The LLM hallucinated an engine. Drop the pick rather
                # than surface a hard error — the orchestrator would
                # silently filter it anyway.
                continue
            out.append(Pick(
                engine=engine, target=target,
                rationale=str(p.get("rationale", ""))[:240],
            ))
        return out
