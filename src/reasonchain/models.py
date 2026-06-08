"""Core data models for the ReasonChain reference implementation.

Kept intentionally small. The architecture's three claims (closed-loop,
cross-tool fusion, target-aware) are exercised through these types; if
a paper reviewer can read this file in 60 seconds, the abstraction is
the right size.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal


Severity = Literal["critical", "high", "medium", "low", "info"]

# reasonchain-core ships only web-HTTP engines; the paper's H1/H2/H3
# evaluation runs against OWASP-class deliberately-vulnerable web apps.
# Production extensions (network, ip, domain, ad, k8s, cloud, mobile,
# llm_model, database) live in the private Pentagon repo.
TargetType = Literal["web_api"]


@dataclass
class Finding:
    """One discrete result from an engine run."""
    title: str
    severity: Severity = "info"
    source: str = ""              # engine that emitted this finding
    cve_ids: list[str] = field(default_factory=list)
    evidence: dict[str, Any] = field(default_factory=dict)


@dataclass
class Pick:
    """One LLM-or-heuristic recommendation for the next engine to run."""
    engine: str                   # registered engine name
    target: str                   # the target args to pass to the engine
    rationale: str = ""           # human-readable WHY (cited in paper)
    depth: int = 0                # hops from the seed (0 = initial plan)


@dataclass
class EngineResult:
    """What an engine returns after running."""
    engine: str
    target: str
    findings: list[Finding] = field(default_factory=list)
    # New facts the engine learned (open ports, services, urls, etc.).
    # These get merged into the shared Facts bag under FUSION=ON.
    facts: dict[str, Any] = field(default_factory=dict)
    raw_output: str = ""
    duration_s: float = 0.0
    error: str | None = None


@dataclass
class AssessmentSpec:
    """Inputs for one assessment run."""
    target: str
    target_type: TargetType
    # Hard caps so a misbehaving planner can't loop forever.
    max_steps: int = 25
    max_depth: int = 3


@dataclass
class AssessmentResult:
    """Aggregated output of one assessment run."""
    spec: AssessmentSpec
    findings: list[Finding] = field(default_factory=list)
    engines_used: list[str] = field(default_factory=list)
    duration_s: float = 0.0
    replans: int = 0              # how often the planner was called after step 0
    decisions: list["DecisionRecord"] = field(default_factory=list)
    aborted: bool = False
    abort_reason: str | None = None


@dataclass
class DecisionRecord:
    """One planner call's input + output. Drives H3 (failure-mode taxonomy)."""
    step: int
    predecessor: str | None       # engine that just finished (None for initial plan)
    picks: list[Pick]
    facts_snapshot_keys: list[str]
    # Filled in post-hoc by the H3 annotator (correct / suboptimal / incorrect).
    quality_label: str | None = None
