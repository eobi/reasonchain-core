"""ReasonChain — closed-loop LLM architecture for autonomous multi-tool
cybersecurity assessment.

Minimal reference implementation supporting the H1/H2/H3 ablations in
the SRF paper. Every engine in this repository makes real network
requests against live targets; there are no synthetic engines or
synthetic data. Premium engines, commercial integrations, and the
SSH-to-Kali execution layer live in the private Pentagon repository.
"""
from reasonchain.annotator import AnnotatedRun, PickLabel, annotate
from reasonchain.engines import Engine
from reasonchain.facts import Facts
from reasonchain.llm_planner import (
    AnthropicClient, LLMPlanner, OpenAIClient, StubLLMClient,
)
from reasonchain.models import (
    AssessmentResult, AssessmentSpec, DecisionRecord, EngineResult,
    Finding, Pick,
)
from reasonchain.orchestrator import AblationFlags, Orchestrator
from reasonchain.planner import HeuristicPlanner, NullPlanner, Planner
from reasonchain.real_engines import (
    HeaderVulnCheck, HttpProbe, REAL_ENGINES, UrlCrawler,
)
from reasonchain.subprocess_engines import (
    CLI_ENGINES, DirsearchEngine, FeroxbusterEngine, NiktoEngine,
    NmapEngine, NucleiEngine,
)

__version__ = "0.2.0"

__all__ = [
    "AblationFlags",
    "AnnotatedRun",
    "AnthropicClient",
    "AssessmentResult",
    "AssessmentSpec",
    "DecisionRecord",
    "Engine",
    "EngineResult",
    "Facts",
    "Finding",
    "HeaderVulnCheck",
    "HeuristicPlanner",
    "HttpProbe",
    "LLMPlanner",
    "NullPlanner",
    "OpenAIClient",
    "Orchestrator",
    "Pick",
    "PickLabel",
    "Planner",
    "REAL_ENGINES",
    "StubLLMClient",
    "UrlCrawler",
    "annotate",
    # Subprocess engines that wrap real CLI tools
    "CLI_ENGINES",
    "DirsearchEngine",
    "FeroxbusterEngine",
    "NiktoEngine",
    "NmapEngine",
    "NucleiEngine",
]
