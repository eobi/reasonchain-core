"""ReasonChain — closed-loop LLM architecture for autonomous multi-tool
cybersecurity assessment.

Minimal reference implementation supporting the H1/H2/H3 ablations in
the SRF paper. Premium engines, commercial integrations, and the SSH-
to-Kali execution layer live in the private Pentagon repository.
"""
from reasonchain.annotator import AnnotatedRun, PickLabel, annotate
from reasonchain.engines import (
    Engine, MOCK_ENGINES,
    MockPortScanner, MockServiceProbe, MockCveLookup,
    MockUrlCrawler, MockWebVulnScanner,
)
from reasonchain.facts import Facts
from reasonchain.models import (
    AssessmentResult, AssessmentSpec, DecisionRecord, EngineResult,
    Finding, Pick,
)
from reasonchain.orchestrator import AblationFlags, Orchestrator
from reasonchain.planner import HeuristicPlanner, NullPlanner, Planner
from reasonchain.real_engines import (
    HeaderVulnCheck, HttpProbe, REAL_ENGINES, UrlCrawler,
)

__version__ = "0.1.0"

__all__ = [
    "AblationFlags",
    "AnnotatedRun",
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
    "MOCK_ENGINES",
    "MockCveLookup",
    "MockPortScanner",
    "MockServiceProbe",
    "MockUrlCrawler",
    "MockWebVulnScanner",
    "NullPlanner",
    "Orchestrator",
    "Pick",
    "PickLabel",
    "Planner",
    "REAL_ENGINES",
    "UrlCrawler",
    "annotate",
]
