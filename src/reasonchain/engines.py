"""Engine ABI for reasonchain-core.

This module exposes the single abstraction every engine implements:
the ``Engine`` Protocol. Concrete engines live in
``reasonchain.real_engines`` and make real network requests against
live targets. There are no synthetic / mock engines in this repo —
every reported number in the paper is produced by an engine that hit
a live HTTP target.
"""
from __future__ import annotations

from typing import Protocol

from reasonchain.models import EngineResult


class Engine(Protocol):
    """The single contract every engine implements.

    Production extensions (premium engines, SSH-to-Kali wrappers, etc.)
    that live in the private Pentagon repository implement this same
    interface, so reasonchain-core's orchestrator + planner work with
    either pool without code changes.
    """
    name: str
    target_types: set[str]

    def run(self, target: str, facts: dict) -> EngineResult:
        ...
