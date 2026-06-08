"""Shared knowledge bag — the substrate for Cross-Tool Intelligence Fusion.

Engines merge their learned facts into one Facts() instance; the planner
reads from it on every replan. Under the H2 ablation (FUSION=OFF) the
orchestrator passes each engine a FRESH empty Facts() instead of the
shared one, so cross-tool signal is severed.

Design choices that matter for the paper:

- Lists merge by concatenation + dedup so ``open_ports`` from two
  scanners union instead of overwriting.
- Scalars overwrite (last-writer-wins) — the planner uses the most
  recent reading for things like ``waf_detected``.
- ``snapshot_keys()`` is what the planner reads as the H3 trace input
  so we can record exactly what the planner saw on each call.
"""
from __future__ import annotations

from typing import Any


class Facts:
    """Append-and-merge dict with list-aware semantics."""

    def __init__(self, initial: dict[str, Any] | None = None) -> None:
        self._d: dict[str, Any] = dict(initial or {})

    def merge(self, partial: dict[str, Any]) -> None:
        """Fold ``partial`` into the bag. Lists union, scalars overwrite."""
        for k, v in (partial or {}).items():
            if isinstance(v, list) and isinstance(self._d.get(k), list):
                seen = set()
                merged: list = []
                for item in list(self._d[k]) + list(v):
                    key = repr(item)
                    if key in seen:
                        continue
                    seen.add(key)
                    merged.append(item)
                self._d[k] = merged
            else:
                self._d[k] = v

    def get(self, key: str, default: Any = None) -> Any:
        return self._d.get(key, default)

    def as_dict(self) -> dict[str, Any]:
        """Return a shallow copy. Used when handing facts to engines."""
        return dict(self._d)

    def snapshot_keys(self) -> list[str]:
        return sorted(self._d.keys())

    def __contains__(self, key: str) -> bool:
        return key in self._d

    def __bool__(self) -> bool:
        return bool(self._d)

    def __repr__(self) -> str:
        return f"Facts({self._d!r})"
