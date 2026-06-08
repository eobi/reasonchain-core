"""Engine ABI + a small bundle of mock engines.

The Engine protocol is the only contract this repo expects engines to
honor. Production Pentagon plugs in real engines (nmap, nuclei,
feroxbuster, …) by implementing the same interface and registering them.

The bundled MOCK_ENGINES below let the entire pipeline (closed loop +
fusion + ablations) run with zero external dependencies. They're enough
to demonstrate the architecture's behavior in unit tests and reviewer
smoke tests. Real-engine harnesses for HackTheBox / VulnHub / DVWA live
in the ``experiments/`` directory.
"""
from __future__ import annotations

import time
from typing import Protocol

from reasonchain.models import EngineResult, Finding


class Engine(Protocol):
    """Anything with this shape can be used by the orchestrator."""
    name: str
    target_types: set[str]

    def run(self, target: str, facts: dict) -> EngineResult:
        ...


# ── Mock engines ──────────────────────────────────────────────────────


class MockPortScanner:
    """Always finds the same fake ports on any host target.

    Demonstrates: an engine that produces FACTS the downstream engines
    will need (``open_ports``).
    """
    name = "mock_portscan"
    target_types = {"network", "ip", "domain"}

    def run(self, target: str, facts: dict) -> EngineResult:
        t0 = time.perf_counter()
        return EngineResult(
            engine=self.name, target=target,
            findings=[Finding(
                title=f"Open ports on {target}",
                severity="info", source=self.name,
                evidence={"ports": [22, 80, 443]},
            )],
            facts={"open_ports": [22, 80, 443]},
            raw_output=f"22/tcp open\n80/tcp open\n443/tcp open\n",
            duration_s=time.perf_counter() - t0,
        )


class MockServiceProbe:
    """Reads ``open_ports`` from facts and emits service-version facts.

    Demonstrates Cross-Tool Intelligence Fusion: this engine produces
    nothing useful if ``open_ports`` isn't in facts (i.e., under the
    FUSION=OFF ablation it sees an empty Facts() and yields no
    services).
    """
    name = "mock_service_probe"
    target_types = {"network", "ip", "domain"}

    _DB = {22: ("openssh", "8.9p1"), 80: ("nginx", "1.18.0"),
           443: ("nginx", "1.18.0")}

    def run(self, target: str, facts: dict) -> EngineResult:
        t0 = time.perf_counter()
        ports = facts.get("open_ports") or []
        tech: list[dict] = []
        findings: list[Finding] = []
        for p in ports:
            row = self._DB.get(p)
            if not row:
                continue
            product, version = row
            tech.append({"port": p, "product": product, "version": version})
            findings.append(Finding(
                title=f"{product} {version} on port {p}",
                severity="info", source=self.name,
                evidence={"port": p, "product": product, "version": version},
            ))
        return EngineResult(
            engine=self.name, target=target, findings=findings,
            facts={"tech_versions": tech} if tech else {},
            raw_output=f"probed {len(ports)} port(s), found {len(tech)} service(s)",
            duration_s=time.perf_counter() - t0,
        )


class MockCveLookup:
    """Reads ``tech_versions`` and emits CVE findings.

    Demonstrates the full closed-loop chain: portscan → service probe →
    cve_lookup. Drops to zero findings if fusion is broken upstream.
    """
    name = "mock_cve_lookup"
    target_types = {"network", "ip", "domain", "web_api"}

    _CVES = {
        ("openssh", "8.9p1"): [("CVE-2023-38408", "high")],
        ("nginx", "1.18.0"): [("CVE-2021-23017", "high"),
                              ("CVE-2022-41741", "medium")],
    }

    def run(self, target: str, facts: dict) -> EngineResult:
        t0 = time.perf_counter()
        tech = facts.get("tech_versions") or []
        findings: list[Finding] = []
        for row in tech:
            key = (row.get("product"), row.get("version"))
            for cve, sev in self._CVES.get(key, []):
                findings.append(Finding(
                    title=f"{cve} affects {key[0]} {key[1]}",
                    severity=sev, source=self.name, cve_ids=[cve],
                    evidence={"target_product": key[0], "target_version": key[1]},
                ))
        return EngineResult(
            engine=self.name, target=target, findings=findings,
            raw_output=f"checked {len(tech)} product(s), {len(findings)} CVE hit(s)",
            duration_s=time.perf_counter() - t0,
        )


class MockUrlCrawler:
    """Web-side analogue: discovers fake URLs for ``web_api`` runs."""
    name = "mock_crawler"
    target_types = {"web_api"}

    def run(self, target: str, facts: dict) -> EngineResult:
        t0 = time.perf_counter()
        urls = [f"{target.rstrip('/')}/admin",
                f"{target.rstrip('/')}/api/v1/users",
                f"{target.rstrip('/')}/uploads"]
        return EngineResult(
            engine=self.name, target=target,
            findings=[Finding(
                title=f"Discovered {len(urls)} endpoint(s) under {target}",
                severity="info", source=self.name,
                evidence={"urls": urls},
            )],
            facts={"urls": urls},
            raw_output="\n".join(urls),
            duration_s=time.perf_counter() - t0,
        )


class MockWebVulnScanner:
    """Reads ``urls`` and emits web vuln findings per discovered URL."""
    name = "mock_web_vulnscan"
    target_types = {"web_api"}

    def run(self, target: str, facts: dict) -> EngineResult:
        t0 = time.perf_counter()
        urls = facts.get("urls") or [target]
        findings: list[Finding] = []
        for u in urls:
            if u.endswith("/admin"):
                findings.append(Finding(
                    title=f"Admin endpoint reachable: {u}",
                    severity="medium", source=self.name,
                    evidence={"url": u},
                ))
            if "/api/" in u:
                findings.append(Finding(
                    title=f"Unauthenticated API endpoint: {u}",
                    severity="high", source=self.name,
                    evidence={"url": u},
                ))
        return EngineResult(
            engine=self.name, target=target, findings=findings,
            raw_output=f"scanned {len(urls)} url(s)",
            duration_s=time.perf_counter() - t0,
        )


MOCK_ENGINES: dict[str, Engine] = {
    e.name: e for e in (
        MockPortScanner(), MockServiceProbe(), MockCveLookup(),
        MockUrlCrawler(), MockWebVulnScanner(),
    )
}
