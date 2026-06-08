"""Real HTTP engines for live web-target evaluation.

These are fresh, MIT-licensed engines written from scratch for the
reasonchain-core repo — NOT ports of Pentagon's proprietary engines.
They use only ``urllib`` (stdlib) so the repo runs without extra deps,
making the live Juice Shop / DVWA experiments reproducible from a
clean Python 3.10+ install.

Each engine implements the ``reasonchain.engines.Engine`` protocol and
is the production engine pool the orchestrator drives in every
ablation run.

Three engines:

  - ``HttpProbe``    — single GET against the target; learns server,
                       content-type, response code, and (best-effort)
                       page title. Cheap recon to feed the planner.
  - ``UrlCrawler``   — pulls hrefs from the seed page, returns same-
                       host URLs in ``facts["urls"]`` (mirrors what
                       katana does in Pentagon, just dumber).
  - ``HeaderVulnCheck`` — reads the seed's headers and emits findings
                       for missing security headers, exposed framework
                       headers (X-Powered-By, Server with version),
                       and common admin/debug paths returning 200.
"""
from __future__ import annotations

import re
import socket
import time
from html.parser import HTMLParser
from typing import Optional
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin, urlparse
from urllib.request import Request, urlopen

from reasonchain.models import EngineResult, Finding


_UA = "reasonchain-core/0.1 (+https://github.com/eobi/reasonchain-core)"
_TIMEOUT_S = 5
_MAX_BODY = 200_000  # cap response body to keep parses bounded


def _fetch(url: str, timeout: float = _TIMEOUT_S) -> tuple[int, dict, str]:
    """Return (status, headers, body) or raise on transport-level error.

    Catches HTTPError so 4xx / 5xx still surface as (status, headers,
    body) rather than blowing up the engine — the response data is
    often the point of interest (admin pages, .git/config dumps, etc.).
    """
    req = Request(url, headers={"User-Agent": _UA, "Accept": "*/*"})
    try:
        with urlopen(req, timeout=timeout) as r:
            headers = {k.lower(): v for k, v in r.headers.items()}
            body = r.read(_MAX_BODY).decode("utf-8", errors="replace")
            return r.status, headers, body
    except HTTPError as e:
        headers = {k.lower(): v for k, v in e.headers.items()} if e.headers else {}
        body = e.read(_MAX_BODY).decode("utf-8", errors="replace") if e.fp else ""
        return e.code, headers, body


class _TitleParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.in_title = False
        self.title: list[str] = []

    def handle_starttag(self, tag: str, attrs):
        if tag.lower() == "title":
            self.in_title = True

    def handle_endtag(self, tag: str):
        if tag.lower() == "title":
            self.in_title = False

    def handle_data(self, data: str):
        if self.in_title:
            self.title.append(data)


class _HrefParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.hrefs: list[str] = []

    def handle_starttag(self, tag: str, attrs):
        if tag.lower() != "a":
            return
        for k, v in attrs:
            if k.lower() == "href" and v:
                self.hrefs.append(v)


def _same_host(seed: str, candidate: str) -> bool:
    a, b = urlparse(seed), urlparse(candidate)
    return (a.netloc or "") == (b.netloc or "") and bool(b.netloc)


# ── Engines ────────────────────────────────────────────────────────────


class HttpProbe:
    """Single GET against the target. Learns banner + content-type."""
    name = "http_probe"
    target_types = {"web_api"}

    def run(self, target: str, facts: dict) -> EngineResult:
        t0 = time.perf_counter()
        findings: list[Finding] = []
        result_facts: dict = {}
        try:
            status, headers, body = _fetch(target)
        except (URLError, socket.timeout, ConnectionError) as e:
            return EngineResult(
                engine=self.name, target=target,
                error=f"unreachable: {e.__class__.__name__}: {e}",
                duration_s=time.perf_counter() - t0,
            )

        server = headers.get("server", "")
        powered = headers.get("x-powered-by", "")
        ctype = headers.get("content-type", "")
        result_facts["http_status"] = status
        result_facts["content_type"] = ctype
        if server:
            result_facts["server_header"] = server
        if powered:
            result_facts["x_powered_by"] = powered

        # Best-effort title.
        title = ""
        if "html" in ctype.lower():
            p = _TitleParser()
            try:
                p.feed(body)
            except Exception:
                pass
            title = " ".join(p.title).strip()
        if title:
            result_facts["page_title"] = title

        findings.append(Finding(
            title=f"HTTP {status} {ctype or 'unknown'} from {target}",
            severity="info", source=self.name,
            evidence={"status": status, "server": server,
                      "x_powered_by": powered, "title": title},
        ))

        # Cheap fingerprint: known-version product strings.
        m = re.match(r"^([A-Za-z0-9_\-]+)[ /]([0-9][0-9A-Za-z.\-]+)", server)
        if m:
            result_facts["tech_versions"] = [{
                "port": 80 if target.startswith("http://") else 443,
                "product": m.group(1).lower(), "version": m.group(2),
            }]

        return EngineResult(
            engine=self.name, target=target, findings=findings,
            facts=result_facts, raw_output=f"{status} {ctype}\n{title}",
            duration_s=time.perf_counter() - t0,
        )


class UrlCrawler:
    """Fetch the seed, parse <a href=>, return same-host URLs.

    Mirrors katana's basic behavior (BFS depth-1) without the heavy
    deps. The planner reads ``facts["urls"]`` to fan out depth-2 picks
    against discovered paths — exactly the F26 mechanism in Pentagon,
    distilled into a single engine here.
    """
    name = "url_crawler"
    target_types = {"web_api"}

    def run(self, target: str, facts: dict) -> EngineResult:
        t0 = time.perf_counter()
        try:
            status, _, body = _fetch(target)
        except (URLError, socket.timeout, ConnectionError) as e:
            return EngineResult(
                engine=self.name, target=target,
                error=f"unreachable: {e.__class__.__name__}: {e}",
                duration_s=time.perf_counter() - t0,
            )

        p = _HrefParser()
        try:
            p.feed(body)
        except Exception:
            pass

        urls: list[str] = []
        seen: set[str] = set()
        for href in p.hrefs:
            full = urljoin(target, href)
            full = full.split("#", 1)[0]
            if full in seen:
                continue
            if not _same_host(target, full):
                continue
            seen.add(full)
            urls.append(full)
            if len(urls) >= 30:
                break

        findings = [Finding(
            title=f"Discovered {len(urls)} same-host endpoint(s)",
            severity="info", source=self.name,
            evidence={"sample_urls": urls[:5], "count": len(urls)},
        )]
        return EngineResult(
            engine=self.name, target=target, findings=findings,
            facts={"urls": urls} if urls else {},
            raw_output=f"crawled {target}; {len(urls)} url(s)",
            duration_s=time.perf_counter() - t0,
        )


class HeaderVulnCheck:
    """Reads facts/headers + probes common sensitive paths.

    Demonstrates fusion: if a prior engine populated ``server_header``
    or ``urls``, this engine works smarter. With fusion off, it falls
    back to the seed target only.
    """
    name = "header_vuln_check"
    target_types = {"web_api"}

    _SENSITIVE_PATHS = (
        "/admin", "/admin/login", "/login", "/.git/config",
        "/.env", "/server-status", "/phpinfo.php", "/robots.txt",
    )

    _MISSING_HEADER_SEVERITY = {
        "content-security-policy": "medium",
        "strict-transport-security": "medium",
        "x-frame-options": "low",
        "x-content-type-options": "low",
    }

    def run(self, target: str, facts: dict) -> EngineResult:
        t0 = time.perf_counter()
        findings: list[Finding] = []
        urls_to_probe: list[str] = list(facts.get("urls") or [])
        urls_to_probe.insert(0, target)

        # Missing-header check on the seed.
        try:
            _, headers, _ = _fetch(target)
        except (URLError, socket.timeout, ConnectionError) as e:
            return EngineResult(
                engine=self.name, target=target,
                error=f"unreachable: {e.__class__.__name__}: {e}",
                duration_s=time.perf_counter() - t0,
            )
        for h, sev in self._MISSING_HEADER_SEVERITY.items():
            if h not in headers:
                findings.append(Finding(
                    title=f"Missing security header: {h}",
                    severity=sev, source=self.name,
                    evidence={"target": target, "header": h},
                ))
        server = headers.get("server", "")
        if server and re.search(r"\d", server):
            findings.append(Finding(
                title=f"Server header discloses version: '{server}'",
                severity="low", source=self.name,
                evidence={"target": target, "server": server},
            ))

        # Sensitive-path probe — only on the seed origin.
        origin = self._origin_of(target)
        for path in self._SENSITIVE_PATHS:
            url = origin + path
            try:
                status, _, body = _fetch(url, timeout=3)
            except (URLError, socket.timeout, ConnectionError):
                continue
            if status == 200 and body.strip():
                findings.append(Finding(
                    title=f"Sensitive path reachable: {url}",
                    severity="medium", source=self.name,
                    evidence={"url": url, "status": status,
                              "body_excerpt": body[:200]},
                ))

        # Re-probe URL list (one per host-path) for 200s on /admin etc.
        for url in urls_to_probe[1:20]:
            if not any(p in url for p in ("admin", "login", "api")):
                continue
            try:
                status, _, _ = _fetch(url, timeout=3)
            except (URLError, socket.timeout, ConnectionError):
                continue
            if status == 200:
                findings.append(Finding(
                    title=f"Probed endpoint reachable: {url}",
                    severity="low", source=self.name,
                    evidence={"url": url, "status": status},
                ))

        return EngineResult(
            engine=self.name, target=target, findings=findings,
            raw_output=(f"probed {len(self._SENSITIVE_PATHS)} sensitive "
                        f"path(s); checked {len(urls_to_probe)} URL(s)"),
            duration_s=time.perf_counter() - t0,
        )

    @staticmethod
    def _origin_of(url: str) -> str:
        p = urlparse(url)
        return f"{p.scheme}://{p.netloc}"


REAL_ENGINES = {
    e.name: e for e in (HttpProbe(), UrlCrawler(), HeaderVulnCheck())
}
