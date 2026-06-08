"""Subprocess engines — wrap real CLI security tools.

Each engine here invokes an actual binary on $PATH (nmap, nuclei,
feroxbuster, dirsearch, nikto, sqlmap, dalfox, wpscan) and parses its
output into findings. If the binary is missing on this host, ``run()``
returns an ``EngineResult`` with ``error="binary_not_available"`` —
the orchestrator treats that as a skip, not a crash.

These engines do real work: nmap actually scans ports, nuclei actually
fires its template library, feroxbuster actually content-discovers.
The findings come from the tools' own parsing logic, not from
hand-rolled regex over response bodies.

For tools not installed locally, see ``reasonchain.kali_engine`` for
the SSH-to-Kali wrapper that runs the same engines on a remote host.
"""
from __future__ import annotations

import json
import re
import shlex
import shutil
import subprocess
import time
from urllib.parse import urlparse

from reasonchain.models import EngineResult, Finding


_TIMEOUT_S = 120


def _which(name: str) -> str | None:
    return shutil.which(name)


def _exec(cmd: list[str], timeout_s: int = _TIMEOUT_S) -> tuple[int, str, str]:
    """Run ``cmd`` synchronously; return (rc, stdout, stderr)."""
    try:
        p = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout_s,
            check=False,
        )
        return p.returncode, p.stdout, p.stderr
    except subprocess.TimeoutExpired as e:
        return 124, e.stdout or "", e.stderr or ""
    except FileNotFoundError:
        return 127, "", "binary not found"


def _host_of(url_or_host: str) -> str:
    p = urlparse(url_or_host)
    return p.netloc or p.path.split("/")[0]


# ── nmap ──────────────────────────────────────────────────────────────


class NmapEngine:
    """Wraps `nmap -sV -T4 --host-timeout 30s <host>` and parses the
    `open` port lines + service version banners."""
    name = "nmap"
    target_types = {"web_api"}
    binary = "nmap"

    def run(self, target: str, facts: dict) -> EngineResult:
        t0 = time.perf_counter()
        if not _which(self.binary):
            return EngineResult(
                engine=self.name, target=target,
                error="binary_not_available",
                duration_s=time.perf_counter() - t0,
            )
        host = _host_of(target)
        cmd = [self.binary, "-sV", "-T4", "--host-timeout", "30s",
               "-Pn", host]
        rc, stdout, stderr = _exec(cmd, timeout_s=90)
        findings: list[Finding] = []
        tech_versions: list[dict] = []
        open_ports: list[int] = []
        # Lines like: "3000/tcp open  ppp     Node.js Express framework"
        line_re = re.compile(
            r"^(\d+)/tcp\s+(open)\s+(\S+)(?:\s+(.+))?$"
        )
        for line in stdout.splitlines():
            m = line_re.match(line.strip())
            if not m:
                continue
            port = int(m.group(1))
            service = m.group(3)
            version = (m.group(4) or "").strip()
            open_ports.append(port)
            tech_versions.append({
                "port": port, "product": service,
                "version": version or "unknown",
            })
            findings.append(Finding(
                title=f"Open port {port}/tcp · {service} · {version or '?'}",
                severity="info", source=self.name,
                evidence={"port": port, "service": service,
                          "version": version, "host": host},
            ))
        return EngineResult(
            engine=self.name, target=target, findings=findings,
            facts={"open_ports": open_ports,
                   "tech_versions": tech_versions} if open_ports else {},
            raw_output=stdout[:4000],
            duration_s=time.perf_counter() - t0,
        )


# ── nuclei ────────────────────────────────────────────────────────────


class NucleiEngine:
    """Wraps the bare-form nuclei command Pentagon validated as the
    operator-proven minimum: ``nuclei -u <target> -j -silent
    -no-color -timeout 15 -retries 1``. Parses one NDJSON finding per
    line. Default template library (~10K templates as of 2025) covers
    CVEs, exposures, misconfigurations, SSTI, SSRF, JWT issues, etc."""
    name = "nuclei"
    target_types = {"web_api"}
    binary = "nuclei"

    _SEV_MAP = {
        "critical": "critical", "high": "high",
        "medium": "medium", "low": "low",
        "info": "info", "unknown": "info",
    }

    def run(self, target: str, facts: dict) -> EngineResult:
        t0 = time.perf_counter()
        if not _which(self.binary):
            return EngineResult(
                engine=self.name, target=target,
                error="binary_not_available",
                duration_s=time.perf_counter() - t0,
            )
        cmd = [
            self.binary, "-u", target, "-j", "-silent", "-no-color",
            "-timeout", "15", "-retries", "1",
            "-disable-update-check",
        ]
        rc, stdout, stderr = _exec(cmd, timeout_s=300)
        findings: list[Finding] = []
        for line in stdout.splitlines():
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            info = obj.get("info") or {}
            tid = obj.get("template-id") or obj.get("template_id") or "?"
            sev = self._SEV_MAP.get(
                str(info.get("severity", "info")).lower(), "info",
            )
            name = info.get("name") or tid
            matched_at = (
                obj.get("matched-at") or obj.get("matched_at")
                or obj.get("host") or target
            )
            cves = info.get("classification", {}).get("cve-id") or []
            if isinstance(cves, str):
                cves = [cves]
            findings.append(Finding(
                title=f"[{sev}] {name}",
                severity=sev, source=self.name,
                cve_ids=list(cves),
                evidence={"template_id": tid, "matched_at": matched_at,
                          "tags": info.get("tags", "")},
            ))
        return EngineResult(
            engine=self.name, target=target, findings=findings,
            raw_output=stdout[:4000],
            duration_s=time.perf_counter() - t0,
        )


# ── feroxbuster ───────────────────────────────────────────────────────


class FeroxbusterEngine:
    """Content discovery via feroxbuster. Uses the bundled wordlist
    (commonest 4622 entries from SecLists raft-medium)."""
    name = "feroxbuster"
    target_types = {"web_api"}
    binary = "feroxbuster"

    def run(self, target: str, facts: dict) -> EngineResult:
        t0 = time.perf_counter()
        if not _which(self.binary):
            return EngineResult(
                engine=self.name, target=target,
                error="binary_not_available",
                duration_s=time.perf_counter() - t0,
            )
        # Use the engine's own JSON output + cap to 120s to keep
        # ablation runs bounded.
        cmd = [
            self.binary, "-u", target, "--silent",
            "--threads", "50", "--no-recursion",
            "--status-codes", "200,204,301,302,307,401,403",
            "--timeout", "5",
            "--scan-limit", "1", "--time-limit", "90s",
            "--json",
        ]
        rc, stdout, stderr = _exec(cmd, timeout_s=120)
        findings: list[Finding] = []
        urls: list[str] = []
        for line in stdout.splitlines():
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            if obj.get("type") != "response":
                continue
            url = obj.get("url")
            status = obj.get("status")
            if not url or not status:
                continue
            urls.append(url)
            sev = "info"
            if status in (200, 204) and any(
                k in url.lower() for k in
                ("admin", "config", "backup", ".git", ".env",
                 "secret", "phpmyadmin")
            ):
                sev = "medium"
            findings.append(Finding(
                title=f"Discovered {status} {url}",
                severity=sev, source=self.name,
                evidence={"url": url, "status": status,
                          "content_length": obj.get("content_length")},
            ))
        return EngineResult(
            engine=self.name, target=target, findings=findings,
            facts={"urls": urls} if urls else {},
            raw_output=stdout[:4000],
            duration_s=time.perf_counter() - t0,
        )


# ── dirsearch ─────────────────────────────────────────────────────────


class DirsearchEngine:
    """Wraps the dirsearch Python CLI in plain-text-output mode for
    parsing simplicity."""
    name = "dirsearch"
    target_types = {"web_api"}
    binary = "dirsearch"

    def run(self, target: str, facts: dict) -> EngineResult:
        t0 = time.perf_counter()
        if not _which(self.binary):
            return EngineResult(
                engine=self.name, target=target,
                error="binary_not_available",
                duration_s=time.perf_counter() - t0,
            )
        cmd = [
            self.binary, "-u", target, "-q",
            "--format", "plain", "-o", "/tmp/_rc_dirsearch.txt",
            "--max-time", "90", "-t", "30",
        ]
        rc, _, _ = _exec(cmd, timeout_s=120)
        findings: list[Finding] = []
        urls: list[str] = []
        try:
            with open("/tmp/_rc_dirsearch.txt") as fh:
                for line in fh:
                    parts = line.split()
                    if len(parts) < 3 or not parts[0].isdigit():
                        continue
                    status = int(parts[0])
                    if status >= 400:
                        continue
                    url = parts[-1]
                    urls.append(url)
                    sev = "info"
                    if any(k in url.lower() for k in
                           ("admin", "backup", "secret", ".git",
                            ".env", "phpmyadmin", "config")):
                        sev = "medium"
                    findings.append(Finding(
                        title=f"Discovered {status} {url}",
                        severity=sev, source=self.name,
                        evidence={"url": url, "status": status},
                    ))
        except FileNotFoundError:
            pass
        return EngineResult(
            engine=self.name, target=target, findings=findings,
            facts={"urls": urls} if urls else {},
            duration_s=time.perf_counter() - t0,
        )


# ── nikto (typically requires Kali; checked here for completeness) ────


class NiktoEngine:
    """Wraps the nikto web server scanner. The local mac doesn't have
    nikto so this engine will return binary_not_available unless wired
    through the KaliRemoteEngine wrapper."""
    name = "nikto"
    target_types = {"web_api"}
    binary = "nikto"

    def run(self, target: str, facts: dict) -> EngineResult:
        t0 = time.perf_counter()
        if not _which(self.binary):
            return EngineResult(
                engine=self.name, target=target,
                error="binary_not_available",
                duration_s=time.perf_counter() - t0,
            )
        cmd = [self.binary, "-h", target, "-Tuning", "x6", "-maxtime",
               "120s", "-ask", "no", "-nointeractive"]
        rc, stdout, stderr = _exec(cmd, timeout_s=150)
        findings: list[Finding] = []
        for line in stdout.splitlines():
            line = line.strip()
            if not line.startswith("+ "):
                continue
            # Nikto formats: "+ <url>: <message>" or "+ OSVDB-xxxx: <msg>"
            payload = line[2:]
            sev = "low"
            if "OSVDB" in payload or "CVE-" in payload:
                sev = "medium"
            findings.append(Finding(
                title=payload[:180],
                severity=sev, source=self.name,
                evidence={"line": payload[:500]},
            ))
        return EngineResult(
            engine=self.name, target=target, findings=findings,
            raw_output=stdout[:4000],
            duration_s=time.perf_counter() - t0,
        )


# Engines available without Kali. Add to your orchestrator with:
#     orchestrator = Orchestrator(engines={**REAL_ENGINES, **CLI_ENGINES}, ...)
CLI_ENGINES = {
    e.name: e for e in (
        NmapEngine(), NucleiEngine(),
        FeroxbusterEngine(), DirsearchEngine(),
        NiktoEngine(),  # registered; returns "not_available" if missing
    )
}
