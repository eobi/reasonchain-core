"""SSH-to-Kali engine wrapper.

When you want to run nikto / sqlmap / dalfox / wpscan / etc. against a
target but the binary isn't installed on the host running
reasonchain-core, configure a Kali profile and these wrappers will
execute the same engine on the Kali box over SSH.

Profile config — reasonchain-core/kali_profile.ini (gitignored):

    [kali]
    host = 192.168.1.236
    username = kali
    key_path = ~/.ssh/id_ed25519
    # OR password (env var preferred for CI):
    # password_env = KALI_SSH_PASSWORD

The wrapper translates each subprocess engine's ``cmd`` list into a
single shell string, runs it via paramiko, and parses the returned
stdout with the same parser the subprocess engine uses. So adding a
new remote engine = subclassing ``RemoteEngine`` with the engine
binary + parser.

If paramiko isn't installed OR the profile file is missing, ``Kali``
constructor raises a clean RuntimeError — the orchestrator should
register Kali-backed engines only when a profile exists.
"""
from __future__ import annotations

import configparser
import os
import shlex
import time
from dataclasses import dataclass, field
from pathlib import Path

from reasonchain.models import EngineResult


DEFAULT_PROFILE = Path(__file__).resolve().parents[2] / "kali_profile.ini"


@dataclass
class KaliProfile:
    host: str
    username: str
    port: int = 22
    key_path: str | None = None
    password: str | None = None        # inline (gitignored ini only)
    password_env: str | None = None    # env-var pointer (CI-safe)

    @classmethod
    def from_ini(cls, p: Path = DEFAULT_PROFILE) -> "KaliProfile":
        if not p.exists():
            raise RuntimeError(
                f"no Kali profile at {p}; create one with:\n"
                "[kali]\nhost = 192.168.1.236\nusername = kali\n"
                "auth_method = password\npassword = <yours>\n"
            )
        cfg = configparser.ConfigParser()
        cfg.read(p)
        if "kali" not in cfg:
            raise RuntimeError(f"profile {p} missing [kali] section")
        section = cfg["kali"]
        return cls(
            host=section["host"], username=section["username"],
            port=int(section.get("port", 22)),
            key_path=section.get("key_path") or None,
            password=section.get("password") or None,
            password_env=section.get("password_env") or None,
        )


class Kali:
    """Thin paramiko wrapper. One connection per Kali instance."""

    def __init__(self, profile: KaliProfile | None = None) -> None:
        try:
            import paramiko  # type: ignore[import-not-found]
        except ImportError as e:
            raise RuntimeError(
                "paramiko not installed; run `pip install paramiko`"
            ) from e
        self.profile = profile or KaliProfile.from_ini()
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        kwargs: dict = {
            "hostname": self.profile.host,
            "port": self.profile.port,
            "username": self.profile.username,
            "timeout": 10,
        }
        if self.profile.key_path:
            kwargs["key_filename"] = os.path.expanduser(self.profile.key_path)
        elif self.profile.password_env:
            pw = os.environ.get(self.profile.password_env)
            if not pw:
                raise RuntimeError(
                    f"profile says password_env={self.profile.password_env} "
                    "but the env var is unset"
                )
            kwargs["password"] = pw
        elif self.profile.password:
            kwargs["password"] = self.profile.password
        client.connect(**kwargs)
        self._client = client

    def exec(
        self, cmd: list[str], timeout_s: int = 300,
    ) -> tuple[int, str, str]:
        """Run ``cmd`` on Kali; return (rc, stdout, stderr)."""
        cmd_str = " ".join(shlex.quote(c) for c in cmd)
        stdin, stdout, stderr = self._client.exec_command(
            cmd_str, timeout=timeout_s,
        )
        # exec_command is non-blocking; read until EOF to drain.
        out = stdout.read().decode("utf-8", errors="replace")
        err = stderr.read().decode("utf-8", errors="replace")
        rc = stdout.channel.recv_exit_status()
        return rc, out, err

    def has(self, binary: str) -> bool:
        rc, out, _ = self.exec(["command", "-v", binary], timeout_s=5)
        return rc == 0 and out.strip() != ""

    def close(self) -> None:
        try:
            self._client.close()
        except Exception:
            pass


# ── Remote engine wrappers ────────────────────────────────────────────


@dataclass
class RemoteEngine:
    """Adapter: subprocess engine over SSH.

    ``cmd_builder`` may accept either ``(target)`` or ``(target, facts)``.
    The two-arg form lets fact-coupled engines (notably ``nmap_vuln``)
    read prior engines' ``open_ports`` from the shared Facts() bag
    so the H2 ablation actually exercises fusion: with fusion off,
    facts is empty, the engine uses its fallback port list, and the
    chain is observably shorter.
    """
    name: str
    target_types: set[str]
    cmd_builder: callable
    parser: callable
    kali: Kali
    binary: str = ""
    timeout_s: int = 600

    def run(self, target: str, facts: dict) -> EngineResult:
        t0 = time.perf_counter()
        if self.binary and not self.kali.has(self.binary):
            return EngineResult(
                engine=self.name, target=target,
                error=f"binary {self.binary!r} not on Kali",
                duration_s=time.perf_counter() - t0,
            )
        import inspect
        try:
            sig = inspect.signature(self.cmd_builder)
            if len(sig.parameters) >= 2:
                cmd = self.cmd_builder(target, facts)
            else:
                cmd = self.cmd_builder(target)
        except (TypeError, ValueError):
            cmd = self.cmd_builder(target)
        rc, stdout, stderr = self.kali.exec(cmd, timeout_s=self.timeout_s)
        result = self.parser(rc, stdout, stderr, target)
        result.engine = self.name
        result.target = target
        result.duration_s = time.perf_counter() - t0
        return result


def build_kali_engines(kali: Kali) -> dict:
    """Return a dict of {name: engine} for every CLI engine that lives
    on the Kali host. Mirrors the subprocess engines so the
    orchestrator's planner chains work identically over SSH."""
    from reasonchain.subprocess_engines import (
        FeroxbusterEngine, NiktoEngine, NmapEngine, NucleiEngine,
    )

    engines: dict = {}
    if kali.has("nmap"):
        engines["nmap"] = RemoteEngine(
            name="nmap", target_types={"web_api"}, kali=kali,
            binary="nmap",
            cmd_builder=lambda t: [
                "nmap", "-sV", "-T4", "--host-timeout", "60s",
                "-Pn", "-p", "80,443,3000,5000,8000,8080,8089,8090,8091,"
                              "8093,8094,8095,9090",
                _host_only(t),
            ],
            parser=lambda rc, out, err, t: _parse_nmap(out, err, t),
        )
        # nmap_vuln — fact-coupled to nmap via ``open_ports``.
        # When fusion is ON the planner's previous nmap pick populated
        # facts["open_ports"]; we scope --script vuln to exactly those
        # ports and the scan is fast + targeted.
        # When fusion is OFF the engine sees facts={} and falls back to
        # a small default port list (80,443) — so the H2 ablation
        # actually breaks the chain instead of running blindly across
        # 13 ports.
        engines["nmap_vuln"] = RemoteEngine(
            name="nmap_vuln", target_types={"web_api"}, kali=kali,
            binary="nmap",
            timeout_s=900,
            cmd_builder=_nmap_vuln_cmd_builder,
            parser=lambda rc, out, err, t: _parse_nmap_vuln(out, err, t),
        )
    if kali.has("nuclei"):
        # Bare-form per operator directive: ``nuclei -u <target>``,
        # nothing else. -j is added so the parser can read NDJSON, and
        # -silent suppresses the banner — that's the minimum machinery
        # required to consume the output, no scope flags, no rate
        # tuning, no severity filter.
        engines["nuclei"] = RemoteEngine(
            name="nuclei", target_types={"web_api"}, kali=kali,
            binary="nuclei",
            cmd_builder=lambda t: ["nuclei", "-u", t, "-j", "-silent"],
            parser=lambda rc, out, err, t: _parse_nuclei(out, err, t),
        )
    if kali.has("nikto"):
        engines["nikto"] = RemoteEngine(
            name="nikto", target_types={"web_api"}, kali=kali,
            binary="nikto",
            cmd_builder=lambda t: [
                "nikto", "-h", t, "-Tuning", "x6", "-maxtime", "120s",
                "-ask", "no", "-nointeractive",
            ],
            parser=lambda rc, out, err, t: _parse_nikto(out, err, t),
        )
    if kali.has("sqlmap"):
        engines["sqlmap"] = RemoteEngine(
            name="sqlmap", target_types={"web_api"}, kali=kali,
            binary="sqlmap",
            cmd_builder=lambda t: [
                "sqlmap", "-u", t, "--batch", "--crawl", "1",
                "--level", "1", "--risk", "1", "--smart",
                "--timeout", "30",
            ],
            parser=lambda rc, out, err, t: _parse_sqlmap(out, err, t),
        )
    if kali.has("dalfox"):
        engines["dalfox"] = RemoteEngine(
            name="dalfox", target_types={"web_api"}, kali=kali,
            binary="dalfox",
            cmd_builder=lambda t: [
                "dalfox", "url", t, "--silence", "--format", "json",
            ],
            parser=lambda rc, out, err, t: _parse_dalfox(out, err, t),
        )
    if kali.has("wpscan"):
        engines["wpscan"] = RemoteEngine(
            name="wpscan", target_types={"web_api"}, kali=kali,
            binary="wpscan",
            cmd_builder=lambda t: [
                "wpscan", "--url", t, "--no-banner", "--format", "json",
                "--random-user-agent",
            ],
            parser=lambda rc, out, err, t: _parse_wpscan(out, err, t),
        )
    return engines


# ── Output parsers (one per tool) ─────────────────────────────────────


def _host_only(target: str) -> str:
    s = target.replace("http://", "").replace("https://", "")
    return s.split("/")[0].split(":")[0]


def _nmap_vuln_cmd_builder(target: str, facts: dict | None = None) -> list[str]:
    """Fact-coupled cmd builder. Reads ``facts['open_ports']`` and
    scopes the --script vuln scan to those ports. Falls back to
    ``80,443`` when facts is empty (fusion=False ablation) so the
    chain breakage is observable."""
    facts = facts or {}
    open_ports = facts.get("open_ports") or []
    if open_ports:
        port_arg = ",".join(str(p) for p in open_ports[:20])
    else:
        port_arg = "80,443"
    return [
        "nmap", "-sV", "-T4", "-Pn", "--script", "vuln",
        "--script-timeout", "60s",
        "--host-timeout", "300s",
        "-p", port_arg,
        _host_only(target),
    ]


def _parse_nmap(stdout: str, stderr: str, target: str) -> EngineResult:
    from reasonchain.models import Finding
    findings: list[Finding] = []
    tech_versions: list[dict] = []
    open_ports: list[int] = []
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
            severity="info", source="nmap",
            evidence={"port": port, "service": service,
                      "version": version},
        ))
    return EngineResult(
        engine="nmap", target=target, findings=findings,
        facts={"open_ports": open_ports,
               "tech_versions": tech_versions} if open_ports else {},
        raw_output=stdout[:4000],
    )


def _parse_nmap_vuln(stdout: str, stderr: str, target: str) -> EngineResult:
    """Parse nmap --script vuln output. Each NSE script reports under
    its own block: ``| <script-name>:`` followed by indented lines.
    The most actionable lines mention CVE IDs or the keyword
    ``VULNERABLE``."""
    from reasonchain.models import Finding
    findings: list[Finding] = []
    current_script = ""
    current_port = 0
    cve_re = re.compile(r"CVE-\d{4}-\d{4,}")
    for raw in stdout.splitlines():
        line = raw.strip()
        # Port header — capture current port for context.
        m_port = re.match(r"^(\d+)/tcp\s+(open|filtered)\s+", line)
        if m_port:
            current_port = int(m_port.group(1))
            current_script = ""
            continue
        # Script start: "| script-name:"
        m_script = re.match(r"^\|\s+([a-z0-9_\-]+):", line)
        if m_script:
            current_script = m_script.group(1)
            continue
        # CVE-flagged finding lines.
        if "VULNERABLE" in line or cve_re.search(line):
            cves = cve_re.findall(line)
            sev = "high"
            if "info" in line.lower() and not cves:
                sev = "low"
            findings.append(Finding(
                title=(f"{current_script or 'nmap_vuln'} on "
                       f"port {current_port}: {line[:140]}"),
                severity=sev, source="nmap_vuln",
                cve_ids=cves,
                evidence={"port": current_port,
                          "script": current_script, "line": line[:500]},
            ))
    return EngineResult(
        engine="nmap_vuln", target=target, findings=findings,
        raw_output=stdout[:6000],
    )


def _parse_nuclei(stdout: str, stderr: str, target: str) -> EngineResult:
    import json
    from reasonchain.models import Finding
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
        tid = obj.get("template-id") or "?"
        sev = str(info.get("severity", "info")).lower()
        if sev not in ("critical", "high", "medium", "low", "info"):
            sev = "info"
        name = info.get("name") or tid
        cves = info.get("classification", {}).get("cve-id") or []
        if isinstance(cves, str):
            cves = [cves]
        findings.append(Finding(
            title=f"[{sev}] {name}",
            severity=sev, source="nuclei",
            cve_ids=list(cves),
            evidence={
                "template_id": tid,
                "matched_at": obj.get("matched-at") or target,
                "tags": info.get("tags", ""),
            },
        ))
    return EngineResult(
        engine="nuclei", target=target, findings=findings,
        raw_output=stdout[:4000],
    )


def _parse_nikto(stdout: str, stderr: str, target: str) -> EngineResult:
    """Parse nikto findings, dropping the boilerplate banner lines.

    Nikto prefixes every output line with ``+ ``, including pure
    informational banners like ``Target IP: x.x.x.x``. We keep only
    lines that describe an actual finding (path probe, header, vuln
    code) — never the run header.
    """
    from reasonchain.models import Finding
    BANNER_KEYWORDS = (
        "Target IP:", "Target Hostname:", "Target Port:",
        "Platform:", "Start Time:", "End Time:", "Server:",
        "host(s) tested", "items checked", "0 items checked",
    )
    findings: list[Finding] = []
    for line in stdout.splitlines():
        line = line.strip()
        if not line.startswith("+ "):
            continue
        payload = line[2:]
        if any(k in payload for k in BANNER_KEYWORDS):
            continue
        sev = "low"
        if "OSVDB" in payload or "CVE-" in payload:
            sev = "medium"
        if any(x in payload for x in
               ("admin", "config", "backup", ".env", ".git",
                "default credentials", "RCE", "exploit")):
            sev = "medium"
        findings.append(Finding(
            title=payload[:180],
            severity=sev, source="nikto",
            evidence={"line": payload[:500]},
        ))
    return EngineResult(
        engine="nikto", target=target, findings=findings,
        raw_output=stdout[:4000],
    )


def _parse_sqlmap(stdout: str, stderr: str, target: str) -> EngineResult:
    from reasonchain.models import Finding
    findings: list[Finding] = []
    # sqlmap prints "Parameter: <name>" + "Type: <kind>" when injection found.
    blocks = re.findall(
        r"Parameter:\s*(\S+).*?Type:\s*(\S[^\n]+?)(?:\n|$)",
        stdout, re.DOTALL,
    )
    for param, kind in blocks:
        findings.append(Finding(
            title=f"SQL injection in parameter {param}",
            severity="high", source="sqlmap",
            evidence={"parameter": param, "injection_type": kind.strip(),
                      "target": target},
        ))
    return EngineResult(
        engine="sqlmap", target=target, findings=findings,
        raw_output=stdout[:4000],
    )


def _parse_dalfox(stdout: str, stderr: str, target: str) -> EngineResult:
    import json
    from reasonchain.models import Finding
    findings: list[Finding] = []
    for line in stdout.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        url = obj.get("url") or target
        payload = obj.get("payload") or "?"
        findings.append(Finding(
            title=f"XSS reflected at {url}",
            severity="high", source="dalfox",
            evidence={"url": url, "payload": payload[:200]},
        ))
    return EngineResult(
        engine="dalfox", target=target, findings=findings,
        raw_output=stdout[:4000],
    )


def _parse_wpscan(stdout: str, stderr: str, target: str) -> EngineResult:
    import json
    from reasonchain.models import Finding
    findings: list[Finding] = []
    try:
        obj = json.loads(stdout)
    except json.JSONDecodeError:
        return EngineResult(
            engine="wpscan", target=target, findings=[],
            raw_output=stdout[:4000],
        )
    interesting = obj.get("interesting_findings") or []
    for item in interesting:
        findings.append(Finding(
            title=item.get("to_s", "wpscan finding")[:180],
            severity="medium", source="wpscan",
            evidence={"url": item.get("url"),
                      "type": item.get("type")},
        ))
    plugins = obj.get("plugins") or {}
    for name, info in plugins.items():
        vulns = info.get("vulnerabilities") or []
        for v in vulns:
            findings.append(Finding(
                title=f"WordPress plugin {name}: {v.get('title','')}"[:180],
                severity="high", source="wpscan",
                cve_ids=v.get("references", {}).get("cve") or [],
                evidence={"plugin": name, "version": info.get("version", {})
                          .get("number")},
            ))
    return EngineResult(
        engine="wpscan", target=target, findings=findings,
        raw_output=stdout[:4000],
    )


# Module-level imports for the parsers above.
import re  # noqa: E402
