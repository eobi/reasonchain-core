"""Real HTTP engines — fresh MIT code, no Pentagon imports.

These tests use a local stub HTTP server so they pass offline + in CI
without depending on Juice Shop / DVWA being up.
"""
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from reasonchain.real_engines import (
    HeaderVulnCheck, HttpProbe, REAL_ENGINES, UrlCrawler,
)


# ── Local stub server fixtures ────────────────────────────────────────


class _Stub(BaseHTTPRequestHandler):
    def log_message(self, *a, **kw):
        pass

    def do_GET(self):
        path = self.path
        if path == "/":
            body = (
                b"<html><head><title>Stub Home</title></head>"
                b'<body><a href="/admin">admin</a> '
                b'<a href="/login">login</a> '
                b'<a href="https://elsewhere.example/x">offsite</a></body></html>'
            )
            self.send_response(200)
            self.send_header("Server", "stubd/1.2.3")
            self.send_header("X-Powered-By", "TestFramework/4.5")
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(body)
        elif path == "/admin":
            self.send_response(200)
            self.send_header("Server", "stubd/1.2.3")
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(b"<html>admin page</html>")
        elif path == "/robots.txt":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"User-agent: *\nDisallow:\n")
        else:
            self.send_response(404)
            self.send_header("Server", "stubd/1.2.3")
            self.end_headers()
            self.wfile.write(b"not found")


@pytest.fixture(scope="module")
def stub_server():
    srv = HTTPServer(("127.0.0.1", 0), _Stub)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    host, port = srv.server_address
    url = f"http://{host}:{port}/"
    yield url
    srv.shutdown()


# ── Tests ─────────────────────────────────────────────────────────────


def test_http_probe_pulls_banner_and_title(stub_server):
    res = HttpProbe().run(stub_server, facts={})
    assert res.error is None
    assert res.facts["http_status"] == 200
    assert res.facts["server_header"].startswith("stubd")
    assert res.facts["x_powered_by"].startswith("TestFramework")
    assert res.facts["page_title"] == "Stub Home"
    # Banner version extraction.
    tech = res.facts.get("tech_versions") or []
    assert tech and tech[0]["product"] == "stubd"


def test_url_crawler_filters_to_same_host(stub_server):
    res = UrlCrawler().run(stub_server, facts={})
    urls = res.facts.get("urls") or []
    # Same-host links accepted; offsite dropped.
    assert any("/admin" in u for u in urls)
    assert any("/login" in u for u in urls)
    assert all("elsewhere.example" not in u for u in urls)


def test_header_vuln_check_flags_missing_csp(stub_server):
    res = HeaderVulnCheck().run(stub_server, facts={})
    titles = [f.title for f in res.findings]
    assert any("content-security-policy" in t for t in titles)


def test_header_vuln_check_finds_admin_path(stub_server):
    res = HeaderVulnCheck().run(stub_server, facts={})
    titles = [f.title for f in res.findings]
    assert any("admin" in t.lower() for t in titles)


def test_real_engines_registered():
    assert "http_probe" in REAL_ENGINES
    assert "url_crawler" in REAL_ENGINES
    assert "header_vuln_check" in REAL_ENGINES


def test_engines_protocol_shape():
    for e in REAL_ENGINES.values():
        assert hasattr(e, "name") and isinstance(e.name, str)
        assert hasattr(e, "target_types")
        assert callable(e.run)
