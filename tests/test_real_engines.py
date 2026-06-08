"""Real HTTP engines — fresh MIT code, no Pentagon imports.

These tests run against the session-scoped local stub HTTP server
defined in ``conftest.py``. Every assertion is on engine output
produced by a real loopback HTTP request.
"""
from reasonchain.real_engines import (
    HeaderVulnCheck, HttpProbe, REAL_ENGINES, UrlCrawler,
)


def test_http_probe_pulls_banner_and_title(stub_server):
    res = HttpProbe().run(stub_server, facts={})
    assert res.error is None
    assert res.facts["http_status"] == 200
    assert res.facts["server_header"].startswith("stubd")
    assert res.facts["x_powered_by"].startswith("TestFramework")
    assert res.facts["page_title"] == "Stub Web App"
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
