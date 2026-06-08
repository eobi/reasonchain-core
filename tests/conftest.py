"""Shared pytest fixtures.

Provides a session-scoped local HTTP stub server so unit tests can run
the real HTTP engines deterministically without depending on any
external Docker lab. The stub deliberately mimics enough of a
typical OWASP-style vulnerable app (one sensitive path, missing
security headers, banner version, link-bearing landing page) that all
three engines (http_probe, url_crawler, header_vuln_check) produce
findings against it.

The stub is real Python code over real loopback sockets — there are
no mocked HTTP libraries, no patched fetch functions, no fake clocks.
"""
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest


class _StubHandler(BaseHTTPRequestHandler):
    def log_message(self, *a, **kw):
        pass

    def do_GET(self):
        path = self.path
        if path == "/":
            body = (
                b"<html><head><title>Stub Web App</title></head>"
                b'<body><a href="/admin">admin</a> '
                b'<a href="/login">login</a> '
                b'<a href="/api/users">users</a> '
                b'<a href="https://elsewhere.example/x">offsite</a>'
                b"</body></html>"
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
        elif path == "/admin/login":
            self.send_response(200)
            self.send_header("Server", "stubd/1.2.3")
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(b"<html>admin login</html>")
        elif path == "/login":
            self.send_response(200)
            self.send_header("Server", "stubd/1.2.3")
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(b"<html>login</html>")
        elif path == "/api/users":
            self.send_response(200)
            self.send_header("Server", "stubd/1.2.3")
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'[{"id":1,"name":"a"}]')
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


@pytest.fixture(scope="session")
def stub_server():
    srv = HTTPServer(("127.0.0.1", 0), _StubHandler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    host, port = srv.server_address
    url = f"http://{host}:{port}/"
    yield url
    srv.shutdown()
