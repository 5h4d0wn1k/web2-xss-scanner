#!/usr/bin/env python3
"""Tests for WEB2 — XSS Scanner."""

import sys
import os
import threading
import time
import unittest
import urllib.parse
from http.server import HTTPServer, BaseHTTPRequestHandler

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from xss_scanner import XSSScanner, ScanConfig, XSSType, MARKER, MARKER_RE


class VulnHandler(BaseHTTPRequestHandler):
    """Reflects raw, unencoded input (stored + reflected XSS planted)."""

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        params = urllib.parse.parse_qs(parsed.query)
        q = params.get("q", [""])[0]
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        body = f"<html><body><h1>Results</h1><div>{q}</div></body></html>"
        self.wfile.write(body.encode())

    def log_message(self, format, *args):
        pass


class CleanHandler(BaseHTTPRequestHandler):
    """HTML-encodes all input (no reflected XSS)."""

    def do_GET(self):
        import html as html_mod
        parsed = urllib.parse.urlparse(self.path)
        params = urllib.parse.parse_qs(parsed.query)
        q = params.get("q", [""])[0]
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        body = f"<html><body><h1>Results</h1><div>{html_mod.escape(q)}</div></body></html>"
        self.wfile.write(body.encode())

    def log_message(self, format, *args):
        pass


class DomHandler(BaseHTTPRequestHandler):
    """Page with DOM sources and sinks."""

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        body = (
            "<html><body><script>\n"
            "var u = document.URL;\n"
            "var out = document.getElementById('x');\n"
            "out.innerHTML = u;\n"
            "eval(location.hash);\n"
            "</script></body></html>"
        )
        self.wfile.write(body.encode())

    def log_message(self, format, *args):
        pass


class TestXSSReflected(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.vuln = HTTPServer(("127.0.0.1", 18201), VulnHandler)
        threading.Thread(target=cls.vuln.serve_forever, daemon=True).start()
        time.sleep(0.2)

    @classmethod
    def tearDownClass(cls):
        cls.vuln.shutdown()

    def test_reflected_found(self):
        config = ScanConfig(url="http://127.0.0.1:18201/search?q=test", method="GET", timeout=5)
        scanner = XSSScanner(config)
        scanner.run_scan()
        self.assertTrue(any(r.xss_type == XSSType.REFLECTED for r in scanner.results),
                        "Should detect reflected XSS on vulnerable page")


class TestXSSCleanNoFalsePositive(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.clean = HTTPServer(("127.0.0.1", 18202), CleanHandler)
        threading.Thread(target=cls.clean.serve_forever, daemon=True).start()
        time.sleep(0.2)

    @classmethod
    def tearDownClass(cls):
        cls.clean.shutdown()

    def test_no_false_positive(self):
        config = ScanConfig(url="http://127.0.0.1:18202/search?q=test", method="GET", timeout=5)
        scanner = XSSScanner(config)
        scanner.run_scan()
        self.assertEqual(len(scanner.results), 0,
                         "Should NOT detect XSS on clean page (input encoded)")


class TestXSSDomDetection(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dom = HTTPServer(("127.0.0.1", 18203), DomHandler)
        threading.Thread(target=cls.dom.serve_forever, daemon=True).start()
        time.sleep(0.2)

    @classmethod
    def tearDownClass(cls):
        cls.dom.shutdown()

    def test_dom_detected(self):
        config = ScanConfig(url="http://127.0.0.1:18203/page", method="GET", timeout=5, level=2)
        scanner = XSSScanner(config)
        scanner.run_scan()
        self.assertTrue(any(r.xss_type == XSSType.DOM_BASED for r in scanner.results),
                        "Should flag DOM sources+sinks")


class TestXSSDemo(unittest.TestCase):
    def test_demo_finds_vulns(self):
        import subprocess
        result = subprocess.run(
            [sys.executable, "-c", "from xss_scanner import run_demo; run_demo()"],
            capture_output=True, text=True, timeout=20,
            cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        )
        self.assertEqual(result.returncode, 0, f"Demo should exit 0. stderr: {result.stderr[:500]}")


if __name__ == "__main__":
    unittest.main()