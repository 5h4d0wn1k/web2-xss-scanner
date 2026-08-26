# WEB2 — XSS Scanner + Payload Generator

Reflected, Stored, and DOM-based XSS detection with CSP bypass payloads.

## Overview

This project implements a comprehensive XSS scanner that:
- Detects reflected, stored, and DOM-based XSS vulnerabilities
- Generates context-aware payloads (HTML, JS, attribute, URL contexts)
- Analyzes Content Security Policy (CSP) headers for bypass opportunities
- Identifies DOM sources and sinks for client-side injection
- Supports multiple payload encoding methods

## Features

- **Multi-type detection**: Reflected, stored, and DOM-based XSS
- **Context-aware payloads**: Different payloads for HTML, JavaScript, attribute, and URL contexts
- **CSP analysis**: Check headers and test bypass payloads
- **DOM analysis**: Detect sources (document.URL, location.hash) and sinks (eval, innerHTML)
- **Payload encoding**: URL, double URL, HTML entities, Unicode, Base64
- **Polylot payloads**: Advanced bypass techniques

## Installation

```bash
pip install requests
```

## Usage

```bash
# Basic scan
python3 xss_scanner.py -u "http://target.com/search?q=test"

# POST request
python3 xss_scanner.py -u "http://target.com/comment" -m POST -d "text=hello"

# With CSP analysis
python3 xss_scanner.py -u "http://target.com/page?q=test" --check-csp

# Stored XSS + DOM analysis
python3 xss_scanner.py -u "http://target.com/page?q=test" --level 2 --stored

# Encoded payloads with export
python3 xss_scanner.py -u "http://target.com/search?q=test" --encode url -o results.json

# Verbose mode
python3 xss_scanner.py -u "http://target.com/search?q=test" -v
```

## CLI Options

| Option | Description |
|--------|-------------|
| `-u, --url` | Target URL with parameter |
| `-m, --method` | HTTP method: GET or POST |
| `-d, --data` | POST data (key=value&key2=value2) |
| `-c, --cookies` | Cookies (key=value;key2=value2) |
| `--header` | Custom header (repeatable) |
| `--timeout` | Request timeout in seconds |
| `--delay` | Delay between requests |
| `--level` | Scan level: 1 (basic), 2 (DOM analysis), 3 (full) |
| `--encode` | Payload encoding: none, url, double_url, html, unicode, base64 |
| `--stored` | Test for stored XSS |
| `--check-csp` | Analyze and test CSP bypass |
| `-o, --output` | Export results to JSON |
| `-v, --verbose` | Verbose output |

## Example Output

```
  ╔══════════════════════════════════════════════╗
  ║    WEB2 — XSS Scanner + Payload Generator   ║
  ║       Reflected / Stored / DOM XSS           ║
  ╚══════════════════════════════════════════════╝

[*] Target: http://target.com/search?q=test
[*] Method: GET
[*] Marker: xSsABCDEF

[*] Parameters to test: ['q']

[*] Testing parameter: q
[*] Testing reflected XSS...
  [+] Reflected XSS: param=q, context=html
      Payload: <script>alert('xSsABCDEF')</script>

============================================================
  SCAN RESULTS
============================================================

  --- REFLECTED XSS (1 found) ---
  [1] Parameter: q
      Context:  html
      Payload:  <script>alert('xSsABCDEF')</script>
      Evidence: Marker reflected in html context

  Total vulnerabilities: 1
============================================================
```

## Legal Disclaimer

**IMPORTANT: Read before use.**

This project is provided for **educational and authorized security testing purposes only**. 

### Authorization Requirements
- You MUST have explicit written permission from the network owner before using this tool
- Unauthorized interception of network communications is illegal under federal and state laws
- This tool should ONLY be used on networks you own or have written authorization to test

### Legal Framework
- **Computer Fraud and Abuse Act (CFAA)**: Unauthorized access to computer systems is a federal crime
- **Wiretap Act (18 U.S.C. § 2511)**: Interception of electronic communications without consent is illegal
- **State Laws**: Many states have additional computer crime and wiretapping statutes
- **GDPR/CCPA**: Data collection may be subject to privacy regulations

### Acceptable Use
- Testing security of your own networks
- Authorized penetration testing with written scope
- Academic research in controlled lab environments
- Security education and training

### Prohibited Use
- Intercepting communications on networks you do not own
- Attacking infrastructure without authorization
- Any activity that violates applicable laws or regulations
- Commercial use without proper licensing

### No Warranty
This software is provided "AS IS" without warranty of any kind. The author is not responsible for any misuse or damage caused by this software.

### Responsible Disclosure
If you discover vulnerabilities using this tool, follow responsible disclosure practices:
1. Report to the vendor/owner privately
2. Allow reasonable time for remediation
3. Do not exploit beyond proof of concept

## License

MIT
