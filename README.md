> **⚠️ EDUCATIONAL USE ONLY — AUTHORIZED TESTING ONLY.**
> This project exists for education, research, and **defense of systems you own
> or hold explicit written authorization to assess**. Unauthorized use is
> prohibited and may be illegal. Read [ETHICS.md](ETHICS.md) and
> [SCOPE.md](SCOPE.md) before use. Use at your own risk; **AS IS**, no warranty.

# WEB2 — XSS Scanner & Payload Generator

Cross-site scripting (XSS) scanner for web security testing — reflected, stored, and DOM-based
detection with context-aware payloads, CSP-bypass analysis, and multi-encoding payload generation.
Includes an offline demo that scans a built-in vulnerable localhost simulator.

![MIT](https://img.shields.io/badge/license-MIT-blue.svg)
![GitHub stars](https://img.shields.io/github/stars/5h4d0wn1k/web2-xss-scanner)
![GitHub last commit](https://img.shields.io/github/last-commit/5h4d0wn1k/web2-xss-scanner)
![GitHub issues](https://img.shields.io/github/issues/5h4d0wn1k/web2-xss-scanner)

## Why

XSS remains the most common injection bug in web applications, and detection depends on context:
the same payload behaves differently in HTML, attribute, JavaScript, and URL contexts. WEB2
implements a real detection loop — send marker payloads, observe whether the raw marker is
reflected verbatim, then report the parameter, context, and evidence. It also analyzes
Content-Security-Policy headers and DOM sources/sinks for client-side injection. The scanner is a
web-security educational instrument: run the offline `--demo` against the bundled vulnerable
simulator, or test only lab targets you own or have written authorization to assess.

## Features

- **Multi-type detection** — reflected, stored (with `--stored`), and DOM-based XSS.
- **Context-aware payloads** — HTML, JS, attribute, and URL contexts plus polylot payloads.
- **CSP analysis** — parses headers (`--check-csp`) and tests bypass payloads.
- **Encodings** — none, URL, double URL, HTML entities, Unicode, Base64 (`--encode`).
- **DOM analysis** — flags `document.URL`, `location.hash`, `eval`, `innerHTML` sources/sinks
  (`--level 2/3`).
- **Offline demo** — `--demo` scans a stdlib vulnerable simulator and exits `0`.

## Quickstart

Prerequisite: Python 3 (standard library `urllib`).

```bash
python3 xss_scanner.py --demo                 # offline demo against the vulnerable simulator
python3 xss_scanner.py -u "http://<lab-target>/search?q=test" -v
python3 xss_scanner.py -u "http://<lab-target>/page?q=test" --level 2 -o findings.json
python3 xss_scanner.py -u "http://<lab-target>/search?q=test" --check-csp --encode url
```

## Tests

```bash
python3 -m unittest discover -s tests -v
```

Tests start a local vulnerable simulator and a clean control server, then assert the scanner flags
the planted reflected bug and DOM sinks while not false-positiving on an encoding-safe page.

## Project structure

- `xss_scanner.py` — scanner, payload generator, and CLI.
- `tests/` — offline detection and false-positive tests.

## Documentation

- [CONTRIBUTING.md](CONTRIBUTING.md)
- [SECURITY.md](SECURITY.md)
- [ETHICS.md](ETHICS.md) · [SCOPE.md](SCOPE.md)

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Keep finding detection evidence-based (raw marker must
appear in the response).

## License

MIT — see [LICENSE](LICENSE).