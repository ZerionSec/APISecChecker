# APISecChecker

**Defensive, non-destructive API security auditing toolkit.**

APISecChecker performs safe, read-only security checks against APIs you own or are explicitly authorized to test. It never exploits vulnerabilities, never brute-forces credentials, never bypasses authentication, and never sends data-modifying requests (`PUT` / `DELETE` / `PATCH`).

> **Legal notice:** Only scan systems you own or have written permission to test. Unauthorized scanning may be illegal.

## Features

| Check | What it does |
|-------|--------------|
| **HTTPS / TLS** | Certificate validity, expiration, protocol version |
| **Security Headers** | HSTS, X-Content-Type-Options, CSP, etc. (context-aware) |
| **CORS** | Wildcard origin, credentials + `*`, origin reflection |
| **HTTP Methods** | Advertised methods via `OPTIONS` / `Allow` (never sends write methods) |
| **Authentication** | Detects required auth; optional token comparison (no guessing) |
| **Secret Exposure** | Redacted pattern matching for common API keys / JWTs / private keys |
| **JWT Analysis** | Decodes header/claims only (no signature cracking) |
| **Rate Limiting** | Passive header detection only |
| **Information Disclosure** | `Server`, `X-Powered-By`, debug headers |
| **Error Handling** | Safe probes for stack traces / verbose errors |
| **Documentation** | Common Swagger/OpenAPI path exposure |
| **Response Analysis** | Sensitive field names, private IPs, status interpretation |
| **SSRF-Relevant Params** | Flags URL-like parameter names (no SSRF probing) |

Reports include a transparent heuristic **security score** (0–100) and letter grade.

## Requirements

- Python 3.8+
- `requests` (`pip install -r requirements.txt`)

## Installation

```bash
git clone https://github.com/ZerionSec/APISecChecker.git
cd APISecChecker
python3 -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

## Quick Start

```bash
# Basic scan (terminal report)
python3 apisecchecker.py --url https://api.example.com

# HTML report
python3 apisecchecker.py --url https://api.example.com --format html --output report.html

# JSON report
python3 apisecchecker.py --url https://api.example.com --format json --output report.json

# With authentication token
python3 apisecchecker.py --url https://api.example.com --token "your-bearer-token"

# Custom headers
python3 apisecchecker.py --url https://api.example.com -H "X-API-Key: abc123" -H "Accept: application/json"

# POST with body
python3 apisecchecker.py --url https://api.example.com/v1/resource -m POST -d '{"key":"value"}'
```

## CLI Options

```
-u, --url              Target API URL (required)
-m, --method           HTTP method for primary request (default: GET)
-H, --header           Custom header "Name: Value" (repeatable)
-d, --data             JSON request body
--token                Bearer/API token for authenticated checks
--timeout              Request timeout in seconds (default: 10)
--output               Save report to file
--format               json | html | text (default: text)
--no-tls-verify        Disable TLS certificate verification
--safe                 Explicit safe mode (always on)
--no-findings          Hide detailed findings in terminal output
--version              Show version
```

## Security Model

- **Safe by design**: Destructive methods are refused at the HTTP client layer.
- **Request budget**: Hard limit on total requests per scan to avoid load.
- **Response size cap**: Bodies are truncated to prevent memory issues.
- **No exploitation**: Checks are observational / passive only.
- **Secrets redacted**: Any potential secret patterns are masked in reports.
- **Clear disclaimer**: Scores are heuristics, not a professional assessment.

## Example Output (terminal)

```
╔══════════════════════════════════════════════════════════════════════════╗
║                        APISecChecker v1.0.0                              ║
╚══════════════════════════════════════════════════════════════════════════╝

Target: https://api.example.com
Scanned: 2026-08-29 12:00:00 UTC

[+] HTTPS / TLS                                              PASS
[+] Security Headers                                         WARN
[+] CORS                                                     INFO
...

Security Score: 82/100
Grade: B
```

## Project Structure

```
APISecChecker/
├── apisecchecker.py          # Entry point
├── requirements.txt
├── LICENSE                   # MIT
├── README.md
├── reports/                  # Generated reports (gitignored)
└── apisec/
    ├── __init__.py
    ├── models.py             # Severity, Finding, ScanReport, etc.
    ├── http_client.py        # Safety-constrained requests wrapper
    ├── scanner.py            # Orchestration
    ├── scoring.py            # Heuristic score / grade
    ├── reporter.py           # Terminal / JSON / HTML
    ├── cli.py
    └── checks/               # One module per check category
        ├── tls.py
        ├── headers.py
        ├── cors.py
        ├── methods.py
        ├── authentication.py
        ├── secrets.py
        ├── jwt.py
        ├── rate_limit.py
        ├── disclosure.py
        ├── errors.py
        ├── documentation.py
        └── response_analysis.py
```

## Contributing

Pull requests welcome for additional **non-destructive** checks. Please keep the safety model intact (no write methods, no brute force, no exploitation).

## License

MIT License — see [LICENSE](LICENSE).

---

**Only scan systems you own or are explicitly authorized to test.**
