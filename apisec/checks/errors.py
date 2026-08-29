"""Verbose error / stack trace disclosure checks.

Sends a small number of safe, read-only, minimally modified GET requests
(e.g. a clearly non-existent path, a malformed query string) to see whether
the server leaks stack traces, internal file paths, or database error
messages. This module never sends SQL/command injection payloads — only
generic, non-exploitative inputs designed to trigger ordinary error paths.
"""

from __future__ import annotations

import re
from urllib.parse import urlparse

from ..models import CheckResult, Confidence, Finding, ScanConfig, Severity, Status

CHECK_NAME = "Error Handling"

INDICATORS = [
    ("Python traceback", re.compile(r"Traceback \(most recent call last\)")),
    ("Django debug page", re.compile(r"DisallowedHost|Django Version|django\.core\.exceptions")),
    ("Flask/Werkzeug debugger", re.compile(r"Werkzeug Debugger|werkzeug\.exceptions")),
    ("Node.js stack trace", re.compile(r"at\s+[\w.$]+\s+\(.*:\d+:\d+\)")),
    ("Java stack trace", re.compile(r"\bat\s[\w.$]+\([\w.$]+\.java:\d+\)")),
    (".NET stack trace", re.compile(r"System\.\w+Exception")),
    ("PHP fatal error", re.compile(r"Fatal error:.*in .* on line \d+")),
    ("SQL error message", re.compile(r"(SQL syntax|ORA-\d{5}|SQLSTATE\[|pg_query\(\))")),
    ("Internal file path", re.compile(r"(/usr/(local/)?(lib|share)/|/var/www/|[A-Za-z]:\\\\Users\\\\|/home/\w+/)")),
]


def run(client, config: ScanConfig, primary_response) -> CheckResult:
    findings = []
    status = Status.PASS
    parsed = urlparse(config.url)

    probe_urls = [
        parsed._replace(path=parsed.path.rstrip("/") + "/apisecchecker-not-found-probe").geturl(),
        parsed._replace(query=(parsed.query + "&" if parsed.query else "") + "apisecchecker_probe=%00").geturl(),
    ]

    texts_checked = [(config.url, primary_response.text if primary_response.ok else "")]

    for probe_url in probe_urls:
        resp = client.request("GET", probe_url)
        if resp.ok:
            texts_checked.append((probe_url, resp.text))

    seen_labels = set()
    for source_url, text in texts_checked:
        if not text:
            continue
        for label, pattern in INDICATORS:
            if label in seen_labels:
                continue
            match = pattern.search(text)
            if match:
                seen_labels.add(label)
                snippet = text[max(match.start() - 40, 0): match.start() + 80]
                findings.append(
                    Finding(
                        id=f"ERR-{len(findings) + 1:03d}",
                        title=f"Possible {label} disclosure",
                        severity=Severity.MEDIUM,
                        category=CHECK_NAME,
                        description=(
                            f"A response contained a pattern resembling a {label}, which "
                            "may expose internal implementation details to clients."
                        ),
                        evidence=f"Source: {source_url} | Snippet: {snippet.strip()!r}",
                        recommendation="Disable verbose/debug error output in production; return generic error responses.",
                        confidence=Confidence.MEDIUM,
                    )
                )
                status = Status.WARN

    if not findings:
        return CheckResult(name=CHECK_NAME, status=Status.PASS, findings=[],
                            summary="No issues detected by the implemented error-handling checks.")

    return CheckResult(name=CHECK_NAME, status=status, findings=findings,
                        summary=f"{len(findings)} potential verbose-error disclosure(s) found.")
