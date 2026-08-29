"""API key / secret exposure detection.

Scans response headers and body text using conservative regular expressions
for patterns resembling common credential formats. Findings always redact
the discovered value; the full secret is never stored in a report or
printed to the terminal.
"""

from __future__ import annotations

import re

from ..models import CheckResult, Confidence, Finding, ScanConfig, Severity, Status

CHECK_NAME = "Secret Exposure"

# Conservative patterns chosen to minimize false positives. Each tuple is
# (label, compiled regex, confidence).
PATTERNS = [
    ("AWS Access Key ID", re.compile(r"\bAKIA[0-9A-Z]{16}\b"), Confidence.HIGH),
    ("Google API Key", re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"), Confidence.HIGH),
    ("Stripe Live Secret Key", re.compile(r"\bsk_live_[0-9a-zA-Z]{16,}\b"), Confidence.HIGH),
    ("Slack Token", re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b"), Confidence.HIGH),
    ("GitHub Token", re.compile(r"\bgh[pousr]_[0-9A-Za-z]{20,}\b"), Confidence.HIGH),
    ("Generic Bearer Token", re.compile(r"\bBearer\s+[A-Za-z0-9\-._~+/]{20,}=*\b"), Confidence.MEDIUM),
    ("JSON Web Token", re.compile(r"\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\b"), Confidence.MEDIUM),
    (
        "Private Key Block",
        re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |)PRIVATE KEY-----"),
        Confidence.HIGH,
    ),
    (
        "Generic assigned secret",
        re.compile(
            r'(?i)\b(?:api[_-]?key|secret|password|passwd|access[_-]?token|refresh[_-]?token|private[_-]?key)'
            r'["\']?\s*[:=]\s*["\']?([A-Za-z0-9\-_/+]{12,})["\']?'
        ),
        Confidence.LOW,
    ),
]


def _redact(value: str) -> str:
    if len(value) <= 6:
        return "*" * len(value)
    return value[:4] + "*" * max(len(value) - 4, 4)


def _scan_text(label: str, text: str, source: str, findings: list, seen: set, confidence: Confidence) -> None:
    for pattern_label, pattern, conf in PATTERNS:
        for match in pattern.finditer(text):
            value = match.group(0)
            key = (pattern_label, source)
            if key in seen:
                continue
            seen.add(key)
            findings.append(
                Finding(
                    id=f"SECRET-{len(findings) + 1:03d}",
                    title=f"Potential {pattern_label} exposure",
                    severity=Severity.HIGH if conf == Confidence.HIGH else Severity.MEDIUM,
                    category=CHECK_NAME,
                    description=(
                        f"A pattern resembling a {pattern_label} was found in the {source}. "
                        "This may be a false positive; manual review is recommended."
                    ),
                    evidence=f"Potential secret: {_redact(value)}",
                    recommendation="Rotate the credential immediately if confirmed, and remove it from responses/headers.",
                    confidence=conf,
                )
            )


def run(client, config: ScanConfig, primary_response) -> CheckResult:
    findings: list = []
    seen: set = set()

    if not primary_response.ok:
        return CheckResult(name=CHECK_NAME, status=Status.INFO, findings=[],
                            summary="Primary request failed; could not scan for secrets.")

    header_text = "\n".join(f"{k}: {v}" for k, v in primary_response.headers.items())
    _scan_text("headers", header_text, "response headers", findings, seen, Confidence.MEDIUM)
    _scan_text("body", primary_response.text, "response body", findings, seen, Confidence.MEDIUM)

    if not findings:
        return CheckResult(
            name=CHECK_NAME, status=Status.PASS, findings=[],
            summary="No issues detected by the implemented secret-exposure checks.",
        )

    return CheckResult(
        name=CHECK_NAME, status=Status.WARN, findings=findings,
        summary=f"{len(findings)} potential secret pattern(s) detected (review recommended).",
    )
