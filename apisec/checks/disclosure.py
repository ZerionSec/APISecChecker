"""Server information disclosure checks.

Inspects headers such as Server and X-Powered-By for overly verbose version
disclosure. Purely observational — this module does not attempt to exploit
any disclosed software version.
"""

from __future__ import annotations

import re

from ..models import CheckResult, Confidence, Finding, ScanConfig, Severity, Status

CHECK_NAME = "Information Disclosure"

VERSION_PATTERN = re.compile(r"\d+\.\d+(\.\d+)?")

DISCLOSURE_HEADERS = ("Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version", "X-Runtime", "X-Generator")
DEBUG_HEADERS = ("X-Debug", "X-Debug-Token", "X-Debug-Mode")


def run(client, config: ScanConfig, primary_response) -> CheckResult:
    if not primary_response.ok:
        return CheckResult(name=CHECK_NAME, status=Status.INFO, findings=[],
                            summary="Primary request failed; headers could not be evaluated.")

    findings = []
    status = Status.PASS
    headers = primary_response.headers

    for header in DISCLOSURE_HEADERS:
        value = headers.get(header)
        if not value:
            continue
        has_version = bool(VERSION_PATTERN.search(value))
        severity = Severity.LOW if has_version else Severity.INFO
        findings.append(
            Finding(
                id=f"DISC-{header.upper().replace('-', '_')}",
                title=f"{header} header discloses software information",
                severity=severity,
                category=CHECK_NAME,
                description=(
                    f"The {header} header reveals "
                    + ("a specific software version. " if has_version else "server/framework software. ")
                    + "This can help an attacker fingerprint known vulnerabilities for that exact version."
                ),
                evidence=f"{header}: {value}",
                recommendation=f"Consider suppressing or genericizing the {header} header in production.",
                confidence=Confidence.HIGH,
            )
        )
        if has_version:
            status = Status.WARN

    for header in DEBUG_HEADERS:
        if header in headers:
            findings.append(
                Finding(
                    id=f"DISC-{header.upper().replace('-', '_')}",
                    title=f"Debug header present: {header}",
                    severity=Severity.MEDIUM,
                    category=CHECK_NAME,
                    description="A debug-related header was present, which may indicate debug mode is enabled.",
                    evidence=f"{header}: {headers.get(header)}",
                    recommendation="Ensure debug modes and debug headers are disabled in production.",
                    confidence=Confidence.MEDIUM,
                )
            )
            status = Status.WARN

    if not findings:
        return CheckResult(name=CHECK_NAME, status=Status.PASS, findings=[],
                            summary="No issues detected by the implemented disclosure checks.")

    return CheckResult(name=CHECK_NAME, status=status, findings=findings,
                        summary=f"{len(findings)} information-disclosure observation(s) recorded.")
