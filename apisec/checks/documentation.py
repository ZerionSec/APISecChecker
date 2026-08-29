"""API documentation exposure and versioning detection.

Checks only a small, fixed list of common documentation paths (never a
broad crawl) to see whether API documentation such as Swagger/OpenAPI specs
are publicly reachable, and inspects the target URL for common versioning
patterns like /v1/ or /api/v2/.
"""

from __future__ import annotations

import re
from urllib.parse import urlparse

from ..models import CheckResult, Confidence, Finding, ScanConfig, Severity, Status

CHECK_NAME = "Documentation & Versioning"

DOC_PATHS = (
    "/swagger",
    "/swagger.json",
    "/swagger-ui.html",
    "/openapi.json",
    "/openapi.yaml",
    "/api-docs",
    "/docs",
    "/redoc",
)

VERSION_PATTERN = re.compile(r"/(?:api/)?v(\d+(?:\.\d+)?)(?:/|$)")


def run(client, config: ScanConfig, primary_response) -> CheckResult:
    findings = []
    status = Status.PASS
    parsed = urlparse(config.url)
    origin = f"{parsed.scheme}://{parsed.netloc}"

    version_match = VERSION_PATTERN.search(parsed.path)
    if version_match:
        findings.append(
            Finding(
                id="VER-001",
                title="API version detected in URL path",
                severity=Severity.INFO,
                category=CHECK_NAME,
                description="The target URL contains a versioning segment.",
                evidence=f"Path: {parsed.path} (version: v{version_match.group(1)})",
                recommendation="Maintain a documented deprecation policy for old API versions.",
                confidence=Confidence.HIGH,
            )
        )
    else:
        findings.append(
            Finding(
                id="VER-002",
                title="No API version detected in URL path",
                severity=Severity.INFO,
                category=CHECK_NAME,
                description="No common versioning pattern (e.g. /v1/, /api/v2/) was found in the URL path.",
                evidence=f"Path: {parsed.path}",
                recommendation="Consider explicit API versioning to manage breaking changes safely.",
                confidence=Confidence.LOW,
            )
        )

    exposed_docs = []
    for doc_path in DOC_PATHS:
        resp = client.request("GET", origin + doc_path)
        if resp.ok and resp.status_code == 200:
            exposed_docs.append((doc_path, resp.status_code))

    if exposed_docs:
        evidence = "; ".join(f"{path} -> {code}" for path, code in exposed_docs)
        findings.append(
            Finding(
                id="DOC-001",
                title="API documentation appears publicly accessible",
                severity=Severity.LOW,
                category=CHECK_NAME,
                description=(
                    "One or more common API documentation paths returned a successful "
                    "response. Publicly exposed documentation can reveal internal "
                    "endpoints, parameters, and data models to anyone."
                ),
                evidence=evidence,
                recommendation="Restrict documentation access to authorized users/networks in production, or confirm this exposure is intentional.",
                confidence=Confidence.MEDIUM,
            )
        )
        status = Status.WARN
    else:
        findings.append(
            Finding(
                id="DOC-002",
                title="No common documentation paths found",
                severity=Severity.INFO,
                category=CHECK_NAME,
                description="None of a small set of common documentation paths were found accessible.",
                evidence=f"Checked: {', '.join(DOC_PATHS)}",
                recommendation="No action required; informational only.",
                confidence=Confidence.LOW,
            )
        )

    return CheckResult(name=CHECK_NAME, status=status, findings=findings,
                        summary=f"{len(exposed_docs)} documentation path(s) publicly accessible.")
