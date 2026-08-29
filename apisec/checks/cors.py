"""CORS configuration checks.

Sends a single safe OPTIONS (preflight-style) request and analyzes the
CORS-related response headers for risky combinations, such as a wildcard
origin combined with credentialed access. This module never attempts to
exploit CORS misconfigurations; it only reports on headers observed.
"""

from __future__ import annotations

from ..models import CheckResult, Confidence, Finding, ScanConfig, Severity, Status

CHECK_NAME = "CORS"


def run(client, config: ScanConfig, primary_response) -> CheckResult:
    findings = []
    status = Status.PASS

    probe_headers = dict(config.headers)
    probe_headers["Origin"] = "https://example-origin-test.invalid"
    probe_headers["Access-Control-Request-Method"] = "GET"

    resp = client.request("OPTIONS", config.url, headers=probe_headers)

    if not resp.ok:
        # Fall back to reading CORS headers off the primary response, since
        # many APIs don't implement OPTIONS at all.
        resp = primary_response
        if not resp.ok:
            return CheckResult(
                name=CHECK_NAME, status=Status.INFO, findings=[],
                summary="Could not evaluate CORS; no successful response available.",
            )

    lower_headers = {k.lower(): v for k, v in resp.headers.items()}
    allow_origin = lower_headers.get("access-control-allow-origin")
    allow_credentials = lower_headers.get("access-control-allow-credentials", "").lower()
    allow_methods = lower_headers.get("access-control-allow-methods")
    allow_headers = lower_headers.get("access-control-allow-headers")

    if allow_origin is None:
        return CheckResult(
            name=CHECK_NAME, status=Status.INFO, findings=[
                Finding(
                    id="CORS-000",
                    title="No CORS headers observed",
                    severity=Severity.INFO,
                    category=CHECK_NAME,
                    description="The response did not include Access-Control-Allow-Origin.",
                    evidence="Header not present.",
                    recommendation="If this API is meant to be called from browsers on other origins, configure CORS explicitly.",
                    confidence=Confidence.MEDIUM,
                )
            ],
            summary="No CORS headers present.",
        )

    findings.append(
        Finding(
            id="CORS-001",
            title="Access-Control-Allow-Origin observed",
            severity=Severity.INFO,
            category=CHECK_NAME,
            description="Informational record of the CORS origin policy observed.",
            evidence=f"Access-Control-Allow-Origin: {allow_origin}",
            recommendation="Restrict to specific trusted origins where possible.",
            confidence=Confidence.HIGH,
        )
    )

    if allow_origin == "*" and allow_credentials == "true":
        findings.append(
            Finding(
                id="CORS-002",
                title="Wildcard origin combined with credentialed access",
                severity=Severity.HIGH,
                category=CHECK_NAME,
                description=(
                    "The server advertises Access-Control-Allow-Origin: * together with "
                    "Access-Control-Allow-Credentials: true. Per the CORS specification "
                    "compliant browsers should reject this combination, but it indicates "
                    "a misconfiguration that may behave unexpectedly across clients."
                ),
                evidence=(
                    f"Access-Control-Allow-Origin: {allow_origin}; "
                    f"Access-Control-Allow-Credentials: {allow_credentials}"
                ),
                recommendation="Reflect a specific allow-list of trusted origins instead of using a wildcard when credentials are allowed.",
                confidence=Confidence.HIGH,
            )
        )
        status = Status.FAIL
    elif allow_origin == "*":
        findings.append(
            Finding(
                id="CORS-003",
                title="Wildcard CORS origin",
                severity=Severity.LOW,
                category=CHECK_NAME,
                description=(
                    "The API allows requests from any origin. This is common and often "
                    "intentional for public, read-only, non-credentialed APIs."
                ),
                evidence=f"Access-Control-Allow-Origin: {allow_origin}",
                recommendation="Confirm this is intentional; restrict to known origins for sensitive endpoints.",
                confidence=Confidence.MEDIUM,
            )
        )
        status = Status.WARN if status == Status.PASS else status
    else:
        if allow_origin == probe_headers["Origin"]:
            findings.append(
                Finding(
                    id="CORS-004",
                    title="Origin appears to be reflected without validation",
                    severity=Severity.MEDIUM,
                    category=CHECK_NAME,
                    description=(
                        "The server reflected back an arbitrary, non-existent test "
                        "origin in Access-Control-Allow-Origin instead of rejecting it "
                        "or matching against a known allow-list."
                    ),
                    evidence=f"Sent Origin: {probe_headers['Origin']} -> reflected: {allow_origin}",
                    recommendation="Validate the Origin header against an explicit allow-list rather than reflecting it.",
                    confidence=Confidence.MEDIUM,
                )
            )
            status = Status.WARN if status == Status.PASS else status

    if allow_methods:
        findings.append(
            Finding(
                id="CORS-005",
                title="Allowed CORS methods observed",
                severity=Severity.INFO,
                category=CHECK_NAME,
                description="Informational record of methods permitted via CORS.",
                evidence=f"Access-Control-Allow-Methods: {allow_methods}",
                recommendation="Limit to the methods the API actually needs to expose cross-origin.",
                confidence=Confidence.HIGH,
            )
        )

    if allow_headers:
        findings.append(
            Finding(
                id="CORS-006",
                title="Allowed CORS headers observed",
                severity=Severity.INFO,
                category=CHECK_NAME,
                description="Informational record of headers permitted via CORS.",
                evidence=f"Access-Control-Allow-Headers: {allow_headers}",
                recommendation="Limit to headers actually required by legitimate clients.",
                confidence=Confidence.HIGH,
            )
        )

    return CheckResult(
        name=CHECK_NAME, status=status, findings=findings,
        summary=f"CORS policy observed: Access-Control-Allow-Origin = {allow_origin}",
    )
