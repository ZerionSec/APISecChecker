"""Authentication detection.

Passively determines whether the API appears to require authentication, and
if the user has explicitly supplied a test token, safely compares the
unauthenticated vs. authenticated response status codes. This module never
attempts to guess, brute-force, or bypass credentials, and never prints
secret values — all sensitive header values are masked before use in any
finding.
"""

from __future__ import annotations

from ..models import CheckResult, Confidence, Finding, ScanConfig, Severity, Status

CHECK_NAME = "Authentication Detection"

AUTH_HEADER_NAMES = ("authorization", "x-api-key", "x-auth-token", "cookie")


def _mask(value: str) -> str:
    if not value:
        return ""
    if len(value) <= 10:
        return value[:2] + "*" * max(len(value) - 2, 0)
    return value[:10] + "...REDACTED"


def run(client, config: ScanConfig, primary_response) -> CheckResult:
    findings = []
    status = Status.INFO

    request_auth_headers = [h for h in config.headers if h.lower() in AUTH_HEADER_NAMES]
    if request_auth_headers:
        shown = ", ".join(
            f"{h}: {_mask(config.headers[h])}" for h in request_auth_headers
        )
        findings.append(
            Finding(
                id="AUTH-001",
                title="Authentication material supplied by user",
                severity=Severity.INFO,
                category=CHECK_NAME,
                description="The scan was run with user-supplied authentication headers (values masked).",
                evidence=shown,
                recommendation="No action required; informational only.",
                confidence=Confidence.HIGH,
            )
        )

    if not primary_response.ok:
        return CheckResult(
            name=CHECK_NAME, status=Status.INFO, findings=findings,
            summary="Primary request failed; authentication behavior could not be evaluated.",
        )

    status_code = primary_response.status_code
    www_authenticate = primary_response.headers.get("WWW-Authenticate")

    if status_code in (401, 403):
        findings.append(
            Finding(
                id="AUTH-002",
                title="Endpoint appears to require authentication",
                severity=Severity.INFO,
                category=CHECK_NAME,
                description=(
                    f"An unauthenticated request received HTTP {status_code}, suggesting "
                    "the endpoint requires authentication or authorization."
                ),
                evidence=(
                    f"Status: {status_code}"
                    + (f"; WWW-Authenticate: {www_authenticate}" if www_authenticate else "")
                ),
                recommendation="No action required; this is expected behavior for a protected endpoint.",
                confidence=Confidence.HIGH,
            )
        )
        status = Status.PASS
    elif status_code == 200 and not request_auth_headers:
        findings.append(
            Finding(
                id="AUTH-003",
                title="Endpoint responded successfully without authentication",
                severity=Severity.LOW,
                category=CHECK_NAME,
                description=(
                    "A request sent without any authentication headers received a "
                    "successful (200) response. This may be intentional for a public "
                    "endpoint, or may indicate missing access controls."
                ),
                evidence=f"Status: {status_code}",
                recommendation="Confirm that this endpoint is intended to be publicly accessible without authentication.",
                confidence=Confidence.LOW,
            )
        )
        status = Status.WARN

    # Only compare auth vs. no-auth behavior if the user explicitly provided
    # a token for this purpose — never generated or guessed by the tool.
    if config.auth_token and request_auth_headers:
        unauth_headers = {k: v for k, v in config.headers.items() if k.lower() not in AUTH_HEADER_NAMES}
        unauth_resp = client.request(config.method, config.url, headers=unauth_headers, data=config.data)
        if unauth_resp.ok:
            findings.append(
                Finding(
                    id="AUTH-004",
                    title="Authenticated vs. unauthenticated response comparison",
                    severity=Severity.INFO,
                    category=CHECK_NAME,
                    description="Comparison of response status codes with and without the supplied credential.",
                    evidence=(
                        f"With auth: {status_code}; without auth: {unauth_resp.status_code}"
                    ),
                    recommendation=(
                        "If both requests return the same successful status code, verify "
                        "that authentication is actually being enforced server-side."
                    ),
                    confidence=Confidence.MEDIUM,
                )
            )
            if unauth_resp.status_code == status_code == 200:
                findings.append(
                    Finding(
                        id="AUTH-005",
                        title="Identical success response with and without credentials",
                        severity=Severity.MEDIUM,
                        category=CHECK_NAME,
                        description=(
                            "The endpoint returned an identical successful status code "
                            "regardless of whether the supplied credential was included. "
                            "This may indicate authentication is not being enforced on "
                            "this endpoint."
                        ),
                        evidence=f"Both requests returned status {status_code}.",
                        recommendation="Verify server-side that this endpoint enforces authentication as intended.",
                        confidence=Confidence.MEDIUM,
                    )
                )
                status = Status.WARN

    if not findings:
        findings.append(
            Finding(
                id="AUTH-006",
                title="No clear authentication signal detected",
                severity=Severity.INFO,
                category=CHECK_NAME,
                description="Could not determine authentication requirements from this single request.",
                evidence=f"Status: {status_code}",
                recommendation="Manually verify the authentication model for this API.",
                confidence=Confidence.LOW,
            )
        )

    return CheckResult(name=CHECK_NAME, status=status, findings=findings,
                        summary="Authentication behavior recorded.")
