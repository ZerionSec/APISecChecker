"""HTTP security header checks.

Inspects the primary response for the presence and quality of common
security-relevant headers. This module never treats a missing header as an
automatic vulnerability without context, since not every header is
applicable to every API (e.g. CSP is far more relevant to browser-rendered
content than to a pure JSON API), and reflects that nuance in severity.
"""

from __future__ import annotations

from ..models import CheckResult, Confidence, Finding, ScanConfig, Severity, Status

CHECK_NAME = "Security Headers"

# header_name -> (severity_if_missing, recommendation, why_it_matters)
HEADER_SPECS = {
    "Strict-Transport-Security": (
        Severity.MEDIUM,
        "Enable HSTS (e.g. `Strict-Transport-Security: max-age=31536000; includeSubDomains`) for HTTPS deployments.",
        "Without HSTS, clients may be susceptible to protocol-downgrade or SSL-stripping style attacks.",
    ),
    "X-Content-Type-Options": (
        Severity.LOW,
        "Add `X-Content-Type-Options: nosniff` to prevent MIME-sniffing.",
        "Prevents browsers from MIME-sniffing a response away from the declared Content-Type.",
    ),
    "Content-Security-Policy": (
        Severity.INFO,
        "Add a Content-Security-Policy if this endpoint ever serves browser-rendered content.",
        "CSP mitigates XSS and data-injection attacks in browser contexts; less critical for pure JSON APIs.",
    ),
    "X-Frame-Options": (
        Severity.INFO,
        "Add `X-Frame-Options: DENY` (or a frame-ancestors CSP directive) if this endpoint serves HTML.",
        "Helps prevent clickjacking on HTML-rendering endpoints; not applicable to pure JSON APIs.",
    ),
    "Referrer-Policy": (
        Severity.INFO,
        "Add a `Referrer-Policy` header (e.g. `no-referrer` or `strict-origin-when-cross-origin`).",
        "Controls how much referrer information is leaked to other origins.",
    ),
    "Permissions-Policy": (
        Severity.INFO,
        "Add a `Permissions-Policy` header to restrict browser feature access if HTML is served.",
        "Restricts access to sensitive browser features; mainly relevant to HTML-serving endpoints.",
    ),
}


def _looks_like_json_api(content_type: str) -> bool:
    content_type = content_type.lower()
    return "json" in content_type or "xml" in content_type


def run(client, config: ScanConfig, primary_response) -> CheckResult:
    findings = []
    status = Status.PASS

    if not primary_response.ok:
        return CheckResult(
            name=CHECK_NAME,
            status=Status.INFO,
            findings=[],
            summary="Primary request failed; headers could not be evaluated.",
        )

    resp_headers = {k: v for k, v in primary_response.headers.items()}
    lower_headers = {k.lower(): v for k, v in resp_headers.items()}
    content_type = lower_headers.get("content-type", "")
    is_api_like = _looks_like_json_api(content_type)

    for header, (severity, recommendation, why) in HEADER_SPECS.items():
        if header.lower() not in lower_headers:
            # Downgrade browser-oriented headers to INFO when the response is
            # clearly a JSON/XML API rather than browser-rendered content.
            effective_severity = severity
            if is_api_like and header in ("Content-Security-Policy", "X-Frame-Options", "Permissions-Policy"):
                effective_severity = Severity.INFO

            findings.append(
                Finding(
                    id=f"HDR-{header.upper().replace('-', '_')}",
                    title=f"Missing {header}",
                    severity=effective_severity,
                    category=CHECK_NAME,
                    description=why,
                    evidence="Header not present in response.",
                    recommendation=recommendation,
                    confidence=Confidence.MEDIUM,
                )
            )
            if effective_severity in (Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL):
                status = Status.WARN

    # Cache-Control: relevant mainly if response looks like it may carry
    # sensitive data (auth-related endpoints, tokens in body, etc.)
    if "cache-control" not in lower_headers:
        findings.append(
            Finding(
                id="HDR-CACHE-CONTROL",
                title="Missing Cache-Control header",
                severity=Severity.LOW,
                category=CHECK_NAME,
                description=(
                    "No Cache-Control header was present. If this endpoint returns "
                    "sensitive or per-user data, it should not be cacheable by "
                    "intermediate proxies or browsers."
                ),
                evidence="Header not present in response.",
                recommendation="Set `Cache-Control: no-store` on endpoints returning sensitive data.",
                confidence=Confidence.LOW,
            )
        )

    if not findings:
        return CheckResult(
            name=CHECK_NAME, status=Status.PASS, findings=[],
            summary="All checked security headers were present.",
        )

    return CheckResult(
        name=CHECK_NAME,
        status=status,
        findings=findings,
        summary=f"{len(findings)} header observation(s) recorded.",
    )
