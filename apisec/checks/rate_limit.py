"""Rate-limit header detection.

Passively inspects the primary response for common rate-limiting headers.
This module never performs high-volume or repeated requests to test actual
rate-limiting behavior — that would itself risk a denial-of-service style
load on the target, which this tool explicitly refuses to do.
"""

from __future__ import annotations

from ..models import CheckResult, Confidence, Finding, ScanConfig, Severity, Status

CHECK_NAME = "Rate Limiting"

RATE_LIMIT_HEADERS = (
    "X-RateLimit-Limit",
    "X-RateLimit-Remaining",
    "X-RateLimit-Reset",
    "Retry-After",
    "RateLimit-Limit",
    "RateLimit-Remaining",
    "RateLimit-Reset",
)


def run(client, config: ScanConfig, primary_response) -> CheckResult:
    if not primary_response.ok:
        return CheckResult(name=CHECK_NAME, status=Status.INFO, findings=[],
                            summary="Primary request failed; rate-limit headers could not be evaluated.")

    lower_headers = {k.lower(): v for k, v in primary_response.headers.items()}
    observed = {h: lower_headers[h.lower()] for h in RATE_LIMIT_HEADERS if h.lower() in lower_headers}

    if not observed:
        return CheckResult(
            name=CHECK_NAME,
            status=Status.WARN,
            findings=[
                Finding(
                    id="RATE-001",
                    title="No observable rate-limit headers were detected",
                    severity=Severity.LOW,
                    category=CHECK_NAME,
                    description=(
                        "No standard rate-limiting headers were present on this response. "
                        "This does not prove that rate limiting is absent — it may be "
                        "enforced without being advertised via headers, e.g. at a "
                        "gateway or WAF layer."
                    ),
                    evidence="No rate-limit headers observed on a single request.",
                    recommendation="Confirm rate limiting is enforced server-side, and consider advertising limits via standard headers.",
                    confidence=Confidence.LOW,
                )
            ],
            summary="No rate-limit headers observed.",
        )

    evidence = "; ".join(f"{k}: {v}" for k, v in observed.items())
    return CheckResult(
        name=CHECK_NAME,
        status=Status.PASS,
        findings=[
            Finding(
                id="RATE-002",
                title="Rate-limit headers observed",
                severity=Severity.INFO,
                category=CHECK_NAME,
                description="The server advertises rate-limit information via response headers.",
                evidence=evidence,
                recommendation="No action required; informational only.",
                confidence=Confidence.HIGH,
            )
        ],
        summary="Rate-limit headers present.",
    )
