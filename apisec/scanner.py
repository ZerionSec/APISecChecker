"""Scan orchestration.

Coordinates the safety-constrained HTTP client and every check module,
collects their results into a ScanReport, and performs a small amount of
scan-wide analysis (SSRF-relevant parameter naming) that doesn't warrant its
own module.
"""

from __future__ import annotations

from urllib.parse import parse_qs, urlparse

from .checks import (
    authentication,
    cors,
    disclosure,
    documentation,
    errors,
    headers,
    jwt,
    methods,
    rate_limit,
    response_analysis,
    secrets,
    tls,
)
from .http_client import RequestBudgetExceeded, SafeHttpClient
from .models import CheckResult, Confidence, Finding, ScanConfig, ScanReport, Severity, Status

# Checks are ordered so that cheap/foundational checks run first and the
# primary response is fetched exactly once, up front, and reused.
CHECK_MODULES = [
    tls,
    headers,
    cors,
    methods,
    authentication,
    secrets,
    jwt,
    rate_limit,
    disclosure,
    errors,
    documentation,
    response_analysis,
]

SSRF_INTERESTING_PARAMS = {
    "url", "callback", "redirect", "webhook", "image_url", "resource", "endpoint",
    "target", "dest", "destination", "return_url", "next",
}


def _check_ssrf_relevant_params(config: ScanConfig) -> CheckResult:
    """Passively flags parameter names that often accept attacker-influenced
    URLs (a common SSRF vector), without ever sending requests to internal
    IPs, cloud metadata endpoints, or otherwise probing SSRF behavior.
    """
    parsed = urlparse(config.url)
    query_params = set(parse_qs(parsed.query).keys())

    body_params = set()
    if config.data:
        try:
            import json as _json
            body_obj = _json.loads(config.data)
            if isinstance(body_obj, dict):
                body_params = set(body_obj.keys())
        except (ValueError, TypeError):
            pass

    all_params = {p.lower() for p in (query_params | body_params)}
    hits = all_params & SSRF_INTERESTING_PARAMS

    if not hits:
        return CheckResult(
            name="SSRF-Relevant Parameters", status=Status.INFO, findings=[],
            summary="No URL-fetching-style parameter names observed.",
        )

    finding = Finding(
        id="SSRF-001",
        title="Potential URL-fetching parameter detected",
        severity=Severity.LOW,
        category="SSRF-Relevant Parameters",
        description=(
            "One or more request parameters have names commonly associated with "
            "server-side URL fetching (e.g. webhooks, callbacks, redirects). "
            "APISecChecker does not test SSRF behavior; manual review is recommended."
        ),
        evidence=f"Parameter name(s): {', '.join(sorted(hits))}",
        recommendation="Manually review these parameters for server-side request forgery (SSRF) protections (allow-lists, blocking internal ranges, etc.).",
        confidence=Confidence.LOW,
    )
    return CheckResult(
        name="SSRF-Relevant Parameters", status=Status.WARN, findings=[finding],
        summary="Potential URL-fetching parameter(s) detected; manual review recommended.",
    )


def run_scan(config: ScanConfig) -> ScanReport:
    """Run every check module against the given configuration and return a report."""
    client = SafeHttpClient(
        timeout=config.timeout,
        verify_tls=config.verify_tls,
        max_redirects=config.max_redirects,
        max_response_bytes=config.max_response_bytes,
        user_agent=config.user_agent,
    )

    report = ScanReport(target=config.url, config=config)

    primary_response = client.request(
        config.method, config.url, headers=config.headers, data=config.data
    )
    if not primary_response.ok:
        report.errors.append(
            f"Primary request to {config.url} did not succeed: {primary_response.error or 'unknown error'}"
        )

    for module in CHECK_MODULES:
        try:
            result = module.run(client, config, primary_response)
            report.check_results.append(result)
        except RequestBudgetExceeded as exc:
            report.errors.append(str(exc))
            break
        except Exception as exc:  # noqa: BLE001 - a single check must never crash the whole scan
            report.errors.append(f"Check '{module.CHECK_NAME}' failed to complete: {exc}")
            report.check_results.append(
                CheckResult(
                    name=getattr(module, "CHECK_NAME", module.__name__),
                    status=Status.INFO,
                    findings=[],
                    summary="This check could not complete due to an internal error.",
                )
            )

    try:
        report.check_results.append(_check_ssrf_relevant_params(config))
    except Exception as exc:  # noqa: BLE001
        report.errors.append(f"SSRF parameter check failed: {exc}")

    return report
