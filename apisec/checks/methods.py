"""HTTP method discovery.

Uses only safe, non-destructive requests (OPTIONS, HEAD, GET) to determine
which HTTP methods the server advertises as supported. Destructive methods
such as DELETE, PUT, and PATCH are never sent by this tool (enforced at the
HTTP client layer) — they are only reported if the server itself discloses
support for them via the Allow header.
"""

from __future__ import annotations

from ..models import CheckResult, Confidence, Finding, ScanConfig, Severity, Status

CHECK_NAME = "HTTP Methods"

POTENTIALLY_RISKY_METHODS = {"TRACE", "CONNECT", "PUT", "DELETE", "PATCH"}


def run(client, config: ScanConfig, primary_response) -> CheckResult:
    findings = []
    status = Status.PASS

    resp = client.request("OPTIONS", config.url)
    allow_header = None
    if resp.ok:
        allow_header = resp.headers.get("Allow") or resp.headers.get("Access-Control-Allow-Methods")

    if not allow_header:
        # OPTIONS often isn't implemented; that's not itself a finding.
        return CheckResult(
            name=CHECK_NAME, status=Status.INFO, findings=[
                Finding(
                    id="METH-000",
                    title="No Allow header advertised via OPTIONS",
                    severity=Severity.INFO,
                    category=CHECK_NAME,
                    description="The server did not advertise supported methods via an Allow header on OPTIONS.",
                    evidence="No Allow header present.",
                    recommendation="No action required; this is common for many API frameworks.",
                    confidence=Confidence.LOW,
                )
            ],
            summary="Server did not advertise methods via OPTIONS.",
        )

    methods = {m.strip().upper() for m in allow_header.split(",") if m.strip()}
    findings.append(
        Finding(
            id="METH-001",
            title="Advertised HTTP methods",
            severity=Severity.INFO,
            category=CHECK_NAME,
            description="Informational record of methods the server advertises as supported.",
            evidence=f"Allow: {allow_header}",
            recommendation="Ensure only intentionally supported methods are advertised.",
            confidence=Confidence.HIGH,
        )
    )

    risky = methods & POTENTIALLY_RISKY_METHODS
    if "TRACE" in risky:
        findings.append(
            Finding(
                id="METH-002",
                title="TRACE method appears to be enabled",
                severity=Severity.MEDIUM,
                category=CHECK_NAME,
                description=(
                    "The TRACE method appears supported. TRACE has historically been "
                    "associated with cross-site tracing (XST) style issues in some environments."
                ),
                evidence=f"Allow: {allow_header}",
                recommendation="Disable the TRACE method at the web server/reverse proxy level unless explicitly required.",
                confidence=Confidence.MEDIUM,
            )
        )
        status = Status.WARN

    if "CONNECT" in risky:
        findings.append(
            Finding(
                id="METH-003",
                title="CONNECT method appears to be enabled",
                severity=Severity.LOW,
                category=CHECK_NAME,
                description="The CONNECT method appears supported, which is unusual for a typical REST API.",
                evidence=f"Allow: {allow_header}",
                recommendation="Confirm CONNECT support is intentional (e.g. proxy functionality); disable if not needed.",
                confidence=Confidence.LOW,
            )
        )
        status = Status.WARN if status == Status.PASS else status

    write_methods = risky & {"PUT", "DELETE", "PATCH"}
    if write_methods:
        findings.append(
            Finding(
                id="METH-004",
                title="Data-modifying methods advertised",
                severity=Severity.LOW,
                category=CHECK_NAME,
                description=(
                    "The server advertises support for "
                    f"{', '.join(sorted(write_methods))}. This is often intentional for "
                    "a REST API, but confirm these endpoints correctly enforce "
                    "authentication and authorization."
                ),
                evidence=f"Allow: {allow_header}",
                recommendation="Confirm authentication/authorization is enforced on all state-changing methods. APISecChecker never sends these methods itself.",
                confidence=Confidence.LOW,
            )
        )

    return CheckResult(
        name=CHECK_NAME, status=status, findings=findings,
        summary=f"Advertised methods: {', '.join(sorted(methods))}",
    )
