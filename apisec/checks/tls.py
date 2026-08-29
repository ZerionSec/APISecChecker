"""HTTPS / TLS checks.

Verifies whether the target is served over HTTPS, whether HTTP redirects to
HTTPS, and inspects the TLS certificate for validity, expiration, and
hostname match. All checks here are passive: this module never attempts to
downgrade, strip, or otherwise interfere with TLS.
"""

from __future__ import annotations

import socket
import ssl
from datetime import datetime, timezone
from urllib.parse import urlparse

from ..http_client import SafeHttpClient
from ..models import CheckResult, Confidence, Finding, ScanConfig, Severity, Status

CHECK_NAME = "HTTPS / TLS"


def _inspect_certificate(hostname: str, port: int, timeout: float) -> dict:
    """Open a TLS connection purely to read certificate metadata (no data sent)."""
    context = ssl.create_default_context()
    info: dict = {}
    with socket.create_connection((hostname, port), timeout=timeout) as sock:
        with context.wrap_socket(sock, server_hostname=hostname) as ssock:
            cert = ssock.getpeercert()
            info["cert"] = cert
            info["tls_version"] = ssock.version()
    return info


def run(client: SafeHttpClient, config: ScanConfig, primary_response) -> CheckResult:
    findings = []
    parsed = urlparse(config.url)
    status = Status.PASS

    if parsed.scheme != "https":
        findings.append(
            Finding(
                id="TLS-001",
                title="Target is not using HTTPS",
                severity=Severity.HIGH,
                category=CHECK_NAME,
                description=(
                    "The target URL uses plain HTTP. Traffic, including any "
                    "credentials or tokens, may be transmitted unencrypted."
                ),
                evidence=f"Scheme observed: {parsed.scheme}",
                recommendation="Serve the API exclusively over HTTPS and redirect HTTP to HTTPS.",
                confidence=Confidence.HIGH,
            )
        )
        status = Status.FAIL

        redirect_resp = client.request("GET", parsed.geturl(), allow_redirects=False)
        if redirect_resp.ok and redirect_resp.status_code in (301, 302, 307, 308):
            location = redirect_resp.headers.get("Location", "")
            if location.startswith("https://"):
                findings.append(
                    Finding(
                        id="TLS-002",
                        title="HTTP redirects to HTTPS",
                        severity=Severity.INFO,
                        category=CHECK_NAME,
                        description="The HTTP endpoint redirects to an HTTPS URL, which is good practice.",
                        evidence=f"Redirected to: {location}",
                        recommendation="Continue enforcing HTTPS via HSTS once confirmed working.",
                        confidence=Confidence.HIGH,
                    )
                )
        return CheckResult(name=CHECK_NAME, status=status, findings=findings,
                            summary="Target does not use HTTPS.")

    hostname = parsed.hostname
    port = parsed.port or 443

    try:
        info = _inspect_certificate(hostname, port, config.timeout)
    except ssl.SSLCertVerificationError as exc:
        findings.append(
            Finding(
                id="TLS-003",
                title="TLS certificate failed verification",
                severity=Severity.HIGH,
                category=CHECK_NAME,
                description="The server's TLS certificate could not be verified against trusted CAs.",
                evidence=str(exc),
                recommendation="Install a valid certificate from a trusted certificate authority.",
                confidence=Confidence.HIGH,
            )
        )
        return CheckResult(name=CHECK_NAME, status=Status.FAIL, findings=findings,
                            summary="TLS certificate verification failed.")
    except (socket.timeout, OSError) as exc:
        findings.append(
            Finding(
                id="TLS-004",
                title="Unable to establish TLS connection for inspection",
                severity=Severity.INFO,
                category=CHECK_NAME,
                description="A direct TLS socket connection for certificate inspection failed.",
                evidence=str(exc),
                recommendation="Manually verify the certificate using an external tool if this persists.",
                confidence=Confidence.LOW,
            )
        )
        return CheckResult(name=CHECK_NAME, status=Status.INFO, findings=findings,
                            summary="Could not inspect certificate directly.")

    cert = info.get("cert") or {}
    tls_version = info.get("tls_version", "unknown")

    findings.append(
        Finding(
            id="TLS-005",
            title="TLS version in use",
            severity=Severity.INFO,
            category=CHECK_NAME,
            description="Informational: the TLS protocol version negotiated for this connection.",
            evidence=f"Negotiated protocol: {tls_version}",
            recommendation="Prefer TLS 1.2 or higher; disable TLS 1.0/1.1 if still enabled.",
            confidence=Confidence.HIGH,
        )
    )
    if tls_version in ("TLSv1", "TLSv1.1"):
        findings.append(
            Finding(
                id="TLS-006",
                title="Outdated TLS version negotiated",
                severity=Severity.MEDIUM,
                category=CHECK_NAME,
                description=f"The connection negotiated {tls_version}, which is considered outdated.",
                evidence=f"Negotiated protocol: {tls_version}",
                recommendation="Disable TLS 1.0/1.1 and require TLS 1.2+.",
                confidence=Confidence.HIGH,
            )
        )
        status = Status.WARN

    not_after = cert.get("notAfter")
    if not_after:
        try:
            expires = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
            days_left = (expires - datetime.now(timezone.utc)).days
            if days_left < 0:
                findings.append(
                    Finding(
                        id="TLS-007",
                        title="TLS certificate has expired",
                        severity=Severity.CRITICAL,
                        category=CHECK_NAME,
                        description="The server's TLS certificate expiration date is in the past.",
                        evidence=f"Certificate expired on {not_after}",
                        recommendation="Renew the TLS certificate immediately.",
                        confidence=Confidence.HIGH,
                    )
                )
                status = Status.FAIL
            elif days_left < 14:
                findings.append(
                    Finding(
                        id="TLS-008",
                        title="TLS certificate expiring soon",
                        severity=Severity.MEDIUM,
                        category=CHECK_NAME,
                        description=f"The TLS certificate expires in {days_left} day(s).",
                        evidence=f"Expires on {not_after}",
                        recommendation="Renew the certificate before it expires.",
                        confidence=Confidence.HIGH,
                    )
                )
                status = Status.WARN
        except ValueError:
            pass

    return CheckResult(
        name=CHECK_NAME,
        status=status,
        findings=findings,
        summary=f"HTTPS in use; TLS version {tls_version}.",
    )
