"""Response body analysis and HTTP status code interpretation.

Looks for sensitive-looking field names in JSON responses (passwords,
tokens, internal IDs, internal IPs/hostnames) without exposing their full
values, and provides contextual, non-accusatory interpretation of the
primary response's HTTP status code.
"""

from __future__ import annotations

import json
import re

from ..models import CheckResult, Confidence, Finding, ScanConfig, Severity, Status

CHECK_NAME = "Response Analysis"

SENSITIVE_FIELD_NAMES = {
    "password", "passwd", "secret", "token", "apikey", "api_key",
    "authorization", "private_key", "access_token", "refresh_token",
    "ssn", "credit_card", "card_number",
}

PRIVATE_IP_PATTERN = re.compile(
    r"\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|"
    r"172\.(1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3}|127\.0\.0\.1)\b"
)
INTERNAL_HOSTNAME_PATTERN = re.compile(r"\b[\w-]+\.(internal|local|corp|lan)\b", re.IGNORECASE)

STATUS_EXPLANATIONS = {
    200: ("OK", "Request succeeded."),
    201: ("Created", "A new resource was created."),
    204: ("No Content", "Request succeeded with no response body."),
    301: ("Moved Permanently", "The resource has permanently moved."),
    302: ("Found", "The resource is temporarily at a different location."),
    400: ("Bad Request", "The request was malformed or invalid."),
    401: ("Unauthorized", "Authentication is required and was missing or invalid."),
    403: ("Forbidden", "The client is authenticated but not authorized for this resource."),
    404: ("Not Found", "The requested resource does not exist at this path."),
    405: ("Method Not Allowed", "The HTTP method used is not supported for this resource."),
    409: ("Conflict", "The request conflicts with the current state of the resource."),
    429: ("Too Many Requests", "The client has been rate-limited."),
    500: ("Internal Server Error", "The server encountered an unexpected error."),
    502: ("Bad Gateway", "An upstream server returned an invalid response."),
    503: ("Service Unavailable", "The server is temporarily unable to handle the request."),
}


def _walk_json(obj, path, findings, seen):
    if isinstance(obj, dict):
        for key, value in obj.items():
            key_lower = str(key).lower()
            current_path = f"{path}.{key}" if path else str(key)
            if key_lower in SENSITIVE_FIELD_NAMES and key_lower not in seen:
                seen.add(key_lower)
                display_value = "REDACTED" if isinstance(value, str) and value else str(type(value).__name__)
                findings.append(
                    Finding(
                        id=f"RESP-{len(findings) + 1:03d}",
                        title=f"Sensitive-looking field name in response: '{key}'",
                        severity=Severity.MEDIUM,
                        category=CHECK_NAME,
                        description=(
                            f"A field named '{key}' was found in the response body. Field "
                            "names like this often carry sensitive data and generally "
                            "should not be returned to clients unless required."
                        ),
                        evidence=f"Path: {current_path}, value: {display_value}",
                        recommendation=f"Confirm '{key}' should be exposed in API responses; remove or mask it otherwise.",
                        confidence=Confidence.LOW,
                    )
                )
            _walk_json(value, current_path, findings, seen)
    elif isinstance(obj, list):
        for i, item in enumerate(obj[:20]):
            _walk_json(item, f"{path}[{i}]", findings, seen)


def run(client, config: ScanConfig, primary_response) -> CheckResult:
    findings = []
    status = Status.PASS

    if primary_response.ok and primary_response.text:
        try:
            parsed_body = json.loads(primary_response.text)
            seen: set = set()
            _walk_json(parsed_body, "", findings, seen)
        except (ValueError, TypeError):
            pass

        text_sample = primary_response.text[:20000]
        if PRIVATE_IP_PATTERN.search(text_sample):
            findings.append(
                Finding(
                    id="RESP-IP-001",
                    title="Internal/private IP address disclosed",
                    severity=Severity.MEDIUM,
                    category=CHECK_NAME,
                    description="The response body appears to contain a private/internal IP address.",
                    evidence="A private-range IP pattern was matched in the response body.",
                    recommendation="Avoid exposing internal network addressing in client-facing responses.",
                    confidence=Confidence.LOW,
                )
            )
            status = Status.WARN
        if INTERNAL_HOSTNAME_PATTERN.search(text_sample):
            findings.append(
                Finding(
                    id="RESP-HOST-001",
                    title="Internal-looking hostname disclosed",
                    severity=Severity.LOW,
                    category=CHECK_NAME,
                    description="The response body appears to contain an internal-style hostname (.internal, .local, .corp, .lan).",
                    evidence="An internal-looking hostname pattern was matched in the response body.",
                    recommendation="Avoid exposing internal hostnames in client-facing responses.",
                    confidence=Confidence.LOW,
                )
            )
            if status == Status.PASS:
                status = Status.WARN

    if primary_response.ok and primary_response.status_code is not None:
        code = primary_response.status_code
        name, explanation = STATUS_EXPLANATIONS.get(code, ("Unknown", "Unrecognized status code."))
        findings.append(
            Finding(
                id="RESP-STATUS",
                title=f"HTTP status {code} ({name})",
                severity=Severity.INFO,
                category=CHECK_NAME,
                description=explanation,
                evidence=f"Status code: {code}",
                recommendation="No action required; informational only.",
                confidence=Confidence.HIGH,
            )
        )
        if code >= 500:
            findings.append(
                Finding(
                    id="RESP-5XX",
                    title="Server error status returned",
                    severity=Severity.MEDIUM,
                    category=CHECK_NAME,
                    description="The primary request received a 5xx server error. This may indicate instability or unhandled exceptions.",
                    evidence=f"Status: {code}",
                    recommendation="Investigate server-side logs and ensure errors are handled gracefully without leaking details.",
                    confidence=Confidence.MEDIUM,
                )
            )
            status = Status.WARN

    if not findings:
        return CheckResult(
            name=CHECK_NAME, status=Status.INFO, findings=[],
            summary="No response-body or status observations recorded.",
        )

    return CheckResult(
        name=CHECK_NAME, status=status, findings=findings,
        summary=f"{len(findings)} response observation(s) recorded.",
    )
