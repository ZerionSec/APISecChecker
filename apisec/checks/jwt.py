"""JWT structural analysis.

Parses a JWT — either explicitly supplied by the user or safely detected in
an authorized request's own Authorization header/response — and inspects
its header and claims for common hygiene issues (missing expiration,
already-expired tokens, suspicious algorithms). This module never attempts
to crack, forge, guess signing keys, or bypass JWT signatures; it only
decodes the base64url segments, which requires no secret.
"""

from __future__ import annotations

import base64
import binascii
import json
import time

from ..models import CheckResult, Confidence, Finding, ScanConfig, Severity, Status

CHECK_NAME = "JWT Analysis"

SUSPICIOUS_ALGORITHMS = {"none", "None", "NONE"}


def _b64url_decode(segment: str) -> bytes:
    padding = "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(segment + padding)


def _find_candidate_jwt(config: ScanConfig, primary_response) -> str:
    for value in config.headers.values():
        if value.count(".") == 2 and value.strip().lower().startswith("bearer "):
            candidate = value.split(" ", 1)[1].strip()
            if candidate.count(".") == 2:
                return candidate
    auth_header = config.headers.get("Authorization", "")
    if auth_header.count(".") == 2:
        return auth_header.split(" ")[-1]
    return ""


def run(client, config: ScanConfig, primary_response) -> CheckResult:
    token = config.auth_token if (config.auth_token and config.auth_token.count(".") == 2) else ""
    if not token:
        token = _find_candidate_jwt(config, primary_response)

    if not token:
        return CheckResult(
            name=CHECK_NAME, status=Status.INFO, findings=[],
            summary="No JWT supplied or detected; JWT analysis skipped.",
        )

    parts = token.split(".")
    if len(parts) != 3:
        return CheckResult(name=CHECK_NAME, status=Status.INFO, findings=[],
                            summary="Value did not have the 3-segment JWT structure; skipped.")

    findings = []
    status = Status.PASS

    try:
        header = json.loads(_b64url_decode(parts[0]))
    except (binascii.Error, ValueError, json.JSONDecodeError):
        return CheckResult(
            name=CHECK_NAME, status=Status.INFO, findings=[
                Finding(
                    id="JWT-000",
                    title="Value resembled a JWT but header could not be decoded",
                    severity=Severity.INFO,
                    category=CHECK_NAME,
                    description="The candidate token's header segment was not valid base64url JSON.",
                    evidence="N/A",
                    recommendation="No action required.",
                    confidence=Confidence.LOW,
                )
            ],
            summary="Candidate value was not a valid JWT.",
        )

    try:
        payload = json.loads(_b64url_decode(parts[1]))
    except (binascii.Error, ValueError, json.JSONDecodeError):
        payload = {}

    alg = header.get("alg", "unknown")
    findings.append(
        Finding(
            id="JWT-001",
            title="JWT structure decoded",
            severity=Severity.INFO,
            category=CHECK_NAME,
            description="Informational: JWT header fields observed (signature not verified or attacked).",
            evidence=f"alg={alg}, typ={header.get('typ', 'unknown')}",
            recommendation="No action required; informational only.",
            confidence=Confidence.HIGH,
        )
    )

    if alg in SUSPICIOUS_ALGORITHMS:
        findings.append(
            Finding(
                id="JWT-002",
                title='JWT uses the "none" algorithm',
                severity=Severity.CRITICAL,
                category=CHECK_NAME,
                description=(
                    'The JWT header declares alg="none", meaning the token is unsigned. '
                    "Servers that accept such tokens without rejecting the none algorithm "
                    "may be vulnerable to forged tokens."
                ),
                evidence=f"alg={alg}",
                recommendation='Reject tokens with alg="none" server-side; require a strong signing algorithm.',
                confidence=Confidence.HIGH,
            )
        )
        status = Status.FAIL

    exp = payload.get("exp")
    if exp is None:
        findings.append(
            Finding(
                id="JWT-003",
                title="JWT has no expiration claim",
                severity=Severity.MEDIUM,
                category=CHECK_NAME,
                description="The token does not include an `exp` (expiration) claim, so it may never expire.",
                evidence="exp claim: absent",
                recommendation="Issue tokens with a reasonable expiration (`exp`) claim.",
                confidence=Confidence.HIGH,
            )
        )
        status = Status.WARN if status == Status.PASS else status
    else:
        try:
            exp_val = float(exp)
            if exp_val < time.time():
                findings.append(
                    Finding(
                        id="JWT-004",
                        title="JWT is expired",
                        severity=Severity.INFO,
                        category=CHECK_NAME,
                        description="The supplied/detected token's `exp` claim is in the past.",
                        evidence=f"exp={exp_val}",
                        recommendation="No action required if this token was expected to be expired.",
                        confidence=Confidence.HIGH,
                    )
                )
        except (TypeError, ValueError):
            pass

    for claim in ("iss", "aud", "sub", "nbf", "iat"):
        if claim not in payload:
            findings.append(
                Finding(
                    id=f"JWT-MISSING-{claim.upper()}",
                    title=f"JWT missing '{claim}' claim",
                    severity=Severity.LOW,
                    category=CHECK_NAME,
                    description=f"The token does not include a '{claim}' claim, reducing validation strength.",
                    evidence=f"{claim} claim: absent",
                    recommendation=f"Consider including and validating the '{claim}' claim where applicable.",
                    confidence=Confidence.LOW,
                )
            )

    sensitive_claim_keys = {"password", "ssn", "credit_card", "secret", "private_key"}
    present_sensitive = sensitive_claim_keys & set(k.lower() for k in payload.keys())
    if present_sensitive:
        findings.append(
            Finding(
                id="JWT-005",
                title="Sensitive-looking data stored in JWT claims",
                severity=Severity.HIGH,
                category=CHECK_NAME,
                description=(
                    "The token payload contains claim names suggesting sensitive data is "
                    "embedded directly in the JWT, which is base64-encoded, not encrypted, "
                    "and readable by anyone holding the token."
                ),
                evidence=f"Claim name(s) observed: {', '.join(sorted(present_sensitive))}",
                recommendation="Avoid storing sensitive data directly in JWT claims; reference it server-side instead.",
                confidence=Confidence.MEDIUM,
            )
        )
        status = Status.WARN if status == Status.PASS else status

    return CheckResult(name=CHECK_NAME, status=status, findings=findings,
                        summary=f"JWT analyzed (alg={alg}).")
