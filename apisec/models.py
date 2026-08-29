"""Data models used across APISecChecker.

This module defines the core data structures shared by every check module:
Severity levels, Confidence levels, the Finding record itself, and the
container used to collect all findings produced during a scan.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class Severity(str, Enum):
    """Severity levels for a finding, ordered from least to most severe."""

    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    @property
    def weight(self) -> int:
        """Numeric weight used by the scoring engine."""
        return {
            Severity.INFO: 0,
            Severity.LOW: 3,
            Severity.MEDIUM: 8,
            Severity.HIGH: 15,
            Severity.CRITICAL: 25,
        }[self]


class Confidence(str, Enum):
    """How confident the check is in a given finding."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


class Status(str, Enum):
    """Pass/warn/fail/info status used for the terminal summary table."""

    PASS = "PASS"
    WARN = "WARN"
    FAIL = "FAIL"
    INFO = "INFO"


@dataclass
class Finding:
    """A single security observation produced by a check module.

    Findings are intentionally descriptive rather than accusatory: they
    report what was observed and why it may matter, and never claim a
    definitive exploit or vulnerability was confirmed unless that is
    genuinely true of a passive/non-destructive check.
    """

    id: str
    title: str
    severity: Severity
    category: str
    description: str
    evidence: str = ""
    recommendation: str = ""
    confidence: Confidence = Confidence.MEDIUM

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "severity": self.severity.value,
            "category": self.category,
            "description": self.description,
            "evidence": self.evidence,
            "recommendation": self.recommendation,
            "confidence": self.confidence.value,
        }


@dataclass
class CheckResult:
    """The summary status + findings produced by a single check module."""

    name: str
    status: Status
    findings: List[Finding] = field(default_factory=list)
    summary: str = ""


@dataclass
class ScanConfig:
    """Configuration for a single scan run."""

    url: str
    method: str = "GET"
    headers: Dict[str, str] = field(default_factory=dict)
    data: Optional[str] = None
    timeout: float = 10.0
    verify_tls: bool = True
    safe_mode: bool = True
    auth_token: Optional[str] = None
    max_redirects: int = 5
    max_response_bytes: int = 5_000_000
    user_agent: str = "APISecChecker/1.0 (+defensive-scanner)"

    def to_dict(self) -> Dict[str, Any]:
        redacted_headers = {
            k: ("REDACTED" if k.lower() in ("authorization", "cookie", "x-api-key", "x-auth-token") else v)
            for k, v in self.headers.items()
        }
        return {
            "url": self.url,
            "method": self.method,
            "headers": redacted_headers,
            "timeout": self.timeout,
            "verify_tls": self.verify_tls,
            "safe_mode": self.safe_mode,
            "auth_provided": bool(self.auth_token),
        }


@dataclass
class ScanReport:
    """The complete result of a scan: metadata, all check results, and score."""

    target: str
    config: ScanConfig
    check_results: List[CheckResult] = field(default_factory=list)
    score: int = 0
    grade: str = "N/A"
    timestamp: float = field(default_factory=time.time)
    errors: List[str] = field(default_factory=list)

    def all_findings(self) -> List[Finding]:
        findings: List[Finding] = []
        for result in self.check_results:
            findings.extend(result.findings)
        return findings

    def severity_summary(self) -> Dict[str, int]:
        counts = {s.value: 0 for s in Severity}
        for finding in self.all_findings():
            counts[finding.severity.value] += 1
        return counts

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "timestamp": self.timestamp,
            "scan_configuration": self.config.to_dict(),
            "summary": {
                "checks_run": len(self.check_results),
                "total_findings": len(self.all_findings()),
                "severity_summary": self.severity_summary(),
                "check_statuses": {r.name: r.status.value for r in self.check_results},
            },
            "score": self.score,
            "grade": self.grade,
            "findings": [f.to_dict() for f in self.all_findings()],
            "recommendations": [
                f.recommendation for f in self.all_findings() if f.recommendation
            ],
            "errors": self.errors,
            "disclaimer": (
                "This score is an automated heuristic and does not replace a "
                "professional security assessment."
            ),
        }
