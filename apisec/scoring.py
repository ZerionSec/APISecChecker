"""Transparent, heuristic security scoring.

The score starts at 100 and deducts points per finding based on severity
weight, with diminishing returns for repeated low-severity findings so a
single noisy check can't dominate the score. The score is explicitly an
automated heuristic, not a substitute for a professional assessment.
"""

from __future__ import annotations

from typing import List, Tuple

from .models import Finding, ScanReport, Severity

GRADE_THRESHOLDS: List[Tuple[int, str]] = [
    (90, "A"),
    (80, "B"),
    (70, "C"),
    (60, "D"),
    (0, "F"),
]


def grade_for_score(score: int) -> str:
    for threshold, grade in GRADE_THRESHOLDS:
        if score >= threshold:
            return grade
    return "F"


def calculate_score(findings: List[Finding]) -> int:
    """Deduct points per finding, weighted by severity.

    To keep the score meaningful even when a check produces many low-severity
    informational-ish findings, deductions for LOW/INFO findings are capped
    in aggregate, while MEDIUM/HIGH/CRITICAL findings deduct their full
    weight every time (these matter regardless of volume).
    """
    score = 100.0
    low_info_deduction = 0.0
    low_info_cap = 15.0

    for finding in findings:
        weight = finding.severity.weight
        if finding.severity in (Severity.INFO, Severity.LOW):
            if low_info_deduction < low_info_cap:
                deduction = min(weight, low_info_cap - low_info_deduction)
                low_info_deduction += deduction
                score -= deduction
        else:
            score -= weight

    return max(0, min(100, round(score)))


def score_report(report: ScanReport) -> None:
    """Populate `report.score` and `report.grade` in place."""
    findings = report.all_findings()
    report.score = calculate_score(findings)
    report.grade = grade_for_score(report.score)
