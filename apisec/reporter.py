"""Report rendering for terminal, JSON, and standalone HTML output."""

from __future__ import annotations

import html
import json
import shutil
import sys
from datetime import datetime, timezone

from .models import ScanReport, Severity, Status

__version__ = "1.0.0"


class Colors:
    """ANSI color codes; disabled automatically on non-TTY output."""

    ENABLED = sys.stdout.isatty()

    RESET = "\033[0m" if ENABLED else ""
    BOLD = "\033[1m" if ENABLED else ""
    DIM = "\033[2m" if ENABLED else ""
    GREEN = "\033[32m" if ENABLED else ""
    YELLOW = "\033[33m" if ENABLED else ""
    RED = "\033[31m" if ENABLED else ""
    CYAN = "\033[36m" if ENABLED else ""
    BLUE = "\033[34m" if ENABLED else ""
    MAGENTA = "\033[35m" if ENABLED else ""


STATUS_COLOR = {
    Status.PASS: Colors.GREEN,
    Status.WARN: Colors.YELLOW,
    Status.FAIL: Colors.RED,
    Status.INFO: Colors.CYAN,
}

SEVERITY_COLOR = {
    Severity.INFO: Colors.CYAN,
    Severity.LOW: Colors.BLUE,
    Severity.MEDIUM: Colors.YELLOW,
    Severity.HIGH: Colors.RED,
    Severity.CRITICAL: Colors.MAGENTA,
}


def _grade_color(grade: str) -> str:
    return {
        "A": Colors.GREEN,
        "B": Colors.GREEN,
        "C": Colors.YELLOW,
        "D": Colors.RED,
        "F": Colors.RED,
    }.get(grade, Colors.RESET)


def render_terminal(report: ScanReport, show_findings: bool = True) -> str:
    width = min(shutil.get_terminal_size((80, 20)).columns, 78)
    lines = []
    title = f" APISecChecker v{__version__} "
    lines.append(Colors.BOLD + Colors.CYAN + "\u2554" + "\u2550" * (width - 2) + "\u2557" + Colors.RESET)
    lines.append(
        Colors.BOLD + Colors.CYAN + "\u2551" + title.center(width - 2) + "\u2551" + Colors.RESET
    )
    lines.append(Colors.BOLD + Colors.CYAN + "\u255a" + "\u2550" * (width - 2) + "\u255d" + Colors.RESET)
    lines.append("")
    lines.append(f"{Colors.BOLD}Target:{Colors.RESET} {report.target}")
    lines.append(
        f"{Colors.BOLD}Scanned:{Colors.RESET} "
        f"{datetime.fromtimestamp(report.timestamp, tz=timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}"
    )
    lines.append("")

    for result in report.check_results:
        color = STATUS_COLOR.get(result.status, Colors.RESET)
        label = f"[+] {result.name}".ljust(width - 12)
        lines.append(f"{label}{color}{Colors.BOLD}{result.status.value:>10}{Colors.RESET}")

    lines.append("")
    grade_color = _grade_color(report.grade)
    lines.append(f"{Colors.BOLD}Security Score:{Colors.RESET} {report.score}/100")
    lines.append(f"{Colors.BOLD}Grade:{Colors.RESET} {grade_color}{Colors.BOLD}{report.grade}{Colors.RESET}")
    lines.append(
        f"{Colors.DIM}This score is an automated heuristic and does not replace a "
        f"professional security assessment.{Colors.RESET}"
    )

    if report.errors:
        lines.append("")
        lines.append(f"{Colors.YELLOW}{Colors.BOLD}Scan notes:{Colors.RESET}")
        for err in report.errors:
            lines.append(f"  {Colors.YELLOW}- {err}{Colors.RESET}")

    if show_findings:
        findings = report.all_findings()
        if findings:
            lines.append("")
            lines.append(f"{Colors.BOLD}Findings ({len(findings)}):{Colors.RESET}")
            for f in findings:
                sev_color = SEVERITY_COLOR.get(f.severity, Colors.RESET)
                lines.append("")
                lines.append(f"  {sev_color}{Colors.BOLD}[{f.severity.value}]{Colors.RESET} {f.title}  {Colors.DIM}({f.id}){Colors.RESET}")
                lines.append(f"    {f.description}")
                if f.evidence:
                    lines.append(f"    {Colors.DIM}Evidence:{Colors.RESET} {f.evidence}")
                if f.recommendation:
                    lines.append(f"    {Colors.DIM}Recommendation:{Colors.RESET} {f.recommendation}")

    lines.append("")
    return "\n".join(lines)


def render_json(report: ScanReport) -> str:
    return json.dumps(report.to_dict(), indent=2, sort_keys=False)


def _severity_counts_html(report: ScanReport) -> str:
    counts = report.severity_summary()
    order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]
    cells = []
    for sev in order:
        cells.append(
            f'<div class="sev-box sev-{sev.value.lower()}">' 
            f'<div class="sev-count">{counts[sev.value]}</div>'
            f'<div class="sev-label">{sev.value}</div></div>'
        )
    return "".join(cells)


def render_html(report: ScanReport) -> str:
    findings = report.all_findings()
    scanned_at = datetime.fromtimestamp(report.timestamp, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    check_rows = "".join(
        f'<tr><td>{html.escape(r.name)}</td>'
        f'<td><span class="badge badge-{r.status.value.lower()}">{r.status.value}</span></td>'
        f'<td>{html.escape(r.summary)}</td></tr>'
        for r in report.check_results
    )

    finding_blocks = "".join(
        f'''<div class="finding sev-border-{f.severity.value.lower()}">
            <div class="finding-header">
                <span class="badge badge-{f.severity.value.lower()}">{f.severity.value}</span>
                <span class="finding-title">{html.escape(f.title)}</span>
                <span class="finding-id">{html.escape(f.id)}</span>
            </div>
            <p class="finding-desc">{html.escape(f.description)}</p>
            {f'<p class="finding-evidence"><strong>Evidence:</strong> {html.escape(f.evidence)}</p>' if f.evidence else ''}
            {f'<p class="finding-rec"><strong>Recommendation:</strong> {html.escape(f.recommendation)}</p>' if f.recommendation else ''}
            <p class="finding-meta">Category: {html.escape(f.category)} &middot; Confidence: {f.confidence.value}</p>
        </div>'''
        for f in findings
    ) or '<p class="no-findings">No issues detected by the implemented checks.</p>'

    errors_html = ""
    if report.errors:
        items = "".join(f"<li>{html.escape(e)}</li>" for e in report.errors)
        errors_html = f'<div class="scan-notes"><h3>Scan Notes</h3><ul>{items}</ul></div>'

    return f'''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>APISecChecker Report - {html.escape(report.target)}</title>
<style>
  :root {{
    --bg: #0f1117; --panel: #171a23; --border: #262b38; --text: #e6e8ef; --muted: #9aa2b1;
    --info: #3ba7db; --low: #4c7cf0; --medium: #d9a441; --high: #d9534f; --critical: #b5179e;
    --pass: #3fb950; --warn: #d9a441; --fail: #d9534f;
  }}
  * {{ box-sizing: border-box; }}
  body {{ font-family: -apple-system, Segoe UI, Roboto, Helvetica, Arial, sans-serif; background: var(--bg); color: var(--text); margin: 0; padding: 2rem; line-height: 1.5; }}
  .container {{ max-width: 900px; margin: 0 auto; }}
  h1 {{ font-size: 1.6rem; margin-bottom: 0.25rem; }}
  .subtitle {{ color: var(--muted); margin-bottom: 2rem; }}
  .panel {{ background: var(--panel); border: 1px solid var(--border); border-radius: 10px; padding: 1.5rem; margin-bottom: 1.5rem; }}
  .score-row {{ display: flex; align-items: center; gap: 2rem; flex-wrap: wrap; }}
  .score-circle {{ font-size: 2.4rem; font-weight: 700; }}
  .grade {{ font-size: 1.8rem; font-weight: 700; }}
  .disclaimer {{ color: var(--muted); font-size: 0.85rem; margin-top: 0.5rem; }}
  .sev-summary {{ display: flex; gap: 0.75rem; flex-wrap: wrap; margin-top: 1rem; }}
  .sev-box {{ border-radius: 8px; padding: 0.6rem 1rem; text-align: center; min-width: 70px; border: 1px solid var(--border); }}
  .sev-count {{ font-size: 1.3rem; font-weight: 700; }}
  .sev-label {{ font-size: 0.7rem; color: var(--muted); letter-spacing: 0.05em; }}
  table {{ width: 100%; border-collapse: collapse; }}
  th, td {{ text-align: left; padding: 0.5rem 0.6rem; border-bottom: 1px solid var(--border); font-size: 0.92rem; }}
  th {{ color: var(--muted); font-weight: 600; font-size: 0.8rem; text-transform: uppercase; }}
  .badge {{ display: inline-block; padding: 0.15rem 0.55rem; border-radius: 999px; font-size: 0.72rem; font-weight: 700; letter-spacing: 0.03em; }}
  .badge-pass {{ background: rgba(63,185,80,0.15); color: var(--pass); }}
  .badge-warn {{ background: rgba(217,164,65,0.15); color: var(--warn); }}
  .badge-fail {{ background: rgba(217,83,79,0.15); color: var(--fail); }}
  .badge-info {{ background: rgba(59,167,219,0.15); color: var(--info); }}
  .badge-low {{ background: rgba(76,124,240,0.15); color: var(--low); }}
  .badge-medium {{ background: rgba(217,164,65,0.15); color: var(--medium); }}
  .badge-high {{ background: rgba(217,83,79,0.15); color: var(--high); }}
  .badge-critical {{ background: rgba(181,23,158,0.18); color: var(--critical); }}
  .finding {{ background: var(--panel); border: 1px solid var(--border); border-left: 4px solid var(--border); border-radius: 8px; padding: 1rem 1.2rem; margin-bottom: 1rem; }}
  .sev-border-info {{ border-left-color: var(--info); }}
  .sev-border-low {{ border-left-color: var(--low); }}
  .sev-border-medium {{ border-left-color: var(--medium); }}
  .sev-border-high {{ border-left-color: var(--high); }}
  .sev-border-critical {{ border-left-color: var(--critical); }}
  .finding-header {{ display: flex; align-items: center; gap: 0.6rem; margin-bottom: 0.5rem; flex-wrap: wrap; }}
  .finding-title {{ font-weight: 700; }}
  .finding-id {{ margin-left: auto; color: var(--muted); font-size: 0.75rem; font-family: monospace; }}
  .finding-desc {{ margin: 0.3rem 0; }}
  .finding-evidence, .finding-rec {{ margin: 0.3rem 0; font-size: 0.9rem; color: var(--muted); }}
  .finding-evidence strong, .finding-rec strong {{ color: var(--text); }}
  .finding-meta {{ font-size: 0.75rem; color: var(--muted); margin-top: 0.5rem; }}
  .no-findings {{ color: var(--muted); }}
  .footer {{ color: var(--muted); font-size: 0.8rem; text-align: center; margin-top: 2rem; }}
  .scan-notes {{ color: var(--warn); }}
  code {{ background: rgba(255,255,255,0.06); padding: 0.1rem 0.35rem; border-radius: 4px; }}
</style>
</head>
<body>
<div class="container">
  <h1>APISecChecker Report</h1>
  <div class="subtitle">Target: <code>{html.escape(report.target)}</code> &middot; Scanned: {scanned_at}</div>

  <div class="panel">
    <h2>Executive Summary</h2>
    <div class="score-row">
      <div><div class="score-circle">{report.score}/100</div><div class="disclaimer">Security Score</div></div>
      <div><div class="grade">Grade {report.grade}</div></div>
    </div>
    <div class="sev-summary">{_severity_counts_html(report)}</div>
    <p class="disclaimer">This score is an automated heuristic and does not replace a professional security assessment. It reflects only the checks implemented by this tool.</p>
  </div>

  <div class="panel">
    <h2>Check Results</h2>
    <table>
      <thead><tr><th>Check</th><th>Status</th><th>Summary</th></tr></thead>
      <tbody>{check_rows}</tbody>
    </table>
    {errors_html}
  </div>

  <div class="panel">
    <h2>Findings ({len(findings)})</h2>
    {finding_blocks}
  </div>

  <div class="panel">
    <h2>Scan Metadata</h2>
    <table>
      <tr><th>Method</th><td>{html.escape(report.config.method)}</td></tr>
      <tr><th>Safe mode</th><td>{report.config.safe_mode}</td></tr>
      <tr><th>TLS verification</th><td>{report.config.verify_tls}</td></tr>
      <tr><th>Timeout</th><td>{report.config.timeout}s</td></tr>
    </table>
  </div>

  <p class="footer">
    Generated by APISecChecker v{__version__} &middot; Defensive, non-destructive API security auditor.<br>
    Only scan systems you own or are explicitly authorized to test.
  </p>
</div>
</body>
</html>
'''
