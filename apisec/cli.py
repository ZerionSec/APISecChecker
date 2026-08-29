"""Command-line interface for APISecChecker."""

from __future__ import annotations

import argparse
import sys
from typing import Dict, List, Optional

from . import reporter, scoring
from .models import ScanConfig
from .scanner import run_scan

__version__ = "1.0.0"

BANNER = f"""APISecChecker v{__version__}
Defensive API Security Auditor
"""

WARNING = """WARNING:
Only scan APIs that you own or have explicit permission to test.
This tool performs defensive, non-destructive checks. It will never attempt
to exploit vulnerabilities, brute-force credentials, bypass authentication,
or send data-modifying requests (PUT/DELETE/PATCH).
"""


def _parse_headers(header_list: Optional[List[str]]) -> Dict[str, str]:
    headers: Dict[str, str] = {}
    for item in header_list or []:
        if ":" not in item:
            raise argparse.ArgumentTypeError(
                f"Invalid header '{item}'. Expected format: 'Name: Value'"
            )
        name, value = item.split(":", 1)
        headers[name.strip()] = value.strip()
    return headers


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="apisecchecker.py",
        description=BANNER + "\n" + WARNING,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("-u", "--url", help="Target API URL")
    parser.add_argument("-m", "--method", default="GET", help="HTTP method for the primary request (default: GET)")
    parser.add_argument(
        "-H", "--header", action="append", dest="headers",
        help="Custom header, format 'Name: Value'. Can be used multiple times.",
    )
    parser.add_argument("-d", "--data", help="JSON request body for the primary request")
    parser.add_argument("--token", help="Explicit bearer/API token to use for authenticated checks (never logged in full)")
    parser.add_argument("--timeout", type=float, default=10.0, help="Request timeout in seconds (default: 10)")
    parser.add_argument("--output", help="Save report to FILE")
    parser.add_argument("--format", choices=["json", "html", "text"], default="text", help="Report format (default: text)")
    parser.add_argument("--no-tls-verify", action="store_true", help="Disable TLS certificate verification")
    parser.add_argument("--safe", action="store_true", help="Enable safe checks only (this is the default and only supported mode)")
    parser.add_argument("--no-findings", action="store_true", help="Hide detailed findings in terminal output (summary table only)")
    parser.add_argument("--version", action="store_true", help="Show version and exit")
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.version:
        print(f"APISecChecker v{__version__}")
        return 0

    if not args.url:
        parser.print_help()
        print("\nError: --url is required.", file=sys.stderr)
        return 2

    if args.method.upper() in ("DELETE", "PUT", "PATCH"):
        print(
            "Error: APISecChecker never sends DELETE/PUT/PATCH requests, even as the "
            "primary request method, to avoid any risk of modifying or deleting data.",
            file=sys.stderr,
        )
        return 2

    try:
        headers = _parse_headers(args.headers)
    except argparse.ArgumentTypeError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2

    if args.token:
        headers.setdefault("Authorization", f"Bearer {args.token}")

    print(reporter.Colors.BOLD + BANNER + reporter.Colors.RESET)
    print(WARNING)

    config = ScanConfig(
        url=args.url,
        method=args.method.upper(),
        headers=headers,
        data=args.data,
        timeout=args.timeout,
        verify_tls=not args.no_tls_verify,
        safe_mode=True,  # Safe mode is always on; --safe is accepted for clarity/compatibility.
        auth_token=args.token,
    )

    if not config.verify_tls:
        print(
            f"{reporter.Colors.YELLOW}Note: TLS verification is disabled for this scan.{reporter.Colors.RESET}\n"
        )

    print(f"Scanning: {config.url}\n")

    report = run_scan(config)
    scoring.score_report(report)

    if args.format == "json":
        output_text = reporter.render_json(report)
    elif args.format == "html":
        output_text = reporter.render_html(report)
    else:
        output_text = reporter.render_terminal(report, show_findings=not args.no_findings)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(output_text)
        print(f"Report saved to: {args.output}")
        if args.format == "text":
            # Also show the terminal summary even when saving to a text file.
            print(reporter.render_terminal(report, show_findings=not args.no_findings))
    else:
        print(output_text)

    if report.score < 60:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
