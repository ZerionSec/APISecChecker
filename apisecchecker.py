#!/usr/bin/env python3
"""APISecChecker entry point.

Run:
    python3 apisecchecker.py --url https://api.example.com --safe --format html --output report.html

See `python3 apisecchecker.py --help` for all options, and README.md for
full documentation, the security model, and legal/authorization requirements.
"""

import sys

from apisec.cli import main

if __name__ == "__main__":
    sys.exit(main())
