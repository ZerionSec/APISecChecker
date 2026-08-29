"""Individual, modular security check implementations.

Each module in this package exposes a single `run(...)` function that
accepts a `SafeHttpClient`, a `ScanConfig`, and the primary response already
fetched by the scanner, and returns a `CheckResult`. Checks are intentionally
independent of one another so they can be tested, extended, or disabled
individually.
"""
