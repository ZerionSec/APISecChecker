"""A safety-constrained HTTP client wrapper used by every check module.

All outbound requests made by APISecChecker go through this module so that
safety limits (timeouts, redirect caps, response-size caps, request counting,
and a small set of disallowed HTTP methods) are enforced in one place instead
of being re-implemented by each check.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Optional

import requests
from requests.exceptions import RequestException

# Methods this tool will never send automatically. Requests using these
# methods can be destructive on real-world APIs and are deliberately
# unsupported here regardless of any check's request.
DISALLOWED_METHODS = {"DELETE", "PUT", "PATCH"}


@dataclass
class SafeResponse:
    """A normalized, size-capped representation of an HTTP response."""

    status_code: Optional[int]
    headers: Dict[str, str]
    text: str
    elapsed_seconds: float
    url: str
    error: Optional[str] = None
    truncated: bool = False

    @property
    def ok(self) -> bool:
        return self.error is None and self.status_code is not None


class RequestBudgetExceeded(Exception):
    """Raised when a scan attempts to exceed its configured request budget."""


class SafeHttpClient:
    """Wraps `requests` with scanner-wide safety limits.

    - Enforces a configurable timeout on every request.
    - Caps the number of redirects followed.
    - Caps response body size read into memory.
    - Refuses to send destructive HTTP methods.
    - Tracks and limits the total number of requests issued in a scan.
    - Always identifies itself via a distinct User-Agent.
    """

    def __init__(
        self,
        timeout: float = 10.0,
        verify_tls: bool = True,
        max_redirects: int = 5,
        max_response_bytes: int = 5_000_000,
        user_agent: str = "APISecChecker/1.0 (+defensive-scanner)",
        max_requests: int = 40,
    ) -> None:
        self.timeout = timeout
        self.verify_tls = verify_tls
        self.max_redirects = max_redirects
        self.max_response_bytes = max_response_bytes
        self.user_agent = user_agent
        self.max_requests = max_requests
        self._request_count = 0
        self._session = requests.Session()
        self._session.max_redirects = max_redirects

    @property
    def request_count(self) -> int:
        return self._request_count

    def request(
        self,
        method: str,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        data: Optional[str] = None,
        allow_redirects: bool = True,
    ) -> SafeResponse:
        method = method.upper()
        if method in DISALLOWED_METHODS:
            return SafeResponse(
                status_code=None,
                headers={},
                text="",
                elapsed_seconds=0.0,
                url=url,
                error=(
                    f"Refused to send {method}: APISecChecker never issues "
                    "requests that could modify or delete server data."
                ),
            )

        if self._request_count >= self.max_requests:
            raise RequestBudgetExceeded(
                f"Request budget of {self.max_requests} exceeded; stopping to "
                "avoid excessive load on the target."
            )

        merged_headers = {"User-Agent": self.user_agent}
        if headers:
            merged_headers.update(headers)

        self._request_count += 1
        try:
            resp = self._session.request(
                method=method,
                url=url,
                headers=merged_headers,
                data=data,
                timeout=self.timeout,
                verify=self.verify_tls,
                allow_redirects=allow_redirects,
                stream=True,
            )
        except RequestException as exc:
            return SafeResponse(
                status_code=None,
                headers={},
                text="",
                elapsed_seconds=0.0,
                url=url,
                error=f"{type(exc).__name__}: {exc}",
            )

        truncated = False
        chunks = []
        total = 0
        try:
            for chunk in resp.iter_content(chunk_size=8192, decode_unicode=False):
                if not chunk:
                    continue
                total += len(chunk)
                if total > self.max_response_bytes:
                    truncated = True
                    break
                chunks.append(chunk)
        except RequestException as exc:
            resp.close()
            return SafeResponse(
                status_code=resp.status_code,
                headers=dict(resp.headers),
                text="",
                elapsed_seconds=resp.elapsed.total_seconds(),
                url=resp.url,
                error=f"Error reading response body: {exc}",
            )

        body_bytes = b"".join(chunks)
        try:
            text = body_bytes.decode(resp.encoding or "utf-8", errors="replace")
        except (LookupError, TypeError):
            text = body_bytes.decode("utf-8", errors="replace")

        safe_resp = SafeResponse(
            status_code=resp.status_code,
            headers=dict(resp.headers),
            text=text,
            elapsed_seconds=resp.elapsed.total_seconds(),
            url=resp.url,
            truncated=truncated,
        )
        resp.close()
        return safe_resp
