"""
OpenRedirectChecker — detects open redirect signals in URL parameters.

Approach:
  - Look for redirect-like parameters in known URL patterns
  - Send a non-redirecting probe with a canary domain
  - Check Location header for reflection
  - Tag confidence based on match quality

Detection only — the canary URL is never fetched or used maliciously.
"""

from __future__ import annotations
import asyncio
from typing import List, Dict
from urllib.parse import urlencode, urlparse, parse_qsl, urljoin

from core.config import Config
from core.http_client import HTTPClient
from core.logger import get_logger

log = get_logger()

CANARY = "https://evil.example.com/redirect-test"

# Common redirect parameter names
REDIRECT_PARAMS = [
    "url", "redirect", "redirect_url", "redirect_uri", "return",
    "return_url", "returnUrl", "return_to", "next", "goto",
    "target", "destination", "dest", "forward", "forward_url",
    "continue", "back", "backUrl", "checkout_url", "success_url",
    "cancel_url", "callback", "redir", "r", "u", "q",
]


class OpenRedirectChecker:
    def __init__(self, config: Config, http: HTTPClient):
        self.config = config
        self.http = http

    async def check_all(self, assets: List[Dict]) -> List[Dict]:
        sem = asyncio.Semaphore(self.config.threads)
        tasks = [self._check(a, sem) for a in assets if a.get("live")]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        return [r for r in results if isinstance(r, dict)]

    async def _check(self, asset: Dict, sem: asyncio.Semaphore) -> Dict | None:
        base_url = asset.get("url", "").rstrip("/")
        if not base_url:
            return None

        for param in REDIRECT_PARAMS:
            test_url = f"{base_url}/?{param}={CANARY}"
            async with sem:
                resp = await self.http.get(test_url, allow_redirects=False)
            if not resp:
                continue

            status   = resp.get("status", 0)
            location = resp.get("location", "")

            # 3xx with our canary in Location = open redirect signal
            if status in (301, 302, 303, 307, 308) and CANARY in location:
                return {
                    "type": "open_redirect",
                    "title": f"Open Redirect via '{param}' parameter",
                    "severity": "medium",
                    "confidence": "high",
                    "url": test_url,
                    "hostname": asset.get("hostname"),
                    "parameter": param,
                    "status": status,
                    "location": location,
                    "description": (
                        f"Parameter '{param}' at {base_url} redirects to attacker-controlled URL. "
                        "Can be used in phishing and OAuth token theft chains."
                    ),
                    "remediation": (
                        "Validate redirect destinations against an allowlist. "
                        "Never redirect to user-supplied URLs without validation."
                    ),
                }

        return None
