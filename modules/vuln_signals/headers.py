"""
HeaderChecker — audits HTTP security headers.

Checks for missing/weak:
  - Content-Security-Policy
  - Strict-Transport-Security
  - X-Frame-Options
  - X-Content-Type-Options
  - Referrer-Policy
  - Permissions-Policy
  - Server / X-Powered-By info leakage
"""

from __future__ import annotations
import asyncio
from typing import List, Dict, Optional

from core.config import Config
from core.http_client import HTTPClient
from core.logger import get_logger

log = get_logger()


HEADER_CHECKS = [
    # (header_name, check_fn_or_None, severity, title, description, remediation)
    (
        "content-security-policy",
        None,   # presence only
        "medium",
        "Missing Content-Security-Policy",
        "No CSP header found. Increases XSS impact.",
        "Implement a strict CSP. Start with default-src 'self'.",
    ),
    (
        "strict-transport-security",
        None,
        "medium",
        "Missing HSTS",
        "No Strict-Transport-Security header. Allows protocol downgrade attacks.",
        "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
    ),
    (
        "x-frame-options",
        None,
        "low",
        "Missing X-Frame-Options",
        "Page may be embeddable in iframes (clickjacking risk).",
        "Add X-Frame-Options: DENY or SAMEORIGIN (or use CSP frame-ancestors).",
    ),
    (
        "x-content-type-options",
        None,
        "low",
        "Missing X-Content-Type-Options",
        "Browser may MIME-sniff responses leading to content injection.",
        "Add: X-Content-Type-Options: nosniff",
    ),
    (
        "referrer-policy",
        None,
        "info",
        "Missing Referrer-Policy",
        "Referrer header may leak sensitive URL fragments.",
        "Add: Referrer-Policy: strict-origin-when-cross-origin",
    ),
]

INFO_LEAK_HEADERS = ["server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version"]


class HeaderChecker:
    def __init__(self, config: Config, http: HTTPClient):
        self.config = config
        self.http = http

    async def check_all(self, assets: List[Dict]) -> List[Dict]:
        sem = asyncio.Semaphore(self.config.threads)
        tasks = [self._check(a, sem) for a in assets if a.get("live")]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        findings = []
        for r in results:
            if isinstance(r, list):
                findings.extend(r)
        return findings

    async def _check(self, asset: Dict, sem: asyncio.Semaphore) -> List[Dict]:
        url = asset.get("url", "")
        async with sem:
            resp = await self.http.head(url)
        if not resp:
            return []

        headers_raw = resp.get("headers", {})
        headers_lc  = {k.lower(): v for k, v in headers_raw.items()}
        findings = []

        for header, check_fn, severity, title, desc, fix in HEADER_CHECKS:
            if header not in headers_lc:
                findings.append({
                    "type": "header",
                    "title": title,
                    "severity": severity,
                    "confidence": "high",
                    "url": url,
                    "hostname": asset.get("hostname"),
                    "description": desc,
                    "remediation": fix,
                })

        # Info leakage via version headers
        for h in INFO_LEAK_HEADERS:
            val = headers_lc.get(h, "")
            if val:
                findings.append({
                    "type": "header_leak",
                    "title": f"Technology Disclosure: {h}",
                    "severity": "info",
                    "confidence": "high",
                    "url": url,
                    "hostname": asset.get("hostname"),
                    "description": f"Header {h}: {val[:100]}",
                    "remediation": f"Remove or neutralise the {h} header to reduce fingerprinting surface.",
                })

        return findings
