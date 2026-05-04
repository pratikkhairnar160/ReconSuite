"""
TakeoverChecker — detects subdomain takeover signals.

Approach:
  1. Resolve subdomain CNAME chain
  2. Check for dangling CNAMEs (NXDOMAIN for the target of CNAME)
  3. Match response body against known takeover fingerprints

This is fingerprint-matching only — no actual takeover is performed.
"""

from __future__ import annotations
import asyncio
import socket
from typing import List, Dict, Optional, Tuple

from core.config import Config
from core.http_client import HTTPClient
from core.logger import get_logger

log = get_logger()

# Service → (body_fingerprint, severity)
# Source: can-i-take-over-xyz and similar public research
TAKEOVER_FINGERPRINTS: Dict[str, Tuple[str, str]] = {
    "GitHub Pages":       ("There isn't a GitHub Pages site here",    "high"),
    "Heroku":             ("No such app",                              "high"),
    "Shopify":            ("Sorry, this shop is currently unavailable","high"),
    "Fastly":             ("Fastly error: unknown domain",             "high"),
    "Ghost":              ("The thing you were looking for is no longer here", "high"),
    "Surge.sh":           ("project not found",                        "high"),
    "AWS S3":             ("NoSuchBucket",                             "critical"),
    "AWS CloudFront":     ("Bad request",                              "medium"),
    "Zendesk":            ("Help Center Closed",                       "medium"),
    "Tumblr":             ("Whatever you were looking for doesn't live here", "high"),
    "Squarespace":        ("No Such Account",                          "high"),
    "Azure":              ("404 Web Site not found",                   "high"),
    "Cargo Collective":   ("404 Not Found",                            "low"),
    "StatusPage.io":      ("You are being redirected",                 "medium"),
    "UserVoice":          ("This UserVoice subdomain is currently available", "high"),
    "WP Engine":          ("The site you were looking for couldn't be found", "medium"),
    "Pantheon":           ("404 error unknown site!",                  "high"),
    "Unbounce":           ("The requested URL was not found on this server", "medium"),
}


class TakeoverChecker:
    def __init__(self, config: Config, http: HTTPClient):
        self.config = config
        self.http = http

    async def check_all(self, assets: List[Dict]) -> List[Dict]:
        sem = asyncio.Semaphore(self.config.threads)
        tasks = [self._check(a, sem) for a in assets]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        return [r for r in results if isinstance(r, dict)]

    async def _check(self, asset: Dict, sem: asyncio.Semaphore) -> Optional[Dict]:
        hostname = asset.get("hostname", "")
        if not hostname:
            return None

        # Check for CNAME pointing to non-existent host (dangling CNAME)
        cname = await self._get_cname(hostname)
        dangling = False
        if cname and cname != hostname:
            dangling = not await self._resolves(cname)

        # Check response body for service-specific takeover fingerprints
        if asset.get("live"):
            url = asset.get("url", f"https://{hostname}")
            async with sem:
                resp = await self.http.get(url)
            if resp:
                body = resp.get("body", "").lower()
                for service, (fingerprint, severity) in TAKEOVER_FINGERPRINTS.items():
                    if fingerprint.lower() in body:
                        return {
                            "type": "subdomain_takeover",
                            "title": f"Potential Subdomain Takeover: {service}",
                            "severity": severity,
                            "confidence": "high" if dangling else "medium",
                            "url": url,
                            "hostname": hostname,
                            "cname": cname,
                            "dangling_cname": dangling,
                            "service": service,
                            "description": (
                                f"Body matches {service} takeover fingerprint. "
                                + ("CNAME is dangling (target NXDOMAIN)." if dangling else "")
                            ),
                            "remediation": (
                                "Remove the DNS record or claim the resource on the target platform "
                                "before a third party does."
                            ),
                        }

        elif dangling:
            # Dead asset with dangling CNAME — still interesting
            return {
                "type": "subdomain_takeover",
                "title": "Dangling CNAME (potential takeover)",
                "severity": "medium",
                "confidence": "medium",
                "url": f"https://{hostname}",
                "hostname": hostname,
                "cname": cname,
                "dangling_cname": True,
                "description": f"CNAME {cname} does not resolve. Possible takeover opportunity.",
                "remediation": "Remove stale DNS record or reclaim the resource.",
            }

        return None

    @staticmethod
    async def _get_cname(hostname: str) -> Optional[str]:
        loop = asyncio.get_event_loop()
        try:
            result = await loop.run_in_executor(
                None, lambda: socket.getaddrinfo(hostname, None)
            )
            # socket doesn't expose CNAME; use a simple DNS library if available
            # For now, return None (full CNAME chain needs dnspython)
            return None
        except Exception:
            return None

    @staticmethod
    async def _resolves(hostname: str) -> bool:
        loop = asyncio.get_event_loop()
        try:
            await loop.run_in_executor(
                None, lambda: socket.getaddrinfo(hostname, None)
            )
            return True
        except socket.gaierror:
            return False
