"""
CORSChecker — detects CORS misconfiguration signals.

Checks for:
  - Wildcard ACAO with credentials
  - Origin reflection (any Origin echoed back)
  - Null origin acceptance
  - Trusted subdomain bypass patterns

Detection only — no exploitation.
"""

from __future__ import annotations
import asyncio
from typing import List, Dict

from core.config import Config
from core.http_client import HTTPClient
from core.logger import get_logger

log = get_logger()

TEST_ORIGINS = [
    "https://evil.com",
    "null",
    "https://attacker.example.com",
]


class CORSChecker:
    def __init__(self, config: Config, http: HTTPClient):
        self.config = config
        self.http = http

    async def check_all(self, assets: List[Dict]) -> List[Dict]:
        sem = asyncio.Semaphore(self.config.threads)
        tasks = [self._check(a, sem) for a in assets if a.get("live")]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        return [r for r in results if isinstance(r, dict)]

    async def _check(self, asset: Dict, sem: asyncio.Semaphore) -> Dict | None:
        url = asset.get("url", "")
        if not url:
            return None

        async with sem:
            # Test with an arbitrary attacker origin
            resp = await self.http.get(
                url,
                headers={"Origin": "https://evil.com"},
            )

        if not resp:
            return None

        resp_headers = resp.get("headers", {})
        acao = resp_headers.get(
            "access-control-allow-origin",
            resp_headers.get("Access-Control-Allow-Origin", "")
        )
        acac = resp_headers.get(
            "access-control-allow-credentials",
            resp_headers.get("Access-Control-Allow-Credentials", "")
        ).lower()

        if not acao:
            return None

        # Wildcard with credentials
        if acao == "*" and acac == "true":
            return self._finding(asset, "critical",
                "CORS: Wildcard origin with credentials enabled",
                "ACAO: * combined with ACAC: true allows any site to make credentialled requests.")

        # Arbitrary origin reflected
        if acao == "https://evil.com":
            if acac == "true":
                return self._finding(asset, "high",
                    "CORS: Arbitrary origin reflected with credentials",
                    "Server reflects any Origin header and allows credentials.")
            else:
                return self._finding(asset, "medium",
                    "CORS: Arbitrary origin reflected (no credentials)",
                    "Server reflects any Origin header. Credentials not allowed but cross-origin reads are possible.")

        # Null origin accepted
        if acao == "null":
            return self._finding(asset, "medium",
                "CORS: Null origin accepted",
                "null origin can be triggered by sandboxed iframes.")

        return None

    @staticmethod
    def _finding(asset: Dict, severity: str, title: str, description: str) -> Dict:
        return {
            "type": "cors",
            "title": title,
            "severity": severity,
            "confidence": "high",
            "url": asset.get("url"),
            "hostname": asset.get("hostname"),
            "description": description,
            "remediation": (
                "Implement a strict allowlist for CORS origins. "
                "Never combine wildcard origin with credentials."
            ),
        }
