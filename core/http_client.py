"""
Shared async HTTP client.

Wraps aiohttp with:
  - Configurable rate limiting (token-bucket style)
  - Proxy support
  - User-Agent rotation
  - Retry + timeout logic
  - Safe defaults (no auto-follows that mask behaviour)
"""

from __future__ import annotations
import asyncio
import random
import time
from typing import Optional, Dict, Any

import aiohttp

from core.config import Config
from core.logger import get_logger

log = get_logger()

# Default UA pool — realistic browser strings
DEFAULT_UA_POOL = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/124.0.0.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1",
]

RECON_UA = "Mozilla/5.0 (compatible; ReconSuite/1.0; +https://github.com/your/reconsuite)"


class RateLimiter:
    """Simple token-bucket rate limiter."""

    def __init__(self, rate: int):
        self.rate = max(1, rate)
        self._tokens = float(self.rate)
        self._last = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self):
        async with self._lock:
            now = time.monotonic()
            elapsed = now - self._last
            self._tokens = min(self.rate, self._tokens + elapsed * self.rate)
            self._last = now
            if self._tokens < 1:
                sleep_for = (1 - self._tokens) / self.rate
                await asyncio.sleep(sleep_for)
                self._tokens = 0
            else:
                self._tokens -= 1


class HTTPClient:
    def __init__(self, config: Config):
        self.config = config
        self._session: Optional[aiohttp.ClientSession] = None
        self._rate_limiter = RateLimiter(config.rate_limit)

    async def __aenter__(self):
        connector = aiohttp.TCPConnector(
            limit=self.config.threads,
            ssl=False,                  # certs often self-signed on recon targets
            ttl_dns_cache=300,
        )
        timeout = aiohttp.ClientTimeout(
            total=self.config.timeout,
            connect=min(5, self.config.timeout),
        )
        self._session = aiohttp.ClientSession(
            connector=connector,
            timeout=timeout,
        )
        return self

    async def __aexit__(self, *_):
        if self._session:
            await self._session.close()

    def _ua(self) -> str:
        if self.config.user_agent:
            return self.config.user_agent
        if self.config.rotate_ua:
            return random.choice(DEFAULT_UA_POOL)
        return RECON_UA

    def _headers(self, extra: Optional[Dict] = None) -> Dict[str, str]:
        h = {"User-Agent": self._ua()}
        if extra:
            h.update(extra)
        return h

    async def get(
        self,
        url: str,
        headers: Optional[Dict] = None,
        allow_redirects: bool = True,
        return_headers: bool = False,
    ) -> Optional[Dict[str, Any]]:
        """
        Perform a GET request with rate limiting and retries.

        Returns a structured dict or None on failure.
        """
        await self._rate_limiter.acquire()
        if self.config.delay > 0:
            await asyncio.sleep(self.config.delay)

        req_headers = self._headers(headers)
        proxy = self.config.proxy

        for attempt in range(self.config.retries + 1):
            try:
                async with self._session.get(
                    url,
                    headers=req_headers,
                    proxy=proxy,
                    allow_redirects=allow_redirects,
                    max_redirects=5,
                ) as resp:
                    body = await resp.text(errors="replace")
                    result: Dict[str, Any] = {
                        "url": str(resp.url),
                        "status": resp.status,
                        "body": body,
                        "headers": dict(resp.headers),
                        "content_length": len(body),
                        "final_url": str(resp.url),
                    }
                    if not allow_redirects:
                        result["location"] = resp.headers.get("Location", "")
                    return result

            except asyncio.TimeoutError:
                log.debug(f"Timeout [{attempt+1}]: {url}")
            except aiohttp.ClientConnectorError as e:
                log.debug(f"Connection error [{attempt+1}]: {url} — {e}")
                break   # DNS/connect failures won't be fixed by retry
            except Exception as e:
                log.debug(f"Request error [{attempt+1}]: {url} — {e}")

            if attempt < self.config.retries:
                await asyncio.sleep(0.5 * (attempt + 1))

        return None

    async def head(self, url: str) -> Optional[Dict[str, Any]]:
        """Lightweight HEAD probe."""
        await self._rate_limiter.acquire()
        proxy = self.config.proxy
        try:
            async with self._session.head(
                url,
                headers=self._headers(),
                proxy=proxy,
                allow_redirects=True,
                max_redirects=5,
            ) as resp:
                return {
                    "url": url,
                    "status": resp.status,
                    "headers": dict(resp.headers),
                    "final_url": str(resp.url),
                }
        except Exception as e:
            log.debug(f"HEAD failed: {url} — {e}")
            return None
