"""
WaybackMiner — fetches historical URLs from Wayback Machine and CommonCrawl.

Useful for finding:
  - Old API endpoints
  - Forgotten admin paths
  - Parameters no longer in active use
  - Backup/debug files
"""

from __future__ import annotations
import asyncio
from typing import List
from urllib.parse import urlparse

import aiohttp

from core.config import Config
from core.logger import get_logger

log = get_logger()

# Extensions to filter out (too noisy)
SKIP_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff",
    ".woff2", ".ttf", ".eot", ".css", ".map", ".pdf",
}


class WaybackMiner:
    def __init__(self, config: Config):
        self.config = config
        self._timeout = aiohttp.ClientTimeout(total=30)

    async def fetch_all(self, domains: List[str]) -> List[str]:
        tasks = [self._fetch_domain(d) for d in domains]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        urls = []
        seen = set()
        for batch in results:
            if isinstance(batch, list):
                for u in batch:
                    if u not in seen:
                        seen.add(u)
                        urls.append(u)
        return urls

    async def _fetch_domain(self, domain: str) -> List[str]:
        urls = await self._wayback(domain)
        if not urls:
            urls = await self._commoncrawl(domain)
        return urls

    async def _wayback(self, domain: str) -> List[str]:
        """Wayback CDX API — returns de-duped URL list."""
        api = (
            f"https://web.archive.org/cdx/search/cdx"
            f"?url=*.{domain}/*&output=text&fl=original&collapse=urlkey"
            f"&limit=5000&filter=statuscode:200"
        )
        try:
            async with aiohttp.ClientSession(timeout=self._timeout) as s:
                async with s.get(api) as resp:
                    if resp.status != 200:
                        return []
                    text = await resp.text()
                    return self._filter_urls(text.splitlines())
        except Exception as e:
            log.debug(f"Wayback error for {domain}: {e}")
            return []

    async def _commoncrawl(self, domain: str) -> List[str]:
        """CommonCrawl index API fallback."""
        api = (
            f"https://index.commoncrawl.org/CC-MAIN-2024-10-index"
            f"?url=*.{domain}&output=text&fl=url&limit=2000"
        )
        try:
            async with aiohttp.ClientSession(timeout=self._timeout) as s:
                async with s.get(api) as resp:
                    if resp.status != 200:
                        return []
                    text = await resp.text()
                    return self._filter_urls(text.splitlines())
        except Exception as e:
            log.debug(f"CommonCrawl error for {domain}: {e}")
            return []

    @staticmethod
    def _filter_urls(raw: List[str]) -> List[str]:
        filtered = []
        for url in raw:
            url = url.strip()
            if not url.startswith("http"):
                continue
            path = urlparse(url).path.lower()
            ext = "." + path.rsplit(".", 1)[-1] if "." in path else ""
            if ext in SKIP_EXTENSIONS:
                continue
            filtered.append(url)
        return filtered
