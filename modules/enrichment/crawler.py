"""
Crawler — crawls live assets to extract:
  - Internal links / endpoints
  - JS file URLs
  - Form action URLs
  - API path patterns

Respects depth limits and scope boundaries.
"""

from __future__ import annotations
import asyncio
import re
from typing import List, Dict, Set
from urllib.parse import urljoin, urlparse

from core.config import Config
from core.http_client import HTTPClient
from core.logger import get_logger

log = get_logger()

HREF_RE   = re.compile(r'href=["\']([^"\']+)["\']', re.I)
SRC_RE    = re.compile(r'src=["\']([^"\']+\.js[^"\']*)["\']', re.I)
ACTION_RE = re.compile(r'action=["\']([^"\']+)["\']', re.I)
# Common API/endpoint path patterns in HTML/JS
ENDPOINT_RE = re.compile(
    r'(?:fetch|axios|XMLHttpRequest|url|endpoint|path|route)\s*[=:(]\s*["\']'
    r'(/[a-zA-Z0-9_\-/]+)',
    re.I
)


class Crawler:
    def __init__(self, config: Config, http: HTTPClient):
        self.config = config
        self.http = http
        self.max_depth = config.crawl_depth

    async def crawl_all(self, assets: List[Dict]) -> List[Dict]:
        sem = asyncio.Semaphore(self.config.threads)
        tasks = [self._crawl_asset(a, sem) for a in assets if a.get("live")]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        return [r for r in results if isinstance(r, dict)]

    async def _crawl_asset(self, asset: Dict, sem: asyncio.Semaphore) -> Dict:
        base_url = asset.get("url", "")
        if not base_url:
            return {**asset, "crawl_urls": [], "js_files": [], "endpoints": []}

        visited: Set[str] = set()
        js_files: Set[str] = set()
        endpoints: Set[str] = set()
        queue = [(base_url, 0)]

        while queue:
            url, depth = queue.pop(0)
            if url in visited or depth > self.max_depth:
                continue
            visited.add(url)

            async with sem:
                resp = await self.http.get(url)
            if not resp:
                continue

            body = resp.get("body", "")
            ct = resp.get("headers", {}).get("Content-Type", "")
            if "html" not in ct and "javascript" not in ct:
                continue

            # Extract JS files
            for match in SRC_RE.finditer(body):
                js_url = urljoin(url, match.group(1))
                if self._in_scope(js_url, base_url):
                    js_files.add(js_url)

            # Extract links (crawl only in-scope HTML)
            if "html" in ct and depth < self.max_depth:
                for match in HREF_RE.finditer(body):
                    linked = urljoin(url, match.group(1))
                    if self._in_scope(linked, base_url) and linked not in visited:
                        queue.append((linked, depth + 1))

            # Extract form actions
            for match in ACTION_RE.finditer(body):
                action = urljoin(url, match.group(1))
                if self._in_scope(action, base_url):
                    endpoints.add(action)

            # Extract API endpoints from JS/HTML patterns
            for match in ENDPOINT_RE.finditer(body):
                endpoints.add(match.group(1))

        return {
            **asset,
            "crawl_urls": list(visited),
            "js_files": list(js_files),
            "endpoints": list(endpoints),
            "pages_crawled": len(visited),
        }

    @staticmethod
    def _in_scope(url: str, base_url: str) -> bool:
        """Only follow links on the same hostname."""
        try:
            return urlparse(url).netloc == urlparse(base_url).netloc
        except Exception:
            return False
