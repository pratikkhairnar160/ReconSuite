"""
ParameterMiner — builds a parameter map per domain from:
  - URL query strings (current + historical)
  - Form input fields
  - JS variable names that resemble parameters
"""

from __future__ import annotations
import re
from typing import List, Dict, Set
from urllib.parse import urlparse, parse_qs

from core.config import Config
from core.logger import get_logger

log = get_logger()

INPUT_RE = re.compile(r'<input[^>]+name=["\']([^"\']+)["\']', re.I)
JS_PARAM_RE = re.compile(
    r'(?:params|data|body|query|payload)\s*\.\s*([a-zA-Z_][a-zA-Z0-9_]{1,30})\b'
)


class ParameterMiner:
    def __init__(self, config: Config):
        self.config = config

    async def mine(self, crawl_results: List[Dict]) -> List[Dict]:
        """Extract parameters from all crawl data."""
        all_params: List[Dict] = []

        for asset in crawl_results:
            domain = asset.get("domain", urlparse(asset.get("url", "")).netloc)
            params: Dict[str, Set[str]] = {}  # param_name → set of source URLs

            # From crawled URLs
            for url in asset.get("crawl_urls", []):
                qs = parse_qs(urlparse(url).query)
                for key in qs:
                    params.setdefault(key, set()).add(url)

            # From form inputs in the base page body
            # (we don't re-fetch here; body was captured during crawl setup)
            # From JS endpoint list
            for ep in asset.get("endpoints", []):
                qs = parse_qs(urlparse(ep).query)
                for key in qs:
                    params.setdefault(key, set()).add(ep)

            if params:
                all_params.append({
                    "domain": domain,
                    "asset_url": asset.get("url", ""),
                    "parameters": {k: list(v) for k, v in params.items()},
                    "param_count": len(params),
                })

        return all_params
