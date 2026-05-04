"""
CrtShEnumerator — certificate transparency log mining via crt.sh.

Crt.sh is the most reliable free source for subdomain discovery.
Handles wildcard entries and deduplication.
"""

from __future__ import annotations
import asyncio
import json
from typing import List, Dict

import aiohttp

from core.config import Config
from core.logger import get_logger

log = get_logger()


class CrtShEnumerator:
    def __init__(self, domain: str, config: Config):
        self.domain = domain.lower()
        self.config = config
        self._timeout = aiohttp.ClientTimeout(total=30)

    async def enumerate(self) -> List[Dict]:
        """Query crt.sh JSON API and extract unique subdomains."""
        url = f"https://crt.sh/?q=%.{self.domain}&output=json"

        for attempt in range(3):
            try:
                async with aiohttp.ClientSession(timeout=self._timeout) as s:
                    async with s.get(url, headers={"User-Agent": "Mozilla/5.0"}) as resp:
                        if resp.status != 200:
                            log.debug(f"crt.sh returned {resp.status}")
                            await asyncio.sleep(2 ** attempt)
                            continue
                        data = await resp.json(content_type=None)
                        return self._parse(data)

            except asyncio.TimeoutError:
                log.debug(f"crt.sh timeout (attempt {attempt+1})")
                await asyncio.sleep(2 ** attempt)
            except json.JSONDecodeError:
                log.debug("crt.sh invalid JSON response")
                break
            except Exception as e:
                log.debug(f"crt.sh error: {e}")
                break

        return []

    def _parse(self, data: list) -> List[Dict]:
        seen: set = set()
        out: List[Dict] = []

        for entry in data:
            # name_value may contain multiple names separated by newlines
            raw = entry.get("name_value", "") + "\n" + entry.get("common_name", "")
            for name in raw.splitlines():
                name = name.strip().lower().lstrip("*.")
                if (
                    name
                    and name.endswith(self.domain)
                    and name not in seen
                    and " " not in name  # skip descriptive entries
                ):
                    seen.add(name)
                    out.append({
                        "hostname": name,
                        "domain": self.domain,
                        "source": "crt_sh",
                        "issuer": entry.get("issuer_name", ""),
                        "not_before": entry.get("not_before", ""),
                    })
        return out
