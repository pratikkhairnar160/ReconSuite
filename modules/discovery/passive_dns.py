"""
PassiveDNS — queries multiple passive DNS/OSINT sources.

Sources:
  - HackerTarget
  - RapidDNS
  - AlienVault OTX
  - ThreatCrowd (fallback)
  - BufferOver (if available)

No API keys required for basic sources.
"""

from __future__ import annotations
import asyncio
import re
from typing import List, Dict

import aiohttp

from core.config import Config
from core.logger import get_logger

log = get_logger()

# Regex for valid subdomain extraction
SUBDOMAIN_RE = re.compile(r"(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}")


class PassiveDNS:
    def __init__(self, domain: str, config: Config):
        self.domain = domain.lower()
        self.config = config
        self._timeout = aiohttp.ClientTimeout(total=20)

    async def enumerate(self) -> List[Dict]:
        tasks = [
            self._hackertarget(),
            self._rapiddns(),
            self._alienvault(),
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        seen: set = set()
        output: List[Dict] = []
        for batch in results:
            if isinstance(batch, Exception):
                continue
            for hostname in batch:
                h = hostname.lower().strip()
                if h and h.endswith(f".{self.domain}") and h not in seen:
                    seen.add(h)
                    output.append({
                        "hostname": h,
                        "domain": self.domain,
                        "source": "passive_dns",
                    })
        return output

    async def _hackertarget(self) -> List[str]:
        url = f"https://api.hackertarget.com/hostsearch/?q={self.domain}"
        try:
            async with aiohttp.ClientSession(timeout=self._timeout) as s:
                async with s.get(url) as resp:
                    text = await resp.text()
                    if "error" in text.lower() or "API count" in text:
                        return []
                    return [line.split(",")[0] for line in text.splitlines() if "," in line]
        except Exception as e:
            log.debug(f"HackerTarget error: {e}")
            return []

    async def _rapiddns(self) -> List[str]:
        url = f"https://rapiddns.io/subdomain/{self.domain}?full=1"
        try:
            async with aiohttp.ClientSession(timeout=self._timeout) as s:
                async with s.get(url, headers={"User-Agent": "Mozilla/5.0"}) as resp:
                    text = await resp.text()
                    return SUBDOMAIN_RE.findall(text)
        except Exception as e:
            log.debug(f"RapidDNS error: {e}")
            return []

    async def _alienvault(self) -> List[str]:
        url = f"https://otx.alienvault.com/api/v1/indicators/domain/{self.domain}/passive_dns"
        try:
            async with aiohttp.ClientSession(timeout=self._timeout) as s:
                async with s.get(url) as resp:
                    data = await resp.json()
                    return [
                        entry.get("hostname", "")
                        for entry in data.get("passive_dns", [])
                        if entry.get("hostname", "").endswith(f".{self.domain}")
                    ]
        except Exception as e:
            log.debug(f"AlienVault error: {e}")
            return []
