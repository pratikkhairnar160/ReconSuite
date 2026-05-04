"""
ASNLookup — maps a domain → ASN → IP ranges.

Uses BGPView public API (no key required).
"""

from __future__ import annotations
from typing import List, Dict
import socket

import aiohttp

from core.config import Config
from core.logger import get_logger

log = get_logger()


class ASNLookup:
    def __init__(self, domain: str, config: Config):
        self.domain = domain
        self.config = config
        self._timeout = aiohttp.ClientTimeout(total=15)

    async def lookup(self) -> List[Dict]:
        """Resolve domain IP → ASN → prefixes."""
        try:
            ip = socket.gethostbyname(self.domain)
        except socket.gaierror:
            log.debug(f"ASN: could not resolve {self.domain}")
            return []

        try:
            async with aiohttp.ClientSession(timeout=self._timeout) as s:
                # IP → ASN
                async with s.get(f"https://api.bgpview.io/ip/{ip}") as resp:
                    data = await resp.json()
                    asns = []
                    for prefix in data.get("data", {}).get("prefixes", []):
                        asn_num = prefix.get("asn", {}).get("asn")
                        if asn_num:
                            asns.append(asn_num)

                if not asns:
                    return []

                # ASN → prefixes
                ranges = []
                for asn in set(asns[:3]):  # cap at 3 ASNs
                    async with s.get(f"https://api.bgpview.io/asn/{asn}/prefixes") as resp:
                        pdata = await resp.json()
                        for p in pdata.get("data", {}).get("ipv4_prefixes", []):
                            prefix_str = p.get("prefix")
                            if prefix_str:
                                ranges.append({
                                    "asn": asn,
                                    "prefix": prefix_str,
                                    "name": p.get("name", ""),
                                    "description": p.get("description", ""),
                                })
                return ranges

        except Exception as e:
            log.debug(f"ASN lookup error: {e}")
            return []
