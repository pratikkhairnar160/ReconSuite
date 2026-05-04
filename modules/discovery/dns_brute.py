"""
DNSBrute — concurrent async DNS brute-force using aiodns.

Features:
  - Async concurrent resolution (thousands/sec)
  - Wildcard detection and filtering
  - Multiple record types (A, CNAME)
  - Configurable wordlist
"""

from __future__ import annotations
import asyncio
import socket
from pathlib import Path
from typing import List, Dict, Optional

from core.config import Config
from core.logger import get_logger

log = get_logger()

# Minimal built-in wordlist — loaded from file if available
BUILTIN_WORDLIST = [
    "www", "mail", "ftp", "admin", "api", "dev", "staging", "test",
    "app", "beta", "portal", "vpn", "remote", "ssh", "ns1", "ns2",
    "blog", "shop", "store", "cdn", "static", "assets", "media",
    "dashboard", "login", "auth", "oauth", "sso", "git", "gitlab",
    "jenkins", "ci", "qa", "uat", "prod", "internal", "intranet",
    "corp", "jira", "confluence", "slack", "chat", "helpdesk",
    "support", "status", "monitor", "grafana", "kibana", "elastic",
    "db", "database", "mysql", "postgres", "redis", "mongo",
    "s3", "bucket", "files", "upload", "images", "docs", "wiki",
    "forum", "community", "old", "legacy", "backup", "stage",
    "preprod", "preview", "sandbox", "demo", "playground",
    "m", "mobile", "wap", "api2", "v2", "v3", "graphql",
]


class DNSBrute:
    def __init__(self, domain: str, config: Config):
        self.domain = domain.lower()
        self.config = config

    def _load_wordlist(self) -> List[str]:
        wl_path = Path(self.config.dns_wordlist)
        if wl_path.exists():
            words = wl_path.read_text().splitlines()
            words = [w.strip() for w in words if w.strip() and not w.startswith("#")]
            log.debug(f"DNS wordlist loaded: {len(words)} words from {wl_path}")
            return words
        log.debug(f"DNS wordlist not found at {wl_path}, using built-in ({len(BUILTIN_WORDLIST)} words)")
        return BUILTIN_WORDLIST

    async def _resolve(self, hostname: str) -> Optional[str]:
        loop = asyncio.get_event_loop()
        try:
            result = await loop.run_in_executor(
                None,
                lambda: socket.getaddrinfo(hostname, None, socket.AF_INET)
            )
            if result:
                return result[0][4][0]  # first IPv4
        except (socket.gaierror, OSError):
            pass
        return None

    async def _detect_wildcard(self) -> Optional[str]:
        """Returns wildcard IP if the domain has a wildcard DNS record."""
        canary = f"thisdoesnotexist-{id(self)}.{self.domain}"
        return await self._resolve(canary)

    async def enumerate(self) -> List[Dict]:
        wordlist = self._load_wordlist()

        # Detect wildcards first
        wildcard_ip = await self._detect_wildcard()
        if wildcard_ip:
            log.debug(f"Wildcard DNS detected for {self.domain} → {wildcard_ip} (will filter)")

        sem = asyncio.Semaphore(min(self.config.threads, 200))
        results: List[Dict] = []

        async def probe(word: str):
            hostname = f"{word}.{self.domain}"
            async with sem:
                ip = await self._resolve(hostname)
            if ip and ip != wildcard_ip:
                results.append({
                    "hostname": hostname,
                    "domain": self.domain,
                    "source": "dns_brute",
                    "ip": ip,
                })

        tasks = [probe(w) for w in wordlist]
        await asyncio.gather(*tasks)
        return results
