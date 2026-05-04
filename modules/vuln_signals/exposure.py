"""
ExposureChecker — probes for exposed sensitive files and debug endpoints.

Paths are well-known from public CVEs, CTF writeups, and bug bounty reports.
Detection only — reads HTTP status + body fragment, never writes or exploits.
"""

from __future__ import annotations
import asyncio
from typing import List, Dict, Tuple
from urllib.parse import urljoin

from core.config import Config
from core.http_client import HTTPClient
from core.logger import get_logger

log = get_logger()


# (path, description, severity, body_confirm — optional string that must appear in body)
EXPOSURE_PROBES: List[Tuple[str, str, str, str]] = [
    ("/.git/HEAD",             "Git repository exposed",          "critical", "ref:"),
    ("/.git/config",           "Git config exposed",              "critical", "[core]"),
    ("/.env",                  ".env file exposed",               "critical", "APP_"),
    ("/.env.local",            ".env.local exposed",              "critical", ""),
    ("/.env.backup",           ".env backup exposed",             "critical", ""),
    ("/config.php",            "PHP config exposed",              "high",     "<?php"),
    ("/wp-config.php.bak",     "WordPress config backup",         "critical", ""),
    ("/phpinfo.php",           "PHPInfo exposed",                 "high",     "PHP Version"),
    ("/server-status",         "Apache server-status exposed",    "medium",   "Apache"),
    ("/server-info",           "Apache server-info exposed",      "medium",   "Apache"),
    ("/actuator",              "Spring Boot actuator exposed",    "high",     ""),
    ("/actuator/env",          "Spring Boot env actuator",        "critical", ""),
    ("/actuator/mappings",     "Spring Boot route mappings",      "high",     ""),
    ("/actuator/heapdump",     "Spring Boot heap dump exposed",   "critical", ""),
    ("/metrics",               "Metrics endpoint exposed",        "medium",   ""),
    ("/health",                "Health endpoint exposed",         "info",     ""),
    ("/_debug_toolbar",        "Django debug toolbar exposed",    "medium",   "djdt"),
    ("/debug",                 "Debug endpoint exposed",          "medium",   ""),
    ("/console",               "Web console exposed",             "high",     ""),
    ("/adminer.php",           "Adminer DB GUI exposed",          "critical", "adminer"),
    ("/phpmyadmin/",           "phpMyAdmin exposed",              "critical", "phpMyAdmin"),
    ("/robots.txt",            "robots.txt (info)",               "info",     ""),
    ("/sitemap.xml",           "Sitemap (info)",                  "info",     ""),
    ("/.htaccess",             ".htaccess exposed",               "medium",   ""),
    ("/backup.sql",            "SQL backup exposed",              "critical", ""),
    ("/dump.sql",              "SQL dump exposed",                "critical", ""),
    ("/db.sqlite3",            "SQLite DB exposed",               "critical", ""),
    ("/web.config",            "IIS web.config exposed",          "high",     "<configuration>"),
    ("/crossdomain.xml",       "Flash crossdomain policy",        "info",     "<cross-domain-policy>"),
    ("/clientaccesspolicy.xml","Silverlight policy",              "info",     "<access-policy>"),
    ("/package.json",          "package.json exposed",            "low",      '"name"'),
    ("/composer.json",         "composer.json exposed",           "low",      '"require"'),
    ("/Dockerfile",            "Dockerfile exposed",              "medium",   "FROM "),
    ("/docker-compose.yml",    "docker-compose exposed",          "medium",   "version:"),
    ("/swagger.json",          "Swagger/OpenAPI spec exposed",    "medium",   '"swagger"'),
    ("/swagger-ui.html",       "Swagger UI exposed",              "medium",   "swagger"),
    ("/api-docs",              "API docs exposed",                "medium",   ""),
    ("/graphql",               "GraphQL endpoint",                "info",     ""),
]


class ExposureChecker:
    def __init__(self, config: Config, http: HTTPClient):
        self.config = config
        self.http = http

    async def check_all(self, assets: List[Dict]) -> List[Dict]:
        sem = asyncio.Semaphore(self.config.threads)
        tasks = [self._check_asset(a, sem) for a in assets if a.get("live")]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        findings = []
        for r in results:
            if isinstance(r, list):
                findings.extend(r)
        return findings

    async def _check_asset(self, asset: Dict, sem: asyncio.Semaphore) -> List[Dict]:
        base_url = asset.get("url", "").rstrip("/")
        if not base_url:
            return []

        findings = []

        async def probe(path: str, desc: str, severity: str, body_confirm: str):
            url = urljoin(base_url + "/", path.lstrip("/"))
            async with sem:
                resp = await self.http.get(url, allow_redirects=False)
            if not resp:
                return

            status = resp.get("status", 0)
            body   = resp.get("body", "")

            # Only flag 200 responses (or 206 for partial)
            if status not in (200, 206):
                return

            # Body confirmation reduces false positives
            if body_confirm and body_confirm.lower() not in body.lower():
                return

            findings.append({
                "type": "exposure",
                "title": desc,
                "severity": severity,
                "confidence": "high" if body_confirm else "medium",
                "url": url,
                "hostname": asset.get("hostname"),
                "status": status,
                "content_length": len(body),
                "description": f"{desc} at {url}",
                "remediation": f"Restrict access to {path} via server config or firewall rule.",
            })

        tasks = [probe(path, desc, sev, confirm) for path, desc, sev, confirm in EXPOSURE_PROBES]
        await asyncio.gather(*tasks)
        return findings
