"""
HTTPProber — validates which discovered subdomains are live.

For each subdomain:
  - Probe HTTP + HTTPS
  - Capture: status, title, server, tech hints, response size
  - Tag interesting assets: login panels, admin, API, debug
  - Filter dead assets (DNS_NXDOMAIN, timeout, connection refused)
"""

from __future__ import annotations
import asyncio
import re
from typing import List, Dict, Optional
from urllib.parse import urlparse

from core.config import Config
from core.http_client import HTTPClient
from core.logger import get_logger

log = get_logger()

TITLE_RE  = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
SERVER_RE = re.compile(r"nginx|apache|iis|cloudflare|caddy|lighttpd|gunicorn|uvicorn|tomcat", re.I)

# Tech fingerprints — header/body patterns
TECH_FINGERPRINTS: Dict[str, List[str]] = {
    "wordpress":      ["wp-content", "wp-includes", "xmlrpc.php"],
    "drupal":         ["sites/default", "Drupal"],
    "jira":           ["atlassian", "JIRA", "servicedesk"],
    "confluence":     ["confluence", "Atlassian Confluence"],
    "jenkins":        ["Jenkins", "hudson"],
    "grafana":        ["grafana", "Grafana"],
    "kibana":         ["kibana", "Kibana"],
    "elasticsearch":  ['"cluster_name"', '"tagline"'],
    "django":         ["csrfmiddlewaretoken", "Django"],
    "rails":          ["_rails_session", "X-Powered-By: Phusion Passenger"],
    "spring":         ["Whitelabel Error Page", "Spring Framework"],
    "struts":         ["struts", "Apache Struts"],
    "laravel":        ["laravel_session", "X-Powered-By: PHP"],
    "swagger":        ["swagger-ui", "Swagger UI"],
    "graphql":        ["__typename", "graphql"],
    "phpmyadmin":     ["phpMyAdmin", "pma_"],
    "adminer":        ["adminer", "Adminer"],
    "gitlab":         ["GitLab", "gl-"],
    "nextcloud":      ["nextcloud", "Nextcloud"],
}

# Patterns that flag an asset as "interesting"
INTERESTING_PATTERNS: Dict[str, List[str]] = {
    "login_panel":   ["/login", "/signin", "/auth", "/wp-login", "login.php"],
    "admin_panel":   ["/admin", "/administrator", "/dashboard", "/manage", "/console"],
    "api_endpoint":  ["/api", "/graphql", "/v1/", "/v2/", "/rest/", "/swagger"],
    "debug_page":    ["/debug", "/phpinfo", "/server-status", "/__debug__", "/actuator"],
    "git_exposure":  ["/.git/HEAD", "/.git/config"],
    "env_exposure":  ["/.env", "/config.php", "/settings.py"],
}


class HTTPProber:
    def __init__(self, config: Config, http: HTTPClient):
        self.config = config
        self.http = http

    async def probe_all(self, subdomains: List[Dict]) -> List[Dict]:
        sem = asyncio.Semaphore(self.config.threads)
        tasks = [self._probe_with_sem(s, sem) for s in subdomains]
        results = await asyncio.gather(*tasks)
        return [r for r in results if r is not None]

    async def _probe_with_sem(self, subdomain: Dict, sem: asyncio.Semaphore) -> Optional[Dict]:
        async with sem:
            return await self._probe(subdomain)

    async def _probe(self, subdomain: Dict) -> Optional[Dict]:
        hostname = subdomain.get("hostname", "")
        if not hostname:
            return None

        # Try HTTPS first, fall back to HTTP
        for scheme in ("https", "http"):
            url = f"{scheme}://{hostname}"
            resp = await self.http.get(url, allow_redirects=True)
            if resp:
                asset = self._enrich(subdomain, resp, scheme)
                return asset

        # No response — mark as dead
        return {**subdomain, "live": False, "url": f"https://{hostname}"}

    def _enrich(self, subdomain: Dict, resp: Dict, scheme: str) -> Dict:
        body    = resp.get("body", "")
        headers = resp.get("headers", {})
        status  = resp.get("status", 0)
        url     = resp.get("final_url", f"{scheme}://{subdomain['hostname']}")

        title = ""
        m = TITLE_RE.search(body)
        if m:
            title = re.sub(r"\s+", " ", m.group(1)).strip()[:200]

        server = headers.get("Server", headers.get("server", ""))
        powered_by = headers.get("X-Powered-By", headers.get("x-powered-by", ""))
        content_type = headers.get("Content-Type", "")

        tech = self._detect_tech(body, headers)
        interesting = self._detect_interesting(url, body)

        return {
            **subdomain,
            "live": True,
            "url": url,
            "scheme": scheme,
            "status": status,
            "title": title,
            "server": server,
            "powered_by": powered_by,
            "content_type": content_type,
            "content_length": resp.get("content_length", 0),
            "tech": tech,
            "interesting_tags": interesting,
            "has_interesting": bool(interesting),
        }

    def _detect_tech(self, body: str, headers: Dict) -> List[str]:
        found = []
        combined = body.lower() + " " + " ".join(str(v).lower() for v in headers.values())
        for tech, patterns in TECH_FINGERPRINTS.items():
            if any(p.lower() in combined for p in patterns):
                found.append(tech)
        return found

    def _detect_interesting(self, url: str, body: str) -> List[str]:
        tags = []
        url_lower = url.lower()
        for tag, patterns in INTERESTING_PATTERNS.items():
            if any(p.lower() in url_lower or p.lower() in body.lower() for p in patterns):
                tags.append(tag)
        return tags
