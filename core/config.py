"""
Core configuration — built from CLI args, passed through the entire pipeline.
"""

from __future__ import annotations
import argparse
from dataclasses import dataclass, field
from typing import Optional, List


@dataclass
class Config:
    # Scan behaviour
    passive_only: bool = False
    active_scan: bool = False
    full_scan: bool = False

    # Performance
    threads: int = 50
    rate_limit: int = 100        # requests/sec
    timeout: int = 10            # seconds
    retries: int = 2
    delay: float = 0.0           # per-request delay

    # OPSEC
    proxy: Optional[str] = None
    user_agent: Optional[str] = None
    rotate_ua: bool = False

    # DNS
    dns_wordlist: str = "data/wordlists/subdomains.txt"
    dns_resolvers: str = "data/resolvers.txt"

    # Crawling
    crawl_depth: int = 2
    crawl_js: bool = True

    # Vuln signals — detection only, no exploitation
    check_cors: bool = True
    check_takeover: bool = True
    check_headers: bool = True
    check_exposure: bool = True
    check_redirects: bool = True
    check_ssrf_patterns: bool = True
    check_xss_reflection: bool = False   # opt-in: active reflection check

    # Intelligence
    interesting_tech: List[str] = field(default_factory=lambda: [
        "wordpress", "drupal", "jira", "confluence", "jenkins",
        "grafana", "kibana", "elasticsearch", "spring", "django",
        "rails", "struts", "coldfusion", "weblogic", "tomcat",
        "phpmyadmin", "adminer", "swagger", "graphql",
    ])

    interesting_paths: List[str] = field(default_factory=lambda: [
        "/admin", "/login", "/dashboard", "/api", "/graphql",
        "/.git", "/.env", "/swagger-ui", "/actuator", "/metrics",
        "/debug", "/console", "/phpinfo", "/server-status",
        "/wp-admin", "/wp-login", "/_debug_toolbar",
    ])

    @classmethod
    def from_args(cls, args: argparse.Namespace) -> "Config":
        return cls(
            passive_only=getattr(args, "passive_only", False),
            active_scan=getattr(args, "active_scan", False),
            full_scan=getattr(args, "full", False),
            threads=args.threads,
            rate_limit=args.rate_limit,
            timeout=args.timeout,
            retries=args.retries,
            delay=args.delay,
            proxy=args.proxy,
            user_agent=getattr(args, "user_agent", None),
            rotate_ua=getattr(args, "rotate_ua", False),
            crawl_js=getattr(args, "full", False),
        )
