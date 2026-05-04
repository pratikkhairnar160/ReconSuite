"""
Prioritiser — ranks assets and findings by value for a bug bounty hunter.

Scoring factors for assets:
  - Interesting tech (Jira, Jenkins, GraphQL, Spring Boot, etc.)
  - Interesting URL patterns (admin, login, API, debug)
  - Live 200 response
  - HTTPS enabled
  - Response behaviour anomalies

Severity ordering for findings:
  critical > high > medium > low > info
"""

from __future__ import annotations
from typing import List, Dict

from core.config import Config
from core.logger import get_logger

log = get_logger()

SEVERITY_RANK = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}

# Tech that historically yields good bug bounty findings
HIGH_VALUE_TECH = {
    "jenkins": 3, "jira": 2, "confluence": 2,
    "grafana": 2, "kibana": 2, "elasticsearch": 3,
    "spring": 2, "struts": 3, "coldfusion": 3,
    "graphql": 2, "swagger": 1, "adminer": 3,
    "phpmyadmin": 3, "wordpress": 1,
}

HIGH_VALUE_TAGS = {
    "admin_panel": 3, "login_panel": 2, "api_endpoint": 2,
    "debug_page": 3, "git_exposure": 4, "env_exposure": 4,
}


class Prioritiser:
    def __init__(self, config: Config):
        self.config = config

    def rank_assets(self, assets: List[Dict]) -> List[Dict]:
        scored = []
        for asset in assets:
            if not asset.get("live"):
                continue

            score = 0

            # Base: live and HTTPS
            score += 1
            if asset.get("scheme") == "https":
                score += 1

            # Tech stack score
            for tech in asset.get("tech", []):
                score += HIGH_VALUE_TECH.get(tech.lower(), 0)

            # Interesting tags
            for tag in asset.get("interesting_tags", []):
                score += HIGH_VALUE_TAGS.get(tag, 1)

            # Status code signals
            status = asset.get("status", 0)
            if status == 200:
                score += 1
            elif status in (401, 403):
                score += 2  # Auth-protected endpoints are interesting

            scored.append({**asset, "priority_score": score})

        return sorted(scored, key=lambda a: a["priority_score"], reverse=True)

    def prioritise_findings(self, findings: List[Dict]) -> List[Dict]:
        """Sort findings by severity, then by confidence."""
        def sort_key(f: Dict):
            sev = SEVERITY_RANK.get(f.get("severity", "info"), 1)
            conf = {"high": 3, "medium": 2, "low": 1}.get(f.get("confidence", "low"), 1)
            return (sev * 10 + conf)

        return sorted(findings, key=sort_key, reverse=True)
