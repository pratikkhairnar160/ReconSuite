"""
JSAnalyzer — static analysis of JS files to surface:

  - Hardcoded secrets (API keys, tokens, credentials)
  - API endpoints and base URLs
  - Internal paths
  - Cloud resource references

This is STATIC analysis only — no execution, no exploitation.
Findings are tagged with confidence level.
"""

from __future__ import annotations
import asyncio
import re
import hashlib
from typing import List, Dict, Tuple
from urllib.parse import urljoin

from core.config import Config
from core.http_client import HTTPClient
from core.logger import get_logger

log = get_logger()


# (name, pattern, severity, confidence_note)
SECRET_PATTERNS: List[Tuple[str, re.Pattern, str, str]] = [
    ("AWS Access Key",        re.compile(r'AKIA[0-9A-Z]{16}'),                               "critical", "high"),
    ("AWS Secret Key",        re.compile(r'(?i)aws.{0,20}secret.{0,20}["\'][0-9a-zA-Z/+]{40}'),  "critical", "medium"),
    ("Google API Key",        re.compile(r'AIza[0-9A-Za-z\-_]{35}'),                         "high",     "high"),
    ("Google OAuth",          re.compile(r'[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com'), "high", "high"),
    ("Stripe Secret Key",     re.compile(r'sk_live_[0-9a-zA-Z]{24}'),                        "critical", "high"),
    ("Stripe Publishable Key",re.compile(r'pk_live_[0-9a-zA-Z]{24}'),                        "medium",   "high"),
    ("GitHub Token",          re.compile(r'gh[pousr]_[A-Za-z0-9_]{36}'),                     "critical", "high"),
    ("Slack Token",           re.compile(r'xox[baprs]-[0-9A-Za-z\-]{10,48}'),               "high",     "high"),
    ("Slack Webhook",         re.compile(r'https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+'), "high", "high"),
    ("Twilio SID",            re.compile(r'AC[a-z0-9]{32}'),                                 "high",     "medium"),
    ("SendGrid Key",          re.compile(r'SG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}'),   "high",     "high"),
    ("JWT Token",             re.compile(r'eyJ[a-zA-Z0-9_\-]+\.eyJ[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+'), "medium", "medium"),
    ("Firebase Config",       re.compile(r'firebase[^\n]{0,200}apiKey'),                     "medium",   "low"),
    ("Private Key Header",    re.compile(r'-----BEGIN (RSA |EC )?PRIVATE KEY-----'),          "critical", "high"),
    ("Generic Password",      re.compile(r'(?i)password\s*[:=]\s*["\'][^"\']{8,}["\']'),    "medium",   "low"),
    ("Generic Secret",        re.compile(r'(?i)(secret|token|api_key|apikey)\s*[:=]\s*["\'][a-zA-Z0-9_\-]{16,}["\']'), "medium", "low"),
    ("Internal IP",           re.compile(r'(?:10\.|172\.(?:1[6-9]|2[0-9]|3[01])\.|192\.168\.)\d{1,3}\.\d{1,3}'), "info", "high"),
    ("Cloud Storage URL",     re.compile(r'https?://[a-z0-9\-]+\.s3(?:[\.\-][a-z0-9\-]+)?\.amazonaws\.com'), "info", "high"),
]

# Endpoint extraction from JS
ENDPOINT_PATTERNS = [
    re.compile(r'["\'](/(?:api|v\d+|rest|graphql)[a-zA-Z0-9_/\-\.]+)["\']'),
    re.compile(r'url\s*[:=]\s*["\']([^"\']+)["\']', re.I),
    re.compile(r'endpoint\s*[:=]\s*["\']([^"\']+)["\']', re.I),
    re.compile(r'baseURL\s*[:=]\s*["\']([^"\']+)["\']', re.I),
    re.compile(r'fetch\s*\(\s*["\']([^"\']+)["\']', re.I),
]


class JSAnalyzer:
    def __init__(self, config: Config, http: HTTPClient):
        self.config = config
        self.http = http
        self._seen_hashes: set = set()

    async def analyse_all(self, js_urls: List[str]) -> List[Dict]:
        if not js_urls:
            return []

        sem = asyncio.Semaphore(self.config.threads)
        tasks = [self._analyse_one(url, sem) for url in js_urls]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        findings = []
        for r in results:
            if isinstance(r, list):
                findings.extend(r)
        return findings

    async def _analyse_one(self, js_url: str, sem: asyncio.Semaphore) -> List[Dict]:
        async with sem:
            resp = await self.http.get(js_url)
        if not resp:
            return []

        body = resp.get("body", "")
        if not body:
            return []

        # Deduplicate by content hash to avoid re-analysing CDN duplicates
        content_hash = hashlib.md5(body.encode()).hexdigest()
        if content_hash in self._seen_hashes:
            return []
        self._seen_hashes.add(content_hash)

        findings = []

        # Secret scanning
        for name, pattern, severity, confidence in SECRET_PATTERNS:
            matches = pattern.findall(body)
            for match in set(matches):
                # Redact long secrets in output — show only prefix
                display = match if len(match) < 20 else match[:12] + "...[redacted]"
                findings.append({
                    "type": "js_secret",
                    "subtype": name,
                    "severity": severity,
                    "confidence": confidence,
                    "source_url": js_url,
                    "value": display,
                    "description": f"Potential {name} found in JS file",
                    "remediation": "Remove secrets from client-side code; rotate any exposed credentials immediately.",
                })

        # Endpoint extraction (info-level findings)
        endpoints_found = set()
        for pattern in ENDPOINT_PATTERNS:
            for match in pattern.findall(body):
                if match.startswith(("/", "http")):
                    endpoints_found.add(match)

        if endpoints_found:
            findings.append({
                "type": "js_endpoints",
                "severity": "info",
                "confidence": "high",
                "source_url": js_url,
                "endpoints": list(endpoints_found)[:50],
                "description": f"API endpoints extracted from JS ({len(endpoints_found)} found)",
            })

        return findings
