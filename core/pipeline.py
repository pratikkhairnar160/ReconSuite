"""
ReconPipeline — chains all six stages and passes structured data forward.

Stage flow:
  Discovery → Validation → Enrichment → VulnSignals → Intelligence → (Report)

Each stage:
  - Reads from StateManager
  - Writes results back to StateManager
  - Respects checkpoint/resume
  - Is independently skippable
"""

from __future__ import annotations
import asyncio
import logging
import time
from typing import List, Dict, Any

from core.config import Config
from core.state import StateManager
from core.http_client import HTTPClient


class ReconPipeline:
    def __init__(
        self,
        targets: List[str],
        config: Config,
        state: StateManager,
        active_stages: List[str],
        log: logging.Logger,
    ):
        self.targets = targets
        self.config = config
        self.state = state
        self.active_stages = active_stages
        self.log = log

    async def run(self) -> Dict[str, Any]:
        start = time.time()

        async with HTTPClient(self.config) as http:
            self._http = http

            if "discovery" in self.active_stages:
                await self._run_stage("discovery",  self._stage_discovery)

            if "validation" in self.active_stages:
                await self._run_stage("validation", self._stage_validation)

            if "enrichment" in self.active_stages:
                await self._run_stage("enrichment", self._stage_enrichment)

            if "signals" in self.active_stages:
                await self._run_stage("signals",    self._stage_signals)

            if "intelligence" in self.active_stages:
                await self._run_stage("intelligence", self._stage_intelligence)

        elapsed = time.time() - start
        return self._compile_results(elapsed)

    # ------------------------------------------------------------------
    # Stage runner with checkpoint logic
    # ------------------------------------------------------------------

    async def _run_stage(self, name: str, coro):
        if self.state.stage_done(name):
            self.log.info(f"[SKIP] Stage '{name}' already completed (resuming)")
            return
        self.log.info(f"[STAGE] {name.upper()}")
        t = time.time()
        await coro()
        elapsed = round(time.time() - t, 2)
        self.state.mark_stage_done(name)
        self.log.info(f"[STAGE] {name.upper()} done in {elapsed}s")

    # ------------------------------------------------------------------
    # Stage 1 — Asset Discovery
    # ------------------------------------------------------------------

    async def _stage_discovery(self):
        from modules.discovery.passive_dns import PassiveDNS
        from modules.discovery.crt_sh import CrtShEnumerator
        from modules.discovery.dns_brute import DNSBrute
        from modules.discovery.asn_lookup import ASNLookup

        all_subdomains: List[Dict] = []

        for target in self.targets:
            self.log.info(f"  Discovering assets for: {target}")

            # Passive DNS (various APIs)
            passive = PassiveDNS(target, self.config)
            subs = await passive.enumerate()
            all_subdomains.extend(subs)
            self.log.info(f"    PassiveDNS:  {len(subs)} results")

            # Certificate transparency
            crt = CrtShEnumerator(target, self.config)
            subs = await crt.enumerate()
            all_subdomains.extend(subs)
            self.log.info(f"    crt.sh:      {len(subs)} results")

            # DNS brute force (only in active/full mode)
            if not self.config.passive_only:
                brute = DNSBrute(target, self.config)
                subs = await brute.enumerate()
                all_subdomains.extend(subs)
                self.log.info(f"    DNS brute:   {len(subs)} results")

            # ASN → IP range expansion
            if self.config.active_scan or self.config.full_scan:
                asn = ASNLookup(target, self.config)
                ranges = await asn.lookup()
                self.state.update("ip_ranges", ranges)
                self.log.info(f"    ASN ranges:  {len(ranges)} found")

        # Deduplicate and persist
        seen = set()
        unique = []
        for s in all_subdomains:
            key = s.get("hostname", "").lower()
            if key and key not in seen:
                seen.add(key)
                unique.append(s)

        self.state.set("subdomains", unique)
        self.log.info(f"  Total unique subdomains: {len(unique)}")

    # ------------------------------------------------------------------
    # Stage 2 — Asset Validation (live probing)
    # ------------------------------------------------------------------

    async def _stage_validation(self):
        from modules.validation.http_prober import HTTPProber

        subdomains = self.state.get("subdomains", [])
        if not subdomains:
            self.log.warning("  No subdomains to validate")
            return

        prober = HTTPProber(self.config, self._http)
        live_assets = await prober.probe_all(subdomains)

        # Filter dead assets
        live = [a for a in live_assets if a.get("live")]
        self.state.set("live_assets", live)
        self.log.info(f"  Live assets: {len(live)} / {len(subdomains)}")

    # ------------------------------------------------------------------
    # Stage 3 — Data Enrichment
    # ------------------------------------------------------------------

    async def _stage_enrichment(self):
        from modules.enrichment.crawler import Crawler
        from modules.enrichment.js_analyzer import JSAnalyzer
        from modules.enrichment.wayback import WaybackMiner
        from modules.enrichment.param_miner import ParameterMiner

        live_assets = self.state.get("live_assets", [])
        if not live_assets:
            self.log.warning("  No live assets to enrich")
            return

        # Crawl each live asset
        crawler = Crawler(self.config, self._http)
        crawl_results = await crawler.crawl_all(live_assets)
        self.state.set("crawl_data", crawl_results)

        # Wayback + commoncrawl historical URLs
        wayback = WaybackMiner(self.config)
        wb_urls = await wayback.fetch_all(self.targets)
        self.state.set("historical_urls", wb_urls)
        self.log.info(f"  Wayback URLs: {len(wb_urls)}")

        # JS intelligence (only in full mode)
        if self.config.full_scan or self.config.crawl_js:
            js_files = [
                e for cr in crawl_results
                for e in cr.get("js_files", [])
            ]
            self.log.info(f"  Analysing {len(js_files)} JS files")
            js_analyzer = JSAnalyzer(self.config, self._http)
            js_findings = await js_analyzer.analyse_all(js_files)
            self.state.set("js_findings", js_findings)
            self.log.info(f"  JS findings: {len(js_findings)}")

        # Parameter mining
        param_miner = ParameterMiner(self.config)
        params = await param_miner.mine(crawl_results)
        self.state.set("parameters", params)
        self.log.info(f"  Parameters found: {len(params)}")

    # ------------------------------------------------------------------
    # Stage 4 — Vulnerability Signal Detection
    # ------------------------------------------------------------------

    async def _stage_signals(self):
        from modules.vuln_signals.cors import CORSChecker
        from modules.vuln_signals.headers import HeaderChecker
        from modules.vuln_signals.takeover import TakeoverChecker
        from modules.vuln_signals.exposure import ExposureChecker
        from modules.vuln_signals.redirect import OpenRedirectChecker

        live_assets = self.state.get("live_assets", [])
        if not live_assets:
            return

        all_findings: List[Dict] = []
        sem = asyncio.Semaphore(self.config.threads)

        async def run_checker(checker, assets):
            async with sem:
                return await checker.check_all(assets)

        checkers = []
        if self.config.check_cors:
            checkers.append(CORSChecker(self.config, self._http))
        if self.config.check_headers:
            checkers.append(HeaderChecker(self.config, self._http))
        if self.config.check_takeover:
            checkers.append(TakeoverChecker(self.config, self._http))
        if self.config.check_exposure:
            checkers.append(ExposureChecker(self.config, self._http))
        if self.config.check_redirects:
            checkers.append(OpenRedirectChecker(self.config, self._http))

        tasks = [run_checker(c, live_assets) for c in checkers]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for r in results:
            if isinstance(r, Exception):
                self.log.warning(f"  Checker error: {r}")
            else:
                all_findings.extend(r)

        # Add JS findings as signal findings
        js_findings = self.state.get("js_findings", [])
        all_findings.extend(js_findings)

        self.state.set("raw_findings", all_findings)
        self.log.info(f"  Raw signals: {len(all_findings)}")

    # ------------------------------------------------------------------
    # Stage 5 — Intelligence & Prioritisation
    # ------------------------------------------------------------------

    async def _stage_intelligence(self):
        from modules.intelligence.prioritiser import Prioritiser
        from modules.intelligence.deduplicator import Deduplicator

        live_assets = self.state.get("live_assets", [])
        raw_findings = self.state.get("raw_findings", [])

        # Deduplicate findings
        dedup = Deduplicator()
        unique_findings = dedup.deduplicate(raw_findings)

        # Rank assets and findings
        prioritiser = Prioritiser(self.config)
        ranked_assets = prioritiser.rank_assets(live_assets)
        prioritised_findings = prioritiser.prioritise_findings(unique_findings)

        self.state.set("ranked_assets", ranked_assets)
        self.state.set("findings", prioritised_findings)

        high_value = [a for a in ranked_assets if a.get("priority_score", 0) >= 7]
        self.log.info(f"  High-value assets: {len(high_value)}")
        self.log.info(f"  Prioritised findings: {len(prioritised_findings)}")

    # ------------------------------------------------------------------
    # Compile final results object
    # ------------------------------------------------------------------

    def _compile_results(self, elapsed: float) -> Dict[str, Any]:
        subdomains   = self.state.get("subdomains", [])
        live_assets  = self.state.get("live_assets", [])
        parameters   = self.state.get("parameters", [])
        findings     = self.state.get("findings", self.state.get("raw_findings", []))
        ranked       = self.state.get("ranked_assets", live_assets)
        historical   = self.state.get("historical_urls", [])
        js_findings  = self.state.get("js_findings", [])

        return {
            "meta": {
                "session_id": self.state.session_id,
                "targets": self.targets,
                "elapsed_seconds": round(elapsed, 2),
                "stages_completed": self.state._state.get("stages_completed", []),
            },
            "summary": {
                "total_targets": len(self.targets),
                "subdomains_found": len(subdomains),
                "live_assets": len(live_assets),
                "endpoints_found": len(parameters),
                "historical_urls": len(historical),
                "js_findings": len(js_findings),
                "total_findings": len(findings),
            },
            "ranked_assets": ranked,
            "findings": findings,
            "parameters": parameters,
            "historical_urls": historical[:500],  # cap for report size
        }
