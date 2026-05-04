#!/usr/bin/env python3
"""
ReconSuite - Professional Attack Surface Mapping Framework
For authorized security testing and bug bounty engagements only.
"""

import asyncio
import argparse
import sys
import os
import json
import logging
from pathlib import Path
from datetime import datetime

from core.pipeline import ReconPipeline
from core.config import Config
from core.logger import setup_logger
from core.state import StateManager


BANNER = r"""
╦═╗┌─┐┌─┐┌─┐┌┐┌╔═╗┬ ┬┬┌┬┐┌─┐
╠╦╝├┤ │  │ ││││╚═╗│ ││ │ ├┤ 
╩╚═└─┘└─┘└─┘┘└┘╚═╝└─┘┴ ┴ └─┘
  Attack Surface Mapping Framework
  For authorized testing only.
"""


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="reconsuite",
        description="Professional recon and attack surface mapping framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Example: python3 reconsuite.py -d example.com --full --output html"
    )

    # Target specification
    target = p.add_mutually_exclusive_group(required=True)
    target.add_argument("-d", "--domain",       help="Single target domain")
    target.add_argument("--scope-file",         help="File with list of domains (one per line)")

    # Scan modes
    mode = p.add_argument_group("Scan Modes")
    mode.add_argument("--passive-only",  action="store_true", help="No active probing — passive OSINT only")
    mode.add_argument("--active-scan",   action="store_true", help="Full active probing and signal detection")
    mode.add_argument("--full",          action="store_true", help="All stages including JS analysis and deep crawl")

    # Performance
    perf = p.add_argument_group("Performance")
    perf.add_argument("--threads",       type=int, default=50,   metavar="N",  help="Concurrency limit (default: 50)")
    perf.add_argument("--rate-limit",    type=int, default=100,  metavar="RPS", help="Max requests/sec (default: 100)")
    perf.add_argument("--timeout",       type=int, default=10,   metavar="SEC", help="Request timeout seconds (default: 10)")
    perf.add_argument("--retries",       type=int, default=2,    metavar="N",  help="Retry attempts (default: 2)")

    # OPSEC
    opsec = p.add_argument_group("OPSEC")
    opsec.add_argument("--proxy",        metavar="URL",  help="HTTP/SOCKS proxy (e.g. http://127.0.0.1:8080)")
    opsec.add_argument("--user-agent",   metavar="UA",   help="Custom User-Agent string")
    opsec.add_argument("--rotate-ua",    action="store_true", help="Rotate User-Agent on each request")
    opsec.add_argument("--delay",        type=float, default=0.0, metavar="SEC", help="Per-request delay (default: 0)")

    # Output
    out = p.add_argument_group("Output")
    out.add_argument("--output",         choices=["json", "html", "both"], default="both", help="Output format (default: both)")
    out.add_argument("--output-dir",     default="./reports", metavar="DIR", help="Output directory (default: ./reports)")
    out.add_argument("--no-color",       action="store_true", help="Disable colored terminal output")

    # Pipeline control
    ctrl = p.add_argument_group("Pipeline Control")
    ctrl.add_argument("--resume",        metavar="SESSION", help="Resume a previous session by ID")
    ctrl.add_argument("--session-id",    metavar="ID",      help="Assign a session ID (auto-generated if omitted)")
    ctrl.add_argument("--skip-stages",   nargs="+",
                      choices=["discovery", "validation", "enrichment", "signals", "intelligence"],
                      help="Skip specific pipeline stages")
    ctrl.add_argument("--only-stages",   nargs="+",
                      choices=["discovery", "validation", "enrichment", "signals", "intelligence"],
                      help="Run only these stages")

    # Verbosity
    p.add_argument("-v", "--verbose",    action="store_true", help="Verbose output")
    p.add_argument("-q", "--quiet",      action="store_true", help="Suppress all output except results")

    return p


async def run(args: argparse.Namespace) -> int:
    log = setup_logger(
        verbose=args.verbose,
        quiet=args.quiet,
        no_color=args.no_color
    )

    print(BANNER)

    # Build config from CLI args
    config = Config.from_args(args)

    # Collect targets
    targets = []
    if args.domain:
        targets = [args.domain.strip().lower()]
    elif args.scope_file:
        scope_path = Path(args.scope_file)
        if not scope_path.exists():
            log.error(f"Scope file not found: {args.scope_file}")
            return 1
        targets = [
            line.strip().lower()
            for line in scope_path.read_text().splitlines()
            if line.strip() and not line.startswith("#")
        ]
        log.info(f"Loaded {len(targets)} targets from scope file")

    if not targets:
        log.error("No valid targets found.")
        return 1

    # Session management
    state = StateManager(session_id=args.session_id, resume_id=args.resume)

    # Determine active pipeline stages
    all_stages = ["discovery", "validation", "enrichment", "signals", "intelligence"]
    if args.only_stages:
        active_stages = [s for s in all_stages if s in args.only_stages]
    elif args.skip_stages:
        active_stages = [s for s in all_stages if s not in args.skip_stages]
    else:
        active_stages = all_stages

    if args.passive_only:
        # Remove active stages
        active_stages = [s for s in active_stages if s in ["discovery", "intelligence"]]
        log.info("Passive-only mode: active probing disabled")

    log.info(f"Session: {state.session_id}")
    log.info(f"Targets: {len(targets)} | Stages: {', '.join(active_stages)}")
    log.info(f"Threads: {config.threads} | Rate: {config.rate_limit} rps")

    # Initialise and run pipeline
    pipeline = ReconPipeline(
        targets=targets,
        config=config,
        state=state,
        active_stages=active_stages,
        log=log
    )

    results = await pipeline.run()

    # Output
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    base_name = f"reconsuite_{state.session_id}_{timestamp}"

    if args.output in ("json", "both"):
        from output.json_reporter import JSONReporter
        json_path = output_dir / f"{base_name}.json"
        JSONReporter(results).write(json_path)
        log.info(f"JSON report: {json_path}")

    if args.output in ("html", "both"):
        from output.html_reporter import HTMLReporter
        html_path = output_dir / f"{base_name}.html"
        HTMLReporter(results).write(html_path)
        log.info(f"HTML report: {html_path}")

    # Terminal summary
    _print_summary(results, log)
    return 0


def _print_summary(results: dict, log: logging.Logger):
    summary = results.get("summary", {})
    findings = results.get("findings", [])

    sev_count = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        sev = f.get("severity", "info").lower()
        sev_count[sev] = sev_count.get(sev, 0) + 1

    log.info("=" * 60)
    log.info("SCAN SUMMARY")
    log.info("=" * 60)
    log.info(f"  Domains scanned    : {summary.get('total_targets', 0)}")
    log.info(f"  Subdomains found   : {summary.get('subdomains_found', 0)}")
    log.info(f"  Live assets        : {summary.get('live_assets', 0)}")
    log.info(f"  Endpoints mapped   : {summary.get('endpoints_found', 0)}")
    log.info(f"  Findings           : {len(findings)}")
    log.info(f"    Critical         : {sev_count['critical']}")
    log.info(f"    High             : {sev_count['high']}")
    log.info(f"    Medium           : {sev_count['medium']}")
    log.info(f"    Low              : {sev_count['low']}")
    log.info("=" * 60)


def main():
    parser = build_parser()
    args = parser.parse_args()

    if args.quiet and args.verbose:
        parser.error("--quiet and --verbose are mutually exclusive")

    try:
        exit_code = asyncio.run(run(args))
        sys.exit(exit_code)
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user. State saved for --resume.")
        sys.exit(130)


if __name__ == "__main__":
    main()
