# ReconSuite

**Professional attack surface mapping framework for authorized bug bounty and security engagements.**

> ⚠️ This tool is for **authorized testing only**. Only run against targets you have explicit written permission to test.

---

## Architecture

```
reconsuite.py          CLI entry point
core/
  config.py            Config dataclass — all settings in one place
  pipeline.py          Stage orchestrator — chains all 5 stages
  state.py             Session persistence / checkpoint/resume
  http_client.py       Async HTTP with rate limiting, proxy, UA rotation
  logger.py            Colored, leveled logging

modules/
  discovery/
    passive_dns.py     HackerTarget, RapidDNS, AlienVault OTX
    crt_sh.py          Certificate transparency logs
    dns_brute.py       Async DNS brute-force with wildcard filtering
    asn_lookup.py      ASN → IP range expansion (BGPView)

  validation/
    http_prober.py     HTTP/S probing: status, title, tech, tags

  enrichment/
    crawler.py         In-scope link/JS/form crawling
    js_analyzer.py     Static JS analysis: secrets, endpoints
    wayback.py         Wayback + CommonCrawl historical URLs
    param_miner.py     Parameter extraction and mapping

  vuln_signals/        Detection only — no exploitation
    cors.py            CORS misconfiguration signals
    headers.py         Missing/weak security headers
    takeover.py        Subdomain takeover fingerprints
    exposure.py        Sensitive path/file exposure
    redirect.py        Open redirect parameter signals

  intelligence/
    prioritiser.py     Asset ranking + finding severity sort
    deduplicator.py    Near-duplicate finding removal

output/
  json_reporter.py     Structured JSON output
  html_reporter.py     Self-contained HTML dashboard
```

### Pipeline Flow

```
Targets → [Discovery] → [Validation] → [Enrichment] → [VulnSignals] → [Intelligence] → Report
             ↓               ↓               ↓               ↓               ↓
          Subdomains     Live Assets    JS/Params/URLs    Findings       Ranked Output
```

Each stage reads from and writes to a shared `StateManager` (JSON on disk), enabling:
- Checkpoint/resume for large scopes
- Stage-level skipping
- Cross-stage data access

---

## Installation

```bash
git clone https://github.com/pratikkhairnar160/ReconSuite.git
cd ReconSuite
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

**Optional tools** (called as subprocesses if available in PATH):
- `subfinder` — additional passive subdomain enumeration
- `httpx` — faster live probing alternative
- `nuclei` — template-based vulnerability scanning

---

## Usage

### Quick scan (passive discovery + validation)
```bash
python3 reconsuite.py -d example.com
```

### Full scan (all stages, active probing, JS analysis)
```bash
python3 reconsuite.py -d example.com --full --active-scan --output both
```

### Passive only (OSINT, no active probing)
```bash
python3 reconsuite.py -d example.com --passive-only --output json
```

### Scope file (multi-target)
```bash
python3 reconsuite.py --scope-file targets.txt --threads 100 --rate-limit 200
```

### Resume interrupted scan
```bash
python3 reconsuite.py -d example.com --resume abc123def456
```

### With proxy (Burp Suite / SOCKS)
```bash
python3 reconsuite.py -d example.com --proxy http://127.0.0.1:8080 --rotate-ua
```

### Control which stages run
```bash
# Only discovery and validation
python3 reconsuite.py -d example.com --only-stages discovery validation

# Skip JS-heavy enrichment
python3 reconsuite.py -d example.com --skip-stages enrichment
```

---

## CLI Reference

| Flag | Default | Description |
|------|---------|-------------|
| `-d` / `--domain` | — | Single target domain |
| `--scope-file` | — | File with one domain per line |
| `--passive-only` | off | No active probing |
| `--active-scan` | off | Enable active signal checks |
| `--full` | off | All stages + JS analysis |
| `--threads` | 50 | Concurrency limit |
| `--rate-limit` | 100 | Max requests/sec |
| `--timeout` | 10 | Request timeout (sec) |
| `--retries` | 2 | Retry count |
| `--proxy` | — | HTTP/SOCKS proxy URL |
| `--rotate-ua` | off | Rotate User-Agent per request |
| `--delay` | 0 | Per-request delay (sec) |
| `--output` | both | `json` / `html` / `both` |
| `--output-dir` | ./reports | Report output directory |
| `--resume` | — | Session ID to resume |
| `--skip-stages` | — | Stages to skip |
| `--only-stages` | — | Stages to run exclusively |
| `-v` | off | Verbose logging |
| `-q` | off | Quiet (warnings only) |

---

## Output

Reports are written to `./reports/` by default:

- `reconsuite_<session>_<timestamp>.json` — full structured data
- `reconsuite_<session>_<timestamp>.html` — standalone dashboard

The JSON output contains:
```json
{
  "meta": { "session_id": "...", "targets": [...], "elapsed_seconds": 42 },
  "summary": { "subdomains_found": 80, "live_assets": 35, ... },
  "ranked_assets": [ { "url": "...", "priority_score": 9, "tech": [...] } ],
  "findings": [ { "type": "cors", "severity": "high", "confidence": "high", ... } ],
  "parameters": [ { "domain": "...", "parameters": { "redirect": [...] } } ],
  "historical_urls": [...]
}
```

---

## Vulnerability Signal Engine

All checks are **detection and fingerprinting only** — no payloads are sent, no exploitation occurs.

| Check | What it detects |
|-------|-----------------|
| CORS | Wildcard/reflected origins, null origin acceptance |
| Headers | Missing CSP, HSTS, X-Frame-Options, info leakage |
| Takeover | Dangling CNAMEs, service fingerprints (GitHub, S3, Heroku…) |
| Exposure | .git, .env, phpinfo, actuator, debug endpoints |
| Open Redirect | Redirect parameter reflection |
| JS Secrets | API keys, tokens, AWS credentials in client-side JS |

---

## Extending ReconSuite

### Add a discovery source
Create `modules/discovery/my_source.py` with:
```python
class MySource:
    def __init__(self, domain: str, config: Config): ...
    async def enumerate(self) -> List[Dict]: ...
        # Return: [{"hostname": "sub.example.com", "domain": "example.com", "source": "my_source"}]
```
Then import and call it in `core/pipeline.py`'s `_stage_discovery()`.

### Add a vuln signal checker
Create `modules/vuln_signals/my_check.py` with:
```python
class MyChecker:
    async def check_all(self, assets: List[Dict]) -> List[Dict]: ...
        # Return: [{"type": "...", "severity": "...", "confidence": "...", "url": "...", ...}]
```
Add it to the checkers list in `_stage_signals()`.

---

## Legal Notice

This tool is intended exclusively for:
- Authorized penetration testing
- Bug bounty programs within defined scope
- Security research on systems you own or have written permission to test

Unauthorized use is illegal and unethical. The authors assume no liability for misuse.
