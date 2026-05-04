"""
HTMLReporter — generates a clean, self-contained HTML dashboard report.
No external dependencies — single file output.
"""

from __future__ import annotations
import html
import json
from pathlib import Path
from typing import Dict, List

SEV_BADGE = {
    "critical": ("🔴", "#e53e3e", "#fff5f5"),
    "high":     ("🟠", "#dd6b20", "#fffaf0"),
    "medium":   ("🟡", "#d69e2e", "#fffff0"),
    "low":      ("🔵", "#3182ce", "#ebf8ff"),
    "info":     ("⚪", "#718096", "#f7fafc"),
}


class HTMLReporter:
    def __init__(self, results: Dict):
        self.results = results

    def write(self, path: Path):
        path.write_text(self._render(), encoding="utf-8")

    def _render(self) -> str:
        meta     = self.results.get("meta", {})
        summary  = self.results.get("summary", {})
        findings = self.results.get("findings", [])
        assets   = self.results.get("ranked_assets", [])

        sev_counts = {s: 0 for s in SEV_BADGE}
        for f in findings:
            sev = f.get("severity", "info")
            sev_counts[sev] = sev_counts.get(sev, 0) + 1

        targets = ", ".join(meta.get("targets", []))
        session = meta.get("session_id", "")
        elapsed = meta.get("elapsed_seconds", 0)

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>ReconSuite Report — {html.escape(targets)}</title>
<style>
  :root {{
    --bg:#0f172a; --surface:#1e293b; --border:#334155;
    --text:#e2e8f0; --muted:#94a3b8; --accent:#38bdf8;
  }}
  * {{ box-sizing:border-box; margin:0; padding:0; }}
  body {{ font-family:system-ui,sans-serif; background:var(--bg); color:var(--text); padding:2rem; }}
  h1 {{ color:var(--accent); font-size:1.8rem; margin-bottom:.25rem; }}
  h2 {{ font-size:1.2rem; color:var(--accent); margin:2rem 0 1rem; border-bottom:1px solid var(--border); padding-bottom:.5rem; }}
  .meta {{ color:var(--muted); font-size:.9rem; margin-bottom:2rem; }}
  .grid {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(140px,1fr)); gap:1rem; margin:1.5rem 0; }}
  .card {{ background:var(--surface); border:1px solid var(--border); border-radius:.5rem; padding:1.25rem; text-align:center; }}
  .card-num {{ font-size:2rem; font-weight:700; color:var(--accent); }}
  .card-label {{ color:var(--muted); font-size:.8rem; margin-top:.25rem; }}
  .sev-cards {{ display:grid; grid-template-columns:repeat(5,1fr); gap:.75rem; margin:1rem 0; }}
  .sev-card {{ border-radius:.5rem; padding:.75rem; text-align:center; border:1px solid transparent; }}
  .finding {{ background:var(--surface); border:1px solid var(--border); border-radius:.5rem; padding:1rem; margin-bottom:.75rem; }}
  .finding-header {{ display:flex; align-items:center; gap:.75rem; margin-bottom:.5rem; }}
  .badge {{ display:inline-block; padding:.2rem .6rem; border-radius:.25rem; font-size:.75rem; font-weight:600; }}
  .finding-url {{ font-family:monospace; font-size:.8rem; color:var(--muted); word-break:break-all; }}
  .finding-desc {{ font-size:.85rem; margin:.5rem 0; color:#cbd5e1; }}
  .finding-fix {{ font-size:.8rem; color:#a3e635; background:rgba(163,230,53,.1); padding:.5rem; border-radius:.25rem; border-left:3px solid #a3e635; }}
  .asset-row {{ background:var(--surface); border:1px solid var(--border); border-radius:.375rem; padding:.75rem 1rem; margin-bottom:.5rem; display:flex; align-items:center; gap:1rem; flex-wrap:wrap; }}
  .asset-url {{ font-family:monospace; font-size:.85rem; color:var(--accent); flex:1; min-width:200px; }}
  .tech-tag {{ background:#1e3a5f; color:#90cdf4; padding:.15rem .5rem; border-radius:.25rem; font-size:.75rem; }}
  .score {{ background:#1a3a1a; color:#68d391; padding:.15rem .5rem; border-radius:.25rem; font-size:.75rem; font-weight:600; }}
  .tag-interesting {{ background:#3d1e1e; color:#fc8181; padding:.15rem .5rem; border-radius:.25rem; font-size:.75rem; }}
  table {{ width:100%; border-collapse:collapse; font-size:.85rem; }}
  th {{ text-align:left; padding:.5rem; background:var(--surface); color:var(--muted); border-bottom:1px solid var(--border); }}
  td {{ padding:.5rem; border-bottom:1px solid #1e293b; word-break:break-all; }}
  .collapsible {{ cursor:pointer; user-select:none; }}
  .collapsible:hover {{ opacity:.8; }}
  details summary {{ cursor:pointer; padding:.5rem 0; color:var(--muted); font-size:.85rem; }}
</style>
</head>
<body>

<h1>🔍 ReconSuite Attack Surface Report</h1>
<p class="meta">
  Targets: <strong>{html.escape(targets)}</strong> &nbsp;|&nbsp;
  Session: <code>{html.escape(session)}</code> &nbsp;|&nbsp;
  Duration: {elapsed}s
</p>

<h2>📊 Summary</h2>
<div class="grid">
  {self._stat_card(summary.get('subdomains_found',0), 'Subdomains')}
  {self._stat_card(summary.get('live_assets',0), 'Live Assets')}
  {self._stat_card(summary.get('endpoints_found',0), 'Endpoints')}
  {self._stat_card(summary.get('historical_urls',0), 'Historical URLs')}
  {self._stat_card(summary.get('js_findings',0), 'JS Findings')}
  {self._stat_card(summary.get('total_findings',0), 'Total Findings')}
</div>

<h2>🚨 Findings by Severity</h2>
<div class="sev-cards">
  {self._sev_cards(sev_counts)}
</div>

<h2>🚨 Findings ({len(findings)})</h2>
{self._render_findings(findings)}

<h2>🖥️ Ranked Assets ({len(assets)} live)</h2>
{self._render_assets(assets[:100])}

<footer style="margin-top:3rem;color:var(--muted);font-size:.8rem;text-align:center;">
  ReconSuite — For authorized security testing only. Handle this report as confidential.
</footer>
</body>
</html>"""

    def _stat_card(self, value, label) -> str:
        return (
            f'<div class="card">'
            f'<div class="card-num">{value}</div>'
            f'<div class="card-label">{html.escape(str(label))}</div>'
            f'</div>'
        )

    def _sev_cards(self, counts: Dict) -> str:
        parts = []
        for sev, (icon, color, bg) in SEV_BADGE.items():
            parts.append(
                f'<div class="sev-card" style="background:{bg};border-color:{color}">'
                f'<div style="font-size:1.5rem;color:{color};font-weight:700">{counts.get(sev,0)}</div>'
                f'<div style="font-size:.75rem;color:{color}">{icon} {sev.upper()}</div>'
                f'</div>'
            )
        return "".join(parts)

    def _render_findings(self, findings: List[Dict]) -> str:
        if not findings:
            return '<p style="color:var(--muted)">No findings recorded.</p>'
        parts = []
        for f in findings:
            sev  = f.get("severity", "info")
            icon, color, bg = SEV_BADGE.get(sev, SEV_BADGE["info"])
            title = html.escape(f.get("title", f.get("type", "Finding")))
            url   = html.escape(f.get("url", ""))
            desc  = html.escape(f.get("description", ""))
            fix   = html.escape(f.get("remediation", ""))
            conf  = html.escape(f.get("confidence", ""))

            parts.append(f"""
<div class="finding">
  <div class="finding-header">
    <span class="badge" style="background:{color};color:#fff">{icon} {sev.upper()}</span>
    <strong>{title}</strong>
    <span style="color:var(--muted);font-size:.8rem">confidence: {conf}</span>
  </div>
  <div class="finding-url">{url}</div>
  {"<div class='finding-desc'>" + desc + "</div>" if desc else ""}
  {"<div class='finding-fix'>💡 " + fix + "</div>" if fix else ""}
</div>""")
        return "".join(parts)

    def _render_assets(self, assets: List[Dict]) -> str:
        if not assets:
            return '<p style="color:var(--muted)">No assets recorded.</p>'
        parts = []
        for a in assets:
            url    = html.escape(a.get("url", ""))
            tech   = a.get("tech", [])
            tags   = a.get("interesting_tags", [])
            score  = a.get("priority_score", 0)
            status = a.get("status", "")
            title  = html.escape(a.get("title", "")[:80])

            tech_html = " ".join(f'<span class="tech-tag">{html.escape(t)}</span>' for t in tech)
            tags_html = " ".join(f'<span class="tag-interesting">{html.escape(t)}</span>' for t in tags)

            parts.append(f"""
<div class="asset-row">
  <a class="asset-url" href="{url}" target="_blank" rel="noopener">{url}</a>
  <span style="color:var(--muted);font-size:.8rem">{status}</span>
  <span class="score">score:{score}</span>
  {tech_html}
  {tags_html}
  {"<span style='color:var(--muted);font-size:.8rem'>" + title + "</span>" if title else ""}
</div>""")
        return "".join(parts)
