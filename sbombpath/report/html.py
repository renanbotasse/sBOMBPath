"""HTML report writer."""

from __future__ import annotations

from pathlib import Path
from typing import Any, List

from ..models import ExploitableFinding, ReportMeta


def _esc(text: Any) -> str:
    return (
        str(text)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


def write_html(
    output_dir: Path, meta: ReportMeta, findings: List[ExploitableFinding]
) -> None:
    rows = []
    for f in findings:
        rows.append(
            "<tr>"
            f"<td>{_esc(f.cve_id)}</td>"
            f"<td>{_esc(f.package)}</td>"
            f"<td><span class='badge {_esc(f.status.value.lower())}'>"
            f"{_esc(f.status.value)}</span></td>"
            f"<td>{_esc(f.http_endpoint or '—')}</td>"
            f"<td>{_esc(f.risk_level.value)}</td>"
            f"<td><code>{_esc(f.taint_source.get('location', ''))}</code></td>"
            f"<td><code>{_esc(f.taint_sink.get('location', ''))}</code></td>"
            f"<td>{_esc(f.mitigation_detected or '—')}</td>"
            "</tr>"
        )

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<title>Exploitable Paths Report</title>
<style>
  :root {{ --bg:#0f1419; --card:#1a2332; --text:#e7ecf3; --muted:#8b9bb4;
           --crit:#e85d5d; --ok:#3ecf8e; --warn:#e6b35a; }}
  body {{ font-family: ui-sans-serif, system-ui, sans-serif; background:var(--bg);
         color:var(--text); margin:0; padding:2rem; }}
  h1 {{ margin-top:0; }}
  .meta {{ color:var(--muted); margin-bottom:1.5rem; }}
  .cards {{ display:flex; gap:1rem; flex-wrap:wrap; margin-bottom:1.5rem; }}
  .card {{ background:var(--card); padding:1rem 1.25rem; border-radius:8px; min-width:140px; }}
  .card strong {{ display:block; font-size:1.6rem; }}
  table {{ width:100%; border-collapse:collapse; background:var(--card); border-radius:8px;
           overflow:hidden; }}
  th, td {{ text-align:left; padding:0.65rem 0.75rem; border-bottom:1px solid #2a3548;
            font-size:0.9rem; vertical-align:top; }}
  th {{ color:var(--muted); font-weight:600; }}
  code {{ font-size:0.8rem; }}
  .badge {{ padding:0.15rem 0.45rem; border-radius:4px; font-size:0.75rem; font-weight:600; }}
  .badge.exploitable {{ background:var(--crit); color:#fff; }}
  .badge.mitigated {{ background:var(--ok); color:#062; }}
  .badge.unknown {{ background:var(--warn); color:#321; }}
  .note {{ color:var(--muted); font-size:0.85rem; margin-top:1.5rem; }}
</style>
</head>
<body>
  <h1>Exploitable Vulnerability Paths</h1>
  <p class="meta">Generated {_esc(meta.generated_at)} · CVEs analyzed: {meta.cves_analyzed}</p>
  <div class="cards">
    <div class="card"><span>Exploitable</span><strong>{meta.exploitable_paths}</strong></div>
    <div class="card"><span>Mitigated</span><strong>{meta.mitigated_paths}</strong></div>
    <div class="card"><span>Unknown</span><strong>{meta.unknown_paths}</strong></div>
  </div>
  <table>
    <thead>
      <tr>
        <th>CVE</th><th>Package</th><th>Status</th><th>Endpoint</th>
        <th>Risk</th><th>Source</th><th>Sink</th><th>Mitigation</th>
      </tr>
    </thead>
    <tbody>
      {''.join(rows) if rows else '<tr><td colspan="8">No findings</td></tr>'}
    </tbody>
  </table>
  <p class="note">sBOMBPath — AST taint-path analysis.
  Reflection and complex aliasing are out of scope.</p>
</body>
</html>
"""
    (output_dir / "exploitable-paths.html").write_text(html, encoding="utf-8")
