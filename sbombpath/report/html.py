"""HTML report — Checkmarx-style Risks / Exploitable Path viewer."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Optional

from ..models import ExposureKind, ExploitableFinding, ReportMeta


def _esc(text: Any) -> str:
    return (
        str(text)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


def _sev_class(sev: str) -> str:
    s = (sev or "").lower()
    if s in {"critical", "high", "medium", "low"}:
        return s
    return "info"


def _reachability_label(finding: Optional[ExploitableFinding], row: Optional[Dict] = None) -> tuple[str, str]:
    """Return (css_class, label) Checkmarx-style."""
    if finding:
        if finding.exposure == ExposureKind.USER_FACING and finding.status.value == "EXPLOITABLE":
            return "ep-found", "Exp. Path Found"
        if finding.exposure == ExposureKind.INTERNAL_TAINT and finding.status.value == "EXPLOITABLE":
            return "ep-found", "Exp. Path Found"
        if finding.status.value == "MITIGATED":
            return "ep-mitigated", "Mitigated"
        if finding.exposure == ExposureKind.PACKAGE_SURFACE:
            return "ep-used", "Package Used"
        if finding.status.value == "UNKNOWN":
            return "ep-pending", "Needs Review"
    if row:
        code = row.get("reason_code") or ""
        if code == "RULE_NO_MATCH_IN_CODE":
            return "ep-not", "Not Detected"
        if code == "PACKAGE_KNOWN_CVE_NOT_MODELED":
            return "ep-unsupported", "Not Supported"
        if code == "NO_PATH_RULE":
            return "ep-unsupported", "Not Supported"
        if row.get("relevant"):
            return "ep-found", "Exp. Path Found"
    return "ep-not", "Not Detected"


def _path_chain(f: ExploitableFinding) -> str:
    nodes = []
    if f.http_endpoint:
        nodes.append(("Route", f.http_endpoint, ""))
    src = f.taint_source or {}
    if src.get("expression"):
        nodes.append(("Source", src.get("expression") or "", src.get("location") or ""))
    for step in f.data_flow_path[1:-1] if len(f.data_flow_path) > 2 else []:
        label = step.get("code") or step.get("function") or step.get("var") or step.get("type") or ""
        nodes.append((step.get("type") or "step", label, step.get("location") or ""))
    sink = f.taint_sink or {}
    if sink.get("expression"):
        nodes.append(("Sink", sink.get("expression") or "", sink.get("location") or ""))
    if not nodes and f.path_description:
        nodes.append(("Path", f.path_description, ""))

    parts = []
    for i, (kind, code, loc) in enumerate(nodes):
        parts.append(
            f"""<div class="node">
  <div class="node-kind">{_esc(kind)}</div>
  <div class="node-code">{_esc(code)}</div>
  <div class="node-loc">{_esc(loc)}</div>
</div>"""
        )
        if i < len(nodes) - 1:
            parts.append('<div class="node-arrow" aria-hidden="true">→</div>')
    return f'<div class="path-chain">{"".join(parts)}</div>'


def _finding_detail(f: ExploitableFinding, idx: int) -> str:
    css, label = _reachability_label(f)
    src = f.taint_source or {}
    sink = f.taint_sink or {}
    rem = f'<div class="detail-remediation"><strong>Remediation</strong><p>{_esc(f.remediation)}</p></div>' if f.remediation else ""
    notes = "".join(f"<li>{_esc(n)}</li>" for n in f.analysis_notes)
    notes_html = f'<ul class="detail-notes">{notes}</ul>' if notes else ""
    mit = ""
    if f.mitigation_detected:
        mit = (
            f'<div class="meta-row"><span>Mitigation</span>'
            f'<code>{_esc(f.mitigation_detected)}</code> '
            f'<span class="muted">{_esc(f.mitigation_location or "")}</span></div>'
        )
    route = f.http_endpoint or "—"
    return f"""
<details class="risk-detail" {"open" if idx <= 3 else ""}>
  <summary>
    <span class="sev-dot {_sev_class(f.severity)}"></span>
    <span class="cve">{_esc(f.cve_id)}</span>
    <span class="pkg">{_esc(f.package)}</span>
    <span class="reach {_esc(css)}">{_esc(label)}</span>
    <span class="route">{_esc(route)}</span>
  </summary>
  <div class="detail-body">
    <div class="detail-grid">
      <div><span class="lbl">Severity</span><span class="sev-pill {_sev_class(f.severity)}">{_esc(f.severity)}</span></div>
      <div><span class="lbl">Reachability</span><span class="reach {_esc(css)}">{_esc(label)}</span></div>
      <div><span class="lbl">Exposure</span><code>{_esc(f.exposure.value)}</code></div>
      <div><span class="lbl">Action</span><code>{_esc(f.priority)}</code></div>
      <div><span class="lbl">Source</span><code>{_esc(src.get("expression") or "—")}</code><div class="muted">{_esc(src.get("location") or "")}</div></div>
      <div><span class="lbl">Sink</span><code>{_esc(sink.get("expression") or "—")}</code><div class="muted">{_esc(sink.get("location") or "")}</div></div>
    </div>
    {mit}
    <div class="ep-card">
      <div class="ep-title">Exploitable Path</div>
      {_path_chain(f)}
    </div>
    {rem}
    {notes_html}
  </div>
</details>
"""


def _risks_table_rows(
    findings: List[ExploitableFinding],
    comparison: Dict[str, Any],
) -> str:
    """Master Risks table: path findings first, then SBOM not-relevant."""
    rows_html = []

    # Path-relevant findings
    for f in findings:
        css, label = _reachability_label(f)
        rows_html.append(
            f"""<tr class="clickable" data-target="finding-{_esc(f.cve_id)}-{_esc((f.taint_sink or {}).get('location',''))}">
  <td><span class="sev-pill {_sev_class(f.severity)}">{_esc(f.severity)}</span></td>
  <td class="mono">{_esc(f.cve_id)}</td>
  <td>{_esc(f.package)}</td>
  <td><span class="reach {_esc(css)}">{_esc(label)}</span></td>
  <td class="mono muted">{_esc(f.http_endpoint or "—")}</td>
  <td class="mono muted">{_esc((f.taint_sink or {}).get("location") or "—")}</td>
</tr>"""
        )

    # SBOM CVEs with no path finding
    for row in comparison.get("not_relevant") or []:
        css, label = _reachability_label(None, row)
        rows_html.append(
            f"""<tr>
  <td><span class="sev-pill {_sev_class(str(row.get("severity") or ""))}">{_esc(row.get("severity") or "—")}</span></td>
  <td class="mono">{_esc(row.get("id"))}</td>
  <td>{_esc(row.get("package"))}</td>
  <td><span class="reach {_esc(css)}">{_esc(label)}</span></td>
  <td class="muted">—</td>
  <td class="muted why-cell">{_esc(row.get("why") or "—")}</td>
</tr>"""
        )

    if not rows_html:
        return '<tr><td colspan="6" class="empty-cell">No risks to display</td></tr>'
    return "".join(rows_html)


def write_html(
    output_dir: Path,
    meta: ReportMeta,
    findings: List[ExploitableFinding],
    comparison: Optional[Dict[str, Any]] = None,
) -> None:
    comparison = comparison or {}
    ep_found = sum(
        1
        for f in findings
        if f.exposure in {ExposureKind.USER_FACING, ExposureKind.INTERNAL_TAINT}
        and f.status.value == "EXPLOITABLE"
    )
    package_used = sum(1 for f in findings if f.exposure == ExposureKind.PACKAGE_SURFACE)
    not_detected = comparison.get("not_relevant_count") or 0
    total_risks = comparison.get("sbom_cves_total") or meta.cves_analyzed

    # Sort findings: exploitable user-facing first
    order = {
        ExposureKind.USER_FACING: 0,
        ExposureKind.INTERNAL_TAINT: 1,
        ExposureKind.PACKAGE_SURFACE: 2,
    }
    sorted_findings = sorted(
        findings,
        key=lambda f: (
            0 if f.status.value == "EXPLOITABLE" else 1,
            order.get(f.exposure, 9),
            f.cve_id,
        ),
    )

    details = "".join(
        _finding_detail(f, i) for i, f in enumerate(sorted_findings, 1)
    ) or '<p class="empty-block">No exploitable paths detected.</p>'

    # Compact not-relevant summary by reason
    by_reason: Dict[str, int] = {}
    for row in comparison.get("not_relevant") or []:
        code = str(row.get("reason_code") or "OTHER")
        by_reason[code] = by_reason.get(code, 0) + 1
    reason_labels = {
        "RULE_NO_MATCH_IN_CODE": "Not Detected — rule exists, pattern not reached",
        "PACKAGE_KNOWN_CVE_NOT_MODELED": "Not Supported — CVE not modeled as taint path",
        "NO_PATH_RULE": "Not Supported — no path rule for CVE/package",
    }
    reason_rows_parts = []
    for k, v in sorted(by_reason.items(), key=lambda x: -x[1]):
        label = reason_labels.get(k, k)
        reason_rows_parts.append(
            "<li>"
            f'<span class="reach ep-unsupported">{_esc(label)}</span>'
            f"<strong>{v}</strong>"
            "</li>"
        )
    reason_rows = "".join(reason_rows_parts) or "<li class='muted'>No SBOM comparison data</li>"

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>sBOMBPath — SCA Results</title>
<style>
:root {{
  --bg: #f4f6f9;
  --panel: #ffffff;
  --ink: #1b2332;
  --muted: #6b778c;
  --line: #dfe3ea;
  --blue: #0052cc;
  --blue-soft: #deebff;
  --green: #006644;
  --green-bg: #e3fcef;
  --red: #de350b;
  --red-bg: #ffebe6;
  --orange: #ff8b00;
  --orange-bg: #fff7e6;
  --yellow: #ffc400;
  --purple: #5243aa;
  --purple-bg: #eae6ff;
  --gray-bg: #ebecf0;
  --header: #172b4d;
  --mono: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  --sans: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
}}
* {{ box-sizing: border-box; }}
body {{
  margin: 0;
  font-family: var(--sans);
  color: var(--ink);
  background: var(--bg);
  font-size: 13px;
  line-height: 1.45;
}}
.topbar {{
  background: var(--header);
  color: #fff;
  padding: 0.85rem 1.5rem;
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 1rem;
}}
.topbar .product {{ font-weight: 700; letter-spacing: 0.02em; font-size: 0.95rem; }}
.topbar .product span {{ font-weight: 500; opacity: 0.7; margin-left: 0.5rem; }}
.topbar .meta {{ opacity: 0.75; font-size: 0.8rem; }}
.page {{ max-width: 1280px; margin: 0 auto; padding: 1.25rem 1.25rem 3rem; }}
.overview {{
  display: grid;
  grid-template-columns: repeat(4, 1fr);
  gap: 0.75rem;
  margin-bottom: 1.25rem;
}}
.kpi {{
  background: var(--panel);
  border: 1px solid var(--line);
  border-radius: 3px;
  padding: 0.9rem 1rem;
}}
.kpi .label {{
  color: var(--muted); font-size: 0.72rem; text-transform: uppercase;
  letter-spacing: 0.04em; font-weight: 600;
}}
.kpi .value {{ font-size: 1.6rem; font-weight: 700; margin-top: 0.15rem; color: var(--header); }}
.kpi.accent .value {{ color: var(--red); }}
.kpi.ok .value {{ color: var(--green); }}
.panel {{
  background: var(--panel);
  border: 1px solid var(--line);
  border-radius: 3px;
  margin-bottom: 1rem;
}}
.panel-h {{
  display: flex; align-items: center; justify-content: space-between;
  gap: 1rem; padding: 0.75rem 1rem; border-bottom: 1px solid var(--line);
}}
.panel-h h2 {{ margin: 0; font-size: 0.95rem; font-weight: 600; color: var(--header); }}
.panel-h .hint {{ color: var(--muted); font-size: 0.8rem; }}
.tabs {{
  display: flex; gap: 0; border-bottom: 1px solid var(--line);
  padding: 0 0.5rem; background: var(--panel); margin-bottom: 0;
  border: 1px solid var(--line); border-bottom: 0; border-radius: 3px 3px 0 0;
}}
.tabs a {{
  text-decoration: none; color: var(--muted); padding: 0.7rem 0.9rem;
  font-weight: 600; font-size: 0.82rem; border-bottom: 2px solid transparent;
}}
.tabs a.active, .tabs a:hover {{ color: var(--blue); border-bottom-color: var(--blue); }}
.panel.tabbed {{ border-radius: 0 0 3px 3px; }}
table.risks {{ width: 100%; border-collapse: collapse; }}
table.risks th {{
  text-align: left; font-size: 0.7rem; text-transform: uppercase;
  letter-spacing: 0.04em; color: var(--muted); font-weight: 600;
  padding: 0.55rem 0.75rem; border-bottom: 1px solid var(--line);
  background: #fafbfc; position: sticky; top: 0;
}}
table.risks td {{
  padding: 0.55rem 0.75rem; border-bottom: 1px solid var(--line); vertical-align: middle;
}}
table.risks tr:hover td {{ background: #f7f9fc; }}
.mono {{ font-family: var(--mono); font-size: 0.78rem; }}
.muted {{ color: var(--muted); }}
.sev-pill {{
  display: inline-block; min-width: 4.5rem; text-align: center;
  font-size: 0.65rem; font-weight: 700; text-transform: uppercase;
  letter-spacing: 0.03em; padding: 0.18rem 0.4rem; border-radius: 3px;
}}
.sev-pill.critical {{ background: var(--red); color: #fff; }}
.sev-pill.high {{ background: var(--orange); color: #fff; }}
.sev-pill.medium {{ background: var(--yellow); color: #172b4d; }}
.sev-pill.low {{ background: var(--blue-soft); color: var(--blue); }}
.sev-pill.info {{ background: var(--gray-bg); color: var(--muted); }}
.reach {{
  display: inline-block; font-size: 0.72rem; font-weight: 600;
  padding: 0.15rem 0.45rem; border-radius: 3px; white-space: nowrap;
}}
.reach.ep-found {{ background: var(--red-bg); color: var(--red); }}
.reach.ep-used {{ background: var(--orange-bg); color: #974f0c; }}
.reach.ep-mitigated {{ background: var(--green-bg); color: var(--green); }}
.reach.ep-not {{ background: var(--green-bg); color: var(--green); }}
.reach.ep-unsupported {{ background: var(--gray-bg); color: var(--muted); }}
.reach.ep-pending {{ background: var(--purple-bg); color: var(--purple); }}
.why-cell {{
  min-width: 220px;
  max-width: 420px;
  white-space: normal;
  word-break: break-word;
  font-size: 0.75rem;
  line-height: 1.4;
}}
table.risks td.mono {{
  white-space: normal;
  word-break: break-all;
}}
.empty-cell, .empty-block {{ color: var(--muted); padding: 1.25rem; text-align: center; }}
.scroll {{ max-height: 420px; overflow: auto; }}
.risk-detail {{ border-bottom: 1px solid var(--line); }}
.risk-detail:last-child {{ border-bottom: 0; }}
.risk-detail summary {{
  list-style: none; cursor: pointer;
  display: grid; grid-template-columns: 12px 170px 110px 130px 1fr;
  gap: 0.75rem; align-items: center; padding: 0.7rem 1rem;
}}
.risk-detail summary::-webkit-details-marker {{ display: none; }}
.risk-detail summary:hover {{ background: #f7f9fc; }}
.risk-detail[open] summary {{ background: #f0f4fa; border-bottom: 1px solid var(--line); }}
.sev-dot {{ width: 8px; height: 8px; border-radius: 50%; background: var(--muted); }}
.sev-dot.critical {{ background: var(--red); }}
.sev-dot.high {{ background: var(--orange); }}
.sev-dot.medium {{ background: #e2b203; }}
.sev-dot.low {{ background: var(--blue); }}
.risk-detail .cve {{ font-family: var(--mono); font-weight: 600; font-size: 0.8rem; }}
.risk-detail .pkg {{ color: var(--muted); }}
.risk-detail .route {{ font-family: var(--mono); color: var(--muted); font-size: 0.75rem; text-align: right; }}
.detail-body {{ padding: 1rem 1.1rem 1.25rem; background: #fafbfc; }}
.detail-grid {{
  display: grid; grid-template-columns: repeat(3, 1fr);
  gap: 0.75rem; margin-bottom: 0.85rem;
}}
.detail-grid .lbl {{
  display: block; font-size: 0.68rem; text-transform: uppercase;
  letter-spacing: 0.04em; color: var(--muted); font-weight: 600; margin-bottom: 0.2rem;
}}
.detail-grid code {{ font-family: var(--mono); font-size: 0.78rem; word-break: break-word; }}
.meta-row {{ margin-bottom: 0.75rem; font-size: 0.82rem; }}
.meta-row span:first-child {{
  color: var(--muted); margin-right: 0.4rem; font-weight: 600;
  font-size: 0.68rem; text-transform: uppercase;
}}
.ep-card {{
  border: 1px solid var(--line); border-radius: 3px;
  background: var(--panel); padding: 0.85rem 1rem; margin: 0.5rem 0;
}}
.ep-title {{
  font-size: 0.72rem; font-weight: 700; text-transform: uppercase;
  letter-spacing: 0.04em; color: var(--header); margin-bottom: 0.75rem;
}}
.path-chain {{ display: flex; flex-wrap: wrap; align-items: stretch; gap: 0.35rem; }}
.node {{
  background: var(--blue-soft); border: 1px solid #b3d4ff;
  border-radius: 3px; padding: 0.45rem 0.6rem; min-width: 140px; max-width: 220px;
}}
.path-chain > .node:first-child {{ background: #e3fcef; border-color: #abf5d1; }}
.path-chain > .node:last-of-type {{ background: var(--red-bg); border-color: #ffbdad; }}
.node-kind {{
  font-size: 0.62rem; font-weight: 700; text-transform: uppercase;
  letter-spacing: 0.04em; color: var(--muted); margin-bottom: 0.15rem;
}}
.node-code {{ font-family: var(--mono); font-size: 0.72rem; word-break: break-word; color: var(--ink); }}
.node-loc {{ font-family: var(--mono); font-size: 0.65rem; color: var(--muted); margin-top: 0.2rem; }}
.node-arrow {{ display: flex; align-items: center; color: var(--blue); font-weight: 700; padding: 0 0.15rem; }}
.detail-remediation {{
  margin-top: 0.75rem; padding: 0.65rem 0.75rem;
  background: var(--green-bg); border-radius: 3px; color: var(--green);
}}
.detail-remediation strong {{
  display: block; font-size: 0.68rem; text-transform: uppercase;
  letter-spacing: 0.04em; margin-bottom: 0.2rem;
}}
.detail-remediation p {{ margin: 0; font-size: 0.82rem; }}
.detail-notes {{ margin: 0.5rem 0 0; padding-left: 1.1rem; color: var(--muted); }}
.legend {{
  display: flex; flex-wrap: wrap; gap: 0.75rem; padding: 0.75rem 1rem;
  border-top: 1px solid var(--line); color: var(--muted); font-size: 0.75rem;
}}
.legend span {{ display: inline-flex; align-items: center; gap: 0.35rem; }}
.summary-list {{ list-style: none; margin: 0; padding: 0.5rem 1rem 1rem; }}
.summary-list li {{
  display: flex; justify-content: space-between; align-items: center;
  gap: 1rem; padding: 0.45rem 0; border-bottom: 1px solid var(--line);
}}
.summary-list li:last-child {{ border-bottom: 0; }}
@media (max-width: 900px) {{
  .overview {{ grid-template-columns: 1fr 1fr; }}
  .risk-detail summary {{ grid-template-columns: 12px 1fr; }}
  .risk-detail .pkg, .risk-detail .reach, .risk-detail .route {{ display: none; }}
  .detail-grid {{ grid-template-columns: 1fr; }}
}}
</style>
</head>
<body>
  <header class="topbar">
    <div class="product">sBOMBPath <span>SCA Results · Exploitable Path</span></div>
    <div class="meta">Generated {_esc(meta.generated_at)}</div>
  </header>

  <div class="page">
    <div class="overview">
      <div class="kpi"><div class="label">SBOM Risks</div><div class="value">{_esc(total_risks)}</div></div>
      <div class="kpi accent"><div class="label">Exp. Path Found</div><div class="value">{ep_found}</div></div>
      <div class="kpi"><div class="label">Package Used</div><div class="value">{package_used}</div></div>
      <div class="kpi ok"><div class="label">Not Detected / N/S</div><div class="value">{not_detected}</div></div>
    </div>

    <nav class="tabs">
      <a class="active" href="#risks">Risks</a>
      <a href="#paths">Exploitable Paths</a>
      <a href="#triage">SBOM Triage</a>
    </nav>

    <section class="panel tabbed" id="risks">
      <div class="panel-h">
        <h2>Risks</h2>
        <span class="hint">Reachability = whether your code can hit the vulnerable method</span>
      </div>
      <div class="scroll">
        <table class="risks">
          <thead>
            <tr>
              <th>Severity</th>
              <th>Vulnerability</th>
              <th>Package</th>
              <th>Reachability</th>
              <th>Route</th>
              <th>Sink / Reason</th>
            </tr>
          </thead>
          <tbody>
            {_risks_table_rows(sorted_findings, comparison)}
          </tbody>
        </table>
      </div>
      <div class="legend">
        <span><span class="reach ep-found">Exp. Path Found</span> user/internal taint → sink</span>
        <span><span class="reach ep-used">Package Used</span> vulnerable API called, no proven user path</span>
        <span><span class="reach ep-not">Not Detected</span> no path to vulnerable method</span>
        <span><span class="reach ep-unsupported">Not Supported</span> not modeled as taint path</span>
      </div>
    </section>

    <section class="panel" id="paths">
      <div class="panel-h">
        <h2>Exploitable Path details</h2>
        <span class="hint">{len(sorted_findings)} finding(s) with code evidence</span>
      </div>
      {details}
    </section>

    <section class="panel" id="triage">
      <div class="panel-h">
        <h2>SBOM triage summary</h2>
        <span class="hint">{_esc(comparison.get("relevant_count", 0))} path-relevant · {_esc(comparison.get("not_relevant_count", 0))} not path-relevant</span>
      </div>
      <ul class="summary-list">
        {reason_rows}
      </ul>
      <div class="legend">
        Not path-relevant CVEs still appear in the Risks table. Upgrade may still be required.
      </div>
    </section>

  </div>
</body>
</html>
"""
    (output_dir / "exploitable-paths.html").write_text(html, encoding="utf-8")