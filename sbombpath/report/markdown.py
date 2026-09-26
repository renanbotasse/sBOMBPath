"""Markdown report writer."""

from __future__ import annotations

from pathlib import Path
from typing import List

from ..models import ExploitableFinding, FindingStatus, ReportMeta


def write_markdown(
    output_dir: Path, meta: ReportMeta, findings: List[ExploitableFinding]
) -> None:
    lines: List[str] = [
        "# Exploitable Vulnerability Paths Report",
        "",
        "## Summary",
        f"- Generated at: {meta.generated_at}",
        f"- Total CVEs analyzed: {meta.cves_analyzed}",
        f"- Exploitable paths found: {meta.exploitable_paths}",
        f"- Mitigated paths: {meta.mitigated_paths}",
        f"- Unknown paths: {meta.unknown_paths}",
        "",
        (
            "> Analysis uses AST-based taint tracking. Reflection, pickle, and complex "
            "aliasing are out of scope for the MVP and may yield incomplete results."
        ),
        "",
    ]

    groups = [
        ("CRITICAL - Directly Exploitable", FindingStatus.EXPLOITABLE),
        ("MEDIUM - Mitigated / Reduced Risk", FindingStatus.MITIGATED),
        ("UNKNOWN - Needs Manual Review", FindingStatus.UNKNOWN),
    ]
    for title, status in groups:
        group = [f for f in findings if f.status == status]
        if not group:
            continue
        lines.append(f"## {title}")
        lines.append("")
        for idx, f in enumerate(group, 1):
            lines.extend(_render_finding(idx, f))

    lines.extend(
        [
            "## Summary Table",
            "",
            "| CVE ID | Package | Status | Endpoint | Risk | Action |",
            "|---|---|---|---|---|---|",
        ]
    )
    for f in findings:
        lines.append(
            f"| {f.cve_id} | {f.package} | {f.status.value} | "
            f"{f.http_endpoint or '—'} | {f.risk_level.value} | {f.priority} |"
        )
    lines.append("")

    path = output_dir / "exploitable-paths.md"
    path.write_text("\n".join(lines), encoding="utf-8")


def _render_finding(idx: int, f: ExploitableFinding) -> List[str]:
    lines = [
        f"### {idx}. {f.cve_id}: {f.package}",
        "",
        f"**Status:** {f.status.value}  ",
        f"**HTTP Endpoint:** `{f.http_endpoint or 'unmapped'}`  ",
        f"**Risk Level:** {f.risk_level.value}  ",
        f"**Priority:** {f.priority}  ",
        "",
        "**Taint Source:**",
        f"- `{f.taint_source.get('expression')}` at `{f.taint_source.get('location')}`",
        "",
        "**Vulnerable Sink:**",
        f"- `{f.taint_sink.get('expression')}` at `{f.taint_sink.get('location')}`",
        "",
        "**Complete Data Flow Path:**",
        "",
        "```",
        f.path_description,
    ]
    for step in f.data_flow_path:
        bit = step.get("code") or step.get("type")
        loc = step.get("location", "")
        lines.append(f"  ↓ [{step.get('type')}] {bit} ({loc})")
    lines.append("```")
    lines.append("")
    if f.attack_payload_example:
        lines.extend(
            [
                "**Attack Payload Example:**",
                "```",
                f.attack_payload_example,
                "```",
                "",
            ]
        )
    if f.mitigation_detected:
        lines.append(
            f"**Mitigation Detected:** `{f.mitigation_detected}` "
            f"at `{f.mitigation_location}`"
        )
        lines.append("")
    if f.remediation:
        lines.extend(["**Remediation:**", f"- {f.remediation}", ""])
    for note in f.analysis_notes:
        lines.extend([f"_Note: {note}_", ""])
    lines.extend(["---", ""])
    return lines
