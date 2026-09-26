"""Markdown report writer — three-axis layout."""

from __future__ import annotations

from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from ..models import ExposureKind, ExploitableFinding, ReportMeta


def write_markdown(
    output_dir: Path,
    meta: ReportMeta,
    findings: List[ExploitableFinding],
    comparison: Optional[Dict[str, Any]] = None,
) -> None:
    user = [f for f in findings if f.exposure == ExposureKind.USER_FACING]
    internal = [f for f in findings if f.exposure == ExposureKind.INTERNAL_TAINT]
    package = [f for f in findings if f.exposure == ExposureKind.PACKAGE_SURFACE]

    lines: List[str] = [
        "# sBOMBPath Report",
        "",
        "## What this report answers",
        "",
        "1. **User-facing** — which HTTP routes can push attacker-controlled data "
        "into a dangerous API.",
        "2. **Contaminated code** — which internal functions/modules carry tainted "
        "data to a dangerous sink (even when there is no clear public route).",
        "3. **Package / API surface** — where vulnerable or high-risk package APIs "
        "are used in your code. These matter even without a user route: a "
        "compromised dependency, internal job, or untraced caller can still hit them.",
        "",
        "## Summary",
        f"- Generated at: `{meta.generated_at}`",
        f"- CVEs in input list: **{meta.cves_analyzed}**",
        f"- User-facing paths: **{meta.user_facing}**",
        f"- Internal contaminated paths: **{meta.internal_taint}**",
        f"- Package/API surface call sites: **{meta.package_surface}**",
        f"- Of which mitigated: **{meta.mitigated_paths}** · unknown: **{meta.unknown_paths}**",
        "",
        (
            "> Static AST taint analysis. It does **not** execute your app. "
            "Missing a route does **not** mean safe — see sections B and C."
        ),
        "",
    ]

    lines.extend(_contaminated_inventory(user + internal))

    lines.extend(
        _section(
            "A. User-facing — routes an attacker can hit",
            "HTTP-mapped path: user input → contaminated code → dangerous sink.",
            user,
            empty="No user-facing taint paths found.",
        )
    )
    lines.extend(
        _section(
            "B. Contaminated code — internal / unmapped paths",
            "Tainted data reaches a sink inside the app without a clear public "
            "route (helpers, jobs, webhooks, unmapped views).",
            internal,
            empty="No internal contaminated paths found.",
        )
    )
    lines.extend(
        _section(
            "C. Package / API surface — dangerous call sites in use",
            "Reported CVE or GENERIC dangerous API is called in source. "
            "No proven user→sink path, but the call site is still an attack "
            "surface if the package is compromised or data arrives via another channel.",
            package,
            empty="No unmatched dangerous package call sites.",
            compact=True,
        )
    )

    lines.extend(_summary_table(findings))
    lines.extend(_comparison_section(comparison or {}))

    path = output_dir / "exploitable-paths.md"
    path.write_text("\n".join(lines), encoding="utf-8")


def _comparison_section(comparison: Dict[str, Any]) -> List[str]:
    if not comparison or not comparison.get("sbom_cves_total"):
        return [
            "## D. SBOM vs sBOMBPath",
            "",
            "_No SBOM/CVE input was provided (`--cves`), so there is nothing to compare._",
            "",
        ]

    relevant = comparison.get("relevant") or []
    not_relevant = comparison.get("not_relevant") or []
    lines = [
        "## D. SBOM vs sBOMBPath",
        "",
        "sBOMBox (or any SCA) lists **dependency CVEs**. sBOMBPath asks whether those "
        "CVEs matter as **reachable / contaminated / package-API paths** in your code.",
        "",
        f"- SBOM CVEs: **{comparison.get('sbom_cves_total', 0)}**",
        f"- Relevant to path analysis: **{comparison.get('relevant_count', 0)}**",
        f"- Not path-relevant (still may need upgrades): **{comparison.get('not_relevant_count', 0)}**",
        "",
        "### Relevant to sBOMBPath",
        "",
    ]
    if not relevant:
        lines.extend(["_None of the SBOM CVEs produced a path/package-surface finding._", ""])
    else:
        for row in relevant:
            sinks = ", ".join(f"`{s}`" for s in (row.get("sink_locations") or [])[:4]) or "—"
            lines.extend(
                [
                    f"#### `{row.get('id')}` · {row.get('package')} · {row.get('severity')}",
                    "",
                    f"- **Verdict:** `{row.get('verdict')}`",
                    f"- **Why:** {row.get('why')}",
                    f"- **Sinks:** {sinks}",
                    "",
                ]
            )

    lines.extend(["### Not path-relevant (and why)", ""])
    if not not_relevant:
        lines.extend(["_Every SBOM CVE had some path relevance._", ""])
    else:
        # Group by reason_code for readability
        by_reason: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        for row in not_relevant:
            by_reason[str(row.get("reason_code") or "OTHER")].append(row)

        reason_titles = {
            "NO_PATH_RULE": "No sBOMBPath rule for this CVE/package",
            "PACKAGE_KNOWN_CVE_NOT_MODELED": "Package known, but this CVE is not modeled as a taint sink",
            "RULE_NO_MATCH_IN_CODE": "Rule exists, but pattern not found / not reached in code",
        }
        for code, title in reason_titles.items():
            rows = by_reason.get(code) or []
            if not rows:
                continue
            lines.extend([f"#### {title} ({len(rows)})", ""])
            for row in rows:
                summary = row.get("summary") or ""
                if len(summary) > 120:
                    summary = summary[:117] + "…"
                lines.append(
                    f"- `{row.get('id')}` · **{row.get('package')}** · {row.get('severity')}"
                    f" — {summary}"
                )
                lines.append(f"  - _{row.get('why')}_")
            lines.append("")

        # Any unexpected codes
        for code, rows in by_reason.items():
            if code in reason_titles:
                continue
            lines.extend([f"#### Other ({code}) ({len(rows)})", ""])
            for row in rows:
                lines.append(f"- `{row.get('id')}` · {row.get('package')} — {row.get('why')}")
            lines.append("")

    return lines


def _contaminated_inventory(findings: List[ExploitableFinding]) -> List[str]:
    if not findings:
        return []
    by_file: Dict[str, Set[str]] = defaultdict(set)
    for f in findings:
        for step in f.data_flow_path:
            loc = step.get("location") or ""
            file = loc.split(":")[0] if loc else ""
            if not file:
                continue
            label = step.get("function") or step.get("var") or step.get("type") or ""
            if label:
                by_file[file].add(str(label))
        src = (f.taint_source or {}).get("location") or ""
        if src:
            by_file[src.split(":")[0]].add(
                (f.taint_source or {}).get("var")
                or (f.taint_source or {}).get("expression")
                or "source"
            )
        sink = (f.taint_sink or {}).get("location") or ""
        if sink:
            by_file[sink.split(":")[0]].add(
                (f.taint_sink or {}).get("function") or "sink"
            )

    lines = [
        "## Contaminated code map",
        "",
        "Files and symbols that appear on a proven taint path "
        "(sections A and B):",
        "",
    ]
    for file in sorted(by_file):
        symbols = ", ".join(f"`{s}`" for s in sorted(by_file[file])[:12])
        lines.append(f"- `{file}` — {symbols}")
    lines.append("")
    return lines


def _section(
    title: str,
    blurb: str,
    findings: List[ExploitableFinding],
    empty: str,
    compact: bool = False,
) -> List[str]:
    lines = [f"## {title}", "", f"_{blurb}_", ""]
    if not findings:
        lines.extend([empty, ""])
        return lines
    for idx, f in enumerate(findings, 1):
        lines.extend(_render_finding(idx, f, compact=compact))
    return lines


def _render_finding(
    idx: int, f: ExploitableFinding, compact: bool = False
) -> List[str]:
    title = f.title or f.package
    lines = [
        f"### {idx}. {f.cve_id} — {title}",
        "",
        f"| Field | Value |",
        f"|---|---|",
        f"| Status | `{f.status.value}` |",
        f"| Exposure | `{f.exposure.value}` |",
        f"| Risk | `{f.risk_level.value}` · priority `{f.priority}` |",
    ]
    if f.http_endpoint:
        lines.append(f"| HTTP route | `{f.http_endpoint}` |")
    elif f.exposure == ExposureKind.USER_FACING:
        lines.append("| HTTP route | _(unmapped)_ |")
    else:
        lines.append("| HTTP route | — (not required for this finding) |")

    src = f.taint_source or {}
    sink = f.taint_sink or {}
    if src.get("expression"):
        lines.append(
            f"| Contaminated input | `{src.get('expression')}` @ `{src.get('location')}` |"
        )
    lines.append(
        f"| Dangerous sink | `{sink.get('expression')}` @ `{sink.get('location')}` |"
    )
    if f.contaminated_symbols:
        lines.append(
            f"| Contaminated symbols | {', '.join(f'`{s}`' for s in f.contaminated_symbols[:8])} |"
        )
    if f.mitigation_detected:
        lines.append(
            f"| Mitigation | `{f.mitigation_detected}` @ `{f.mitigation_location}` |"
        )
    lines.append("")

    if not compact and f.data_flow_path:
        lines.extend(["**How data moves:**", "", "```"])
        if f.path_description:
            lines.append(f.path_description)
        for step in f.data_flow_path:
            bit = step.get("code") or step.get("type")
            loc = step.get("location", "")
            lines.append(f"  ↓ [{step.get('type')}] {bit} ({loc})")
        lines.extend(["```", ""])
    elif f.path_description:
        lines.extend([f"**Note:** {f.path_description}", ""])

    if f.attack_payload_example:
        lines.extend(
            [
                "**Example attacker input:**",
                "```",
                f.attack_payload_example,
                "```",
                "",
            ]
        )
    if f.remediation:
        lines.extend([f"**Fix:** {f.remediation}", ""])
    for note in f.analysis_notes:
        lines.append(f"- _{note}_")
    if f.analysis_notes:
        lines.append("")
    lines.extend(["---", ""])
    return lines


def _summary_table(findings: List[ExploitableFinding]) -> List[str]:
    lines = [
        "## Index",
        "",
        "| CVE | Package | Exposure | Status | Route / sink | Action |",
        "|---|---|---|---|---|---|",
    ]
    for f in findings:
        sink_loc = (f.taint_sink or {}).get("location") or "—"
        where = f.http_endpoint or sink_loc
        lines.append(
            f"| {f.cve_id} | {f.package} | {f.exposure.value} | {f.status.value} | "
            f"`{where}` | {f.priority} |"
        )
    lines.append("")
    return lines
