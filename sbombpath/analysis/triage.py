"""Compare SBOM/SCA CVE list vs sBOMBPath path relevance."""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Set

from ..models import ExposureKind, ExploitableFinding


def _identity_keys(cve: Dict[str, Any]) -> Set[str]:
    keys: Set[str] = set()
    cid = str(cve.get("id") or "")
    if cid:
        keys.add(cid)
    for alias in cve.get("aliases") or []:
        if alias:
            keys.add(str(alias))
    # Prefer canonical CVE-* when present
    for key in list(keys):
        if key.startswith("CVE-"):
            keys.add(key)
    return keys


def _primary_cve_id(cve: Dict[str, Any]) -> str:
    for alias in cve.get("aliases") or []:
        if str(alias).startswith("CVE-"):
            return str(alias)
    return str(cve.get("id") or "UNKNOWN")


def _catalog_cves_for_package(
    symbols_catalog: Dict[str, Any], package: str
) -> Set[str]:
    pkg = (package or "").lower()
    out: Set[str] = set()
    for entry in symbols_catalog.get("sinks") or []:
        entry_pkg = str(entry.get("package") or "").lower()
        if entry_pkg and (entry_pkg == pkg or entry_pkg in pkg or pkg in entry_pkg):
            cve = entry.get("cve")
            if cve and not str(cve).startswith("GENERIC"):
                out.add(str(cve))
    return out


def _catalog_exact_cve(
    symbols_catalog: Dict[str, Any], identities: Set[str]
) -> Optional[Dict[str, Any]]:
    for entry in symbols_catalog.get("sinks") or []:
        cve = str(entry.get("cve") or "")
        if cve in identities:
            return entry
    return None


def build_cve_comparison(
    cve_report: List[Dict[str, Any]],
    findings: List[ExploitableFinding],
    symbols_catalog: Dict[str, Any],
) -> Dict[str, Any]:
    """Explain which SBOM CVEs matter to path analysis and which do not."""

    # Index path findings by CVE id
    by_cve: Dict[str, List[ExploitableFinding]] = {}
    for finding in findings:
        by_cve.setdefault(finding.cve_id, []).append(finding)

    relevant: List[Dict[str, Any]] = []
    not_relevant: List[Dict[str, Any]] = []

    for cve in cve_report:
        identities = _identity_keys(cve)
        primary = _primary_cve_id(cve)
        package = str(cve.get("package") or "")
        severity = str(cve.get("severity") or "")
        summary = str(cve.get("summary") or "")

        matched_findings: List[ExploitableFinding] = []
        for key in identities:
            matched_findings.extend(by_cve.get(key, []))
        # de-dupe by (exposure, sink location)
        seen = set()
        unique: List[ExploitableFinding] = []
        for f in matched_findings:
            k = (f.exposure.value, f.taint_sink.get("location"), f.status.value)
            if k not in seen:
                seen.add(k)
                unique.append(f)

        catalog_entry = _catalog_exact_cve(symbols_catalog, identities)
        package_catalog_cves = _catalog_cves_for_package(symbols_catalog, package)

        row: Dict[str, Any] = {
            "id": primary,
            "sbom_id": cve.get("id"),
            "package": package,
            "severity": severity,
            "summary": summary[:220],
            "path_findings": len(unique),
        }

        if unique:
            exposures = {f.exposure for f in unique}
            statuses = {f.status.value for f in unique}
            sinks = sorted(
                {
                    str((f.taint_sink or {}).get("location") or "")
                    for f in unique
                    if (f.taint_sink or {}).get("location")
                }
            )[:6]
            if ExposureKind.USER_FACING in exposures:
                why = (
                    "User-controlled data reaches a dangerous API mapped to this CVE "
                    f"({len(unique)} path(s))."
                )
                verdict = "RELEVANT_USER_FACING"
            elif ExposureKind.INTERNAL_TAINT in exposures:
                why = (
                    "Contaminated internal data flow reaches a dangerous API for this "
                    "CVE, without a clear public HTTP route."
                )
                verdict = "RELEVANT_INTERNAL"
            else:
                why = (
                    "Vulnerable package API is used in source (package surface). "
                    "No proven user→sink path, but the call site remains an attack "
                    "surface if the dependency is abused or data arrives via another channel."
                )
                verdict = "RELEVANT_PACKAGE_SURFACE"
            row.update(
                {
                    "verdict": verdict,
                    "relevant": True,
                    "why": why,
                    "statuses": sorted(statuses),
                    "sink_locations": sinks,
                    "exposures": sorted(e.value for e in exposures),
                }
            )
            relevant.append(row)
            continue

        # No path findings — explain why sBOMBPath does not flag it
        if catalog_entry:
            why = (
                "sBOMBPath has a sink rule for this CVE "
                f"(`{catalog_entry.get('title') or catalog_entry.get('cve')}`), "
                "but the dangerous call pattern was not found in the analyzed code "
                "(or no taint path reached it)."
            )
            reason_code = "RULE_NO_MATCH_IN_CODE"
        elif package_catalog_cves:
            why = (
                f"Package `{package}` is in the SBOM and sBOMBPath models some of its "
                f"CVEs ({', '.join(sorted(package_catalog_cves)[:3])}"
                f"{'…' if len(package_catalog_cves) > 3 else ''}), but **this** CVE has "
                "no specific taint/sink rule. Typical for DoS, cache, logging, or "
                "validator issues that are not user-data→API paths."
            )
            reason_code = "PACKAGE_KNOWN_CVE_NOT_MODELED"
        else:
            why = (
                "No sBOMBPath sink catalog entry for this CVE/package. "
                "It is a dependency finding only — fix by upgrading/patching; "
                "path analysis cannot prove or disprove exploitability here."
            )
            reason_code = "NO_PATH_RULE"

        row.update(
            {
                "verdict": "NOT_RELEVANT",
                "relevant": False,
                "why": why,
                "reason_code": reason_code,
                "statuses": [],
                "sink_locations": [],
                "exposures": [],
            }
        )
        not_relevant.append(row)

    # Stable sort: severity-ish then id
    sev_rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}

    def sort_key(row: Dict[str, Any]) -> tuple:
        return (sev_rank.get(str(row.get("severity") or "").upper(), 5), row.get("id") or "")

    relevant.sort(key=sort_key)
    not_relevant.sort(key=sort_key)

    return {
        "sbom_cves_total": len(cve_report),
        "relevant_count": len(relevant),
        "not_relevant_count": len(not_relevant),
        "relevant": relevant,
        "not_relevant": not_relevant,
    }
