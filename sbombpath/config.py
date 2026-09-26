"""Configuration loaders (JSON catalogs)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from .severity import extract_cvss_score, normalize_severity


def load_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def default_rules_dir() -> Path:
    return Path(__file__).resolve().parent.parent / "rules"


def _rules_json(name: str, path: Optional[Path] = None) -> Dict[str, Any]:
    return load_json(path or (default_rules_dir() / name))


def load_sources_catalog(path: Optional[Path] = None) -> Dict[str, Any]:
    return _rules_json("sources.json", path)


def load_symbols_catalog(path: Optional[Path] = None) -> Dict[str, Any]:
    return _rules_json("symbols.json", path)


_CVE_LIST_KEYS = ("vulnerabilities", "cves", "findings", "results")
_CVE_ID_KEYS = ("id", "cve", "cve_id", "vulnerability_id")


def load_cve_report(path: Optional[Path]) -> List[Dict[str, Any]]:
    """Normalize an external CVE list JSON into internal CVE dicts.

    Accepts common shapes from other tools (flat list or wrapped under
    vulnerabilities/cves/findings/results). This project does not depend on
    any SBOM package — only on a portable JSON file when --cves is passed.

    Severity follows sBOMBox semantics: explicit label when present, otherwise
    derive from CVSS / CVSS vector. ``UNKNOWN`` is only kept when no score exists.
    """
    if path is None or not path.exists():
        return []
    raw = load_json(path)
    if isinstance(raw, dict):
        for key in _CVE_LIST_KEYS:
            if key in raw and isinstance(raw[key], list):
                raw = raw[key]
                break
        else:
            return []
    if not isinstance(raw, list):
        return []

    normalized: List[Dict[str, Any]] = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        cve_id = next((item.get(k) for k in _CVE_ID_KEYS if item.get(k)), None)
        if not cve_id:
            continue
        cvss = extract_cvss_score(item)
        normalized.append(
            {
                "id": str(cve_id),
                "package": item.get("package") or item.get("component") or "",
                "symbol": item.get("symbol") or item.get("sink") or "",
                "severity": normalize_severity(item),
                "cvss": cvss,
                "nvd_status": item.get("nvd_status") or item.get("vulnStatus") or "",
                "summary": item.get("summary")
                or item.get("title")
                or item.get("description")
                or "",
                "aliases": list(item.get("aliases") or []),
                "version": item.get("version") or "",
                "raw": item,
            }
        )
    return normalized
