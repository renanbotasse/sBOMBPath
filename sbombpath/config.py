"""Configuration loaders (JSON catalogs)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional


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
        normalized.append(
            {
                "id": str(cve_id),
                "package": item.get("package") or item.get("component") or "",
                "symbol": item.get("symbol") or item.get("sink") or "",
                "severity": item.get("severity") or item.get("cvss_severity") or "",
                "raw": item,
            }
        )
    return normalized
