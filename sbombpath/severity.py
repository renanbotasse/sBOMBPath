"""Severity normalization for SBOM / SCA CVE inputs."""

from __future__ import annotations

import re
from typing import Any, Dict, Optional


_SEVERITY_ALIASES = {
    "CRITICAL": "CRITICAL",
    "HIGH": "HIGH",
    "MEDIUM": "MEDIUM",
    "MODERATE": "MEDIUM",
    "LOW": "LOW",
    "INFO": "LOW",
    "INFORMATIONAL": "LOW",
}

_CVSS_VECTOR_RE = re.compile(
    r"CVSS:3\.[01]/AV:[NALP]/AC:[LH]/PR:[NLH]/UI:[NR]/S:[UC]/"
    r"C:([NHLP])/I:([NHLP])/A:([NHLP])",
    re.IGNORECASE,
)

# Rough CVSS v3 base-score estimate from CIA triad letters (N=0,L=low,H=high).
_CIA = {"N": 0.0, "L": 0.22, "H": 0.56, "P": 0.22}


def severity_from_cvss(cvss: Any) -> str:
    try:
        score = float(cvss)
    except (TypeError, ValueError):
        return ""
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score > 0:
        return "LOW"
    return ""


def _parse_label(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, list):
        best = ""
        order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
        for item in value:
            label = _parse_label(item)
            if order.get(label, 0) > order.get(best, 0):
                best = label
        return best
    if isinstance(value, dict):
        for key in ("severity", "baseSeverity", "cvss_severity", "score"):
            if key in value:
                label = _parse_label(value.get(key))
                if label:
                    return label
        return ""
    text = str(value).strip().upper()
    if text in _SEVERITY_ALIASES:
        return _SEVERITY_ALIASES[text]
    # Ignore CVSS vector strings here — handled separately.
    if text.startswith("CVSS:"):
        return ""
    return ""


def _score_from_vector(text: str) -> Optional[float]:
    match = _CVSS_VECTOR_RE.search(text or "")
    if not match:
        return None
    # Very rough impact proxy so UNKNOWN+vector still gets a band.
    c, i, a = match.group(1).upper(), match.group(2).upper(), match.group(3).upper()
    impact = 1 - ((1 - _CIA.get(c, 0)) * (1 - _CIA.get(i, 0)) * (1 - _CIA.get(a, 0)))
    # Map impact 0..~0.9 → score-ish 0..10 (enough for banding).
    return round(impact * 10.5, 1)


def extract_cvss_score(item: Dict[str, Any]) -> Optional[float]:
    for key in ("cvss", "cvss_score", "baseScore", "score"):
        val = item.get(key)
        if val is None:
            continue
        try:
            return float(val)
        except (TypeError, ValueError):
            pass

    raw_sev = item.get("severity")
    candidates = raw_sev if isinstance(raw_sev, list) else [raw_sev]
    for entry in candidates:
        if isinstance(entry, dict):
            for key in ("score", "baseScore"):
                val = entry.get(key)
                if val is None:
                    continue
                try:
                    return float(val)
                except (TypeError, ValueError):
                    if isinstance(val, str) and val.upper().startswith("CVSS:"):
                        scored = _score_from_vector(val)
                        if scored is not None:
                            return scored
        elif isinstance(entry, str) and entry.upper().startswith("CVSS:"):
            scored = _score_from_vector(entry)
            if scored is not None:
                return scored
    return None


def normalize_severity(item: Dict[str, Any]) -> str:
    """Prefer explicit severity; else derive from CVSS / vector (sBOMBox-compatible)."""
    label = _parse_label(
        item.get("severity")
        or item.get("cvss_severity")
        or item.get("cvssSeverity")
        or item.get("baseSeverity")
    )
    if label:
        return label
    score = extract_cvss_score(item)
    if score is not None:
        derived = severity_from_cvss(score)
        if derived:
            return derived
    return "UNKNOWN"
