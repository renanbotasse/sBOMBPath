"""Detect mitigations along a taint path."""

from __future__ import annotations

import ast
import re
from typing import List, Optional

from ..collect import CodebaseFacts, FileFacts
from ..models import Mitigation, RiskLevel
from .flow import TracedPath


WHITELIST_PATTERNS = [
    re.compile(r"\bif\s+.+\bin\s+[A-Z_][A-Z0-9_]*"),
    re.compile(r"\{[^}]*\bfor\b[^}]*\bif\b[^}]*\bin\b"),
    re.compile(r"allowed\s*="),
    re.compile(r"ALLOW(?:ED)?_[A-Z0-9_]+"),
]

TYPEGUARD_PATTERNS = [re.compile(r"isinstance\s*\(")]

ENCODING_MARKERS = ("urllib.parse.quote", "html.escape")

RISK_ORDER = [
    RiskLevel.CRITICAL,
    RiskLevel.HIGH,
    RiskLevel.MEDIUM,
    RiskLevel.LOW,
    RiskLevel.UNKNOWN,
]

STRONG_MITIGATIONS = {
    "whitelist_validation",
    "parametrized_named_kwargs",
    "encoding",
}


def _line_from_location(location: str) -> Optional[int]:
    if ":" not in location:
        return None
    _, _, rest = location.partition(":")
    try:
        return int(rest.split(":")[0])
    except ValueError:
        return None


class MitigationDetector:
    def detect(self, path: TracedPath, codebase: CodebaseFacts) -> Optional[Mitigation]:
        involved_files = {
            step.location.partition(":")[0]
            for step in path.steps
            if ":" in step.location
        }
        for rel in involved_files:
            ff = codebase.files.get(rel)
            if not ff:
                continue
            mit = self._scan_file_near_path(ff, path)
            if mit:
                return mit

        sink = path.sink_call
        if sink and not sink.has_kwargs:
            simple = sink.func_name.split(".")[-1]
            if simple in {"filter", "exclude"} and sink.keyword_names:
                return Mitigation(
                    kind="parametrized_named_kwargs",
                    location=f"{sink.file}:{sink.lineno}",
                    detail="ORM call uses named kwargs instead of ** unpacking",
                )
        return None

    def _path_line_numbers(self, ff: FileFacts, path: TracedPath) -> List[int]:
        line_nos: List[int] = []
        prefix = ff.path + ":"
        for step in path.steps:
            if not step.location.startswith(prefix):
                continue
            lineno = _line_from_location(step.location)
            if lineno is not None:
                line_nos.append(lineno)
        return line_nos

    def _scan_file_near_path(self, ff: FileFacts, path: TracedPath) -> Optional[Mitigation]:
        line_nos = self._path_line_numbers(ff, path)
        if not line_nos:
            return None
        lo = max(1, min(line_nos) - 5)
        hi = min(len(ff.lines), max(line_nos) + 15)
        window = "\n".join(ff.lines[lo - 1 : hi])

        for pat in WHITELIST_PATTERNS:
            if pat.search(window):
                return Mitigation(
                    kind="whitelist_validation",
                    location=f"{ff.path}:{lo}",
                    detail="Whitelist / allow-list validation near taint path",
                )
        for pat in TYPEGUARD_PATTERNS:
            if pat.search(window):
                return Mitigation(
                    kind="type_check",
                    location=f"{ff.path}:{lo}",
                    detail="isinstance type check near path (weak mitigation)",
                )
        if any(marker in window for marker in ENCODING_MARKERS):
            return Mitigation(
                kind="encoding",
                location=f"{ff.path}:{lo}",
                detail="Encoding/escaping helper applied near path",
            )

        for node in ast.walk(ff.tree):
            if isinstance(node, ast.DictComp) and lo <= getattr(node, "lineno", 0) <= hi:
                return Mitigation(
                    kind="whitelist_validation",
                    location=f"{ff.path}:{node.lineno}",
                    detail="Dict comprehension filtering keys",
                )
        return None

    @staticmethod
    def adjust_risk(base: str, mitigation: Optional[Mitigation]) -> RiskLevel:
        try:
            current = RiskLevel(base)
        except ValueError:
            current = RiskLevel.HIGH
        if mitigation is None:
            return current
        drop = 2 if mitigation.kind in STRONG_MITIGATIONS else 1
        idx = RISK_ORDER.index(current)
        new_idx = min(len(RISK_ORDER) - 2, idx + drop)
        return RISK_ORDER[new_idx]
