"""Detect vulnerable sink call sites from catalog."""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Set

from ..collect import CallFact, CodebaseFacts
from ..models import SinkMatch


class SinkDetector:
    def __init__(
        self,
        symbols_catalog: Dict[str, Any],
        cve_filter: Optional[Set[str]] = None,
    ) -> None:
        self.entries = list(symbols_catalog.get("sinks", []))
        self.cve_filter = cve_filter

    def candidate_calls(self, codebase: CodebaseFacts) -> List[CallFact]:
        names = self._all_sink_names()
        found: List[CallFact] = []
        for ff in codebase.files.values():
            for call in ff.calls:
                simple = call.func_name.split(".")[-1]
                if call.func_name in names or simple in names:
                    found.append(call)
        return found

    def _collect_names(self, entries: List[Dict[str, Any]]) -> Set[str]:
        names: Set[str] = set()
        for entry in entries:
            for fn in entry.get("sink_functions", []):
                names.add(fn)
                names.add(fn.split(".")[-1])
        return names

    def _all_sink_names(self) -> Set[str]:
        if self.cve_filter:
            filtered = [
                entry
                for entry in self.entries
                if entry.get("cve") in self.cve_filter
                or str(entry.get("cve", "")).startswith("GENERIC")
            ]
            names = self._collect_names(filtered)
            if names:
                return names
        return self._collect_names(self.entries)

    def match_call(
        self,
        call: CallFact,
        cve_filter: Optional[Set[str]] = None,
    ) -> List[SinkMatch]:
        matches: List[SinkMatch] = []
        simple = call.func_name.split(".")[-1]
        active_filter = cve_filter if cve_filter is not None else self.cve_filter

        for entry in self.entries:
            cve = entry.get("cve", "")
            if active_filter and cve not in active_filter and not cve.startswith("GENERIC"):
                continue
            sink_fns = entry.get("sink_functions") or []
            sink_simples = {s.split(".")[-1] for s in sink_fns}
            if call.func_name not in sink_fns and simple not in sink_simples:
                continue
            pattern = self._pattern_for_call(call, entry)
            if pattern is None:
                continue
            safe = set(entry.get("safe_patterns") or [])
            dangerous = set(entry.get("dangerous_patterns") or [])
            if pattern in safe and pattern not in dangerous:
                continue
            if (
                dangerous
                and pattern not in dangerous
                and pattern != "tainted_first_arg"
            ):
                continue
            matches.append(
                SinkMatch(
                    cve=cve,
                    package=entry.get("package", ""),
                    sink=simple,
                    location=f"{call.file}:{call.lineno}",
                    expression=call.full_expr,
                    pattern_matched=pattern,
                    severity=entry.get("severity", "HIGH"),
                    title=entry.get("title", ""),
                    remediation=entry.get("remediation", ""),
                )
            )
        return matches

    def _pattern_for_call(self, call: CallFact, entry: Dict[str, Any]) -> Optional[str]:
        dangerous = set(entry.get("dangerous_patterns") or [])
        if "starstar_kwargs" in dangerous and call.has_kwargs:
            return "starstar_kwargs"
        if "shell_true" in dangerous and call.shell_true:
            return "shell_true"
        if "named_kwargs" in (entry.get("safe_patterns") or []):
            if call.keyword_names and not call.has_kwargs and not call.arg_names:
                return "named_kwargs"
        if "tainted_first_arg" in dangerous or not dangerous:
            return "tainted_first_arg"
        if call.has_kwargs:
            return "starstar_kwargs"
        return "tainted_first_arg"

    def scan_all(self, codebase: CodebaseFacts) -> List[SinkMatch]:
        out: List[SinkMatch] = []
        for call in self.candidate_calls(codebase):
            out.extend(self.match_call(call))
        return out
