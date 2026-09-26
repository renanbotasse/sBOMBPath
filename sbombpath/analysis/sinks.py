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
        found: List[CallFact] = []
        for ff in codebase.files.values():
            for call in ff.calls:
                if any(self._call_matches_entry(call, entry) for entry in self.entries):
                    found.append(call)
        return found

    def _call_matches_entry(self, call: CallFact, entry: Dict[str, Any]) -> bool:
        return any(
            self._function_matches(call.func_name, sink_fn, entry)
            for sink_fn in (entry.get("sink_functions") or [])
        )

    def _function_matches(
        self, call_name: str, sink_fn: str, entry: Dict[str, Any]
    ) -> bool:
        """Match carefully: pickle.loads ≠ json.loads; eval ≠ SimpleEval.eval."""
        call_name = (call_name or "").strip()
        if not call_name:
            return False

        call_parts = call_name.split(".")
        sink_parts = sink_fn.split(".")
        require_bare = bool(entry.get("require_bare_or_builtins"))
        allow_bare = entry.get("allow_bare_name", True)

        # Qualified catalog entry (pickle.loads, os.path.join, jwt.decode, Image.open)
        if len(sink_parts) >= 2:
            if call_name == sink_fn:
                return True
            # Accept alias forms like PIL.Image.open when sink is Image.open
            if call_parts[-len(sink_parts) :] == sink_parts:
                return True
            return False

        # Bare catalog entry (eval, exec, open, filter, exclude, Q, decrypt, ...)
        sink = sink_fn
        if require_bare:
            return call_name in {sink, f"builtins.{sink}"}

        if call_name == sink:
            return True

        # Attribute form: Product.objects.filter / cipher.decrypt
        if allow_bare is False:
            return False
        if call_parts[-1] != sink:
            return False
        # Reject noisy bare-name collisions used as methods
        if sink in {"loads", "load", "eval", "exec", "join"}:
            return False
        return True

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
            if (
                active_filter
                and cve not in active_filter
                and not str(cve).startswith("GENERIC")
            ):
                continue
            if not self._call_matches_entry(call, entry):
                continue
            pattern = self._pattern_for_call(call, entry)
            if pattern is None:
                continue
            safe = set(entry.get("safe_patterns") or [])
            dangerous = set(entry.get("dangerous_patterns") or [])
            if pattern in safe and pattern not in dangerous:
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

    def _pattern_for_call(
        self, call: CallFact, entry: Dict[str, Any]
    ) -> Optional[str]:
        dangerous = set(entry.get("dangerous_patterns") or [])
        safe = set(entry.get("safe_patterns") or [])

        if "starstar_kwargs" in dangerous and call.has_kwargs:
            return "starstar_kwargs"
        if "shell_true" in dangerous and call.shell_true:
            return "shell_true"
        if "named_kwargs" in safe:
            if call.keyword_names and not call.has_kwargs and not call.arg_names:
                return "named_kwargs"
        if "tainted_first_arg" in dangerous:
            return "tainted_first_arg"
        if not dangerous:
            return "tainted_first_arg"
        # Catalog requires a specific pattern that this call site does not use
        return None

    def scan_all(self, codebase: CodebaseFacts) -> List[SinkMatch]:
        out: List[SinkMatch] = []
        for call in self.candidate_calls(codebase):
            out.extend(self.match_call(call))
        return out
