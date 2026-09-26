"""Match taint paths to CVE sinks and build findings."""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Set, Tuple

from ..collect import CodebaseFacts
from ..models import ExploitableFinding, FindingStatus, RiskLevel, SinkMatch, TaintSource
from .flow import DataFlowAnalyzer, TracedPath
from .mitigation import MitigationDetector
from .reachability import ReachabilityAnalyzer
from .sinks import SinkDetector


STRONG_MITIGATION_KINDS = {
    "whitelist_validation",
    "parametrized_named_kwargs",
    "encoding",
}


def _payload_for(source_type: str, endpoint: Optional[str]) -> str:
    ep = endpoint or "GET /api/…"
    source = source_type or ""
    if "GET" in source or "query" in source:
        method = ep.split()[0] if ep else "GET"
        path = ep.split(" ", 1)[-1] if ep and " " in ep else "/api/search"
        return f'{method} {path}?search={{"__ne": 1}}'
    if "data" in source or "POST" in source:
        return 'POST body: {"token": "<malicious>", "search": {"__ne": 1}}'
    return f"Craft user-controlled input via {source_type}"


class VulnerabilityMapper:
    def __init__(
        self,
        symbols_catalog: Dict[str, Any],
        cve_report: List[Dict[str, Any]],
    ) -> None:
        self.symbols = symbols_catalog
        reported = {c["id"] for c in cve_report} if cve_report else None
        self.cve_ids: Optional[Set[str]] = reported
        self.sink_detector = SinkDetector(symbols_catalog, cve_filter=reported)
        self.mitigation_detector = MitigationDetector()

    def find_exploitable(
        self,
        sources: List[TaintSource],
        flow: DataFlowAnalyzer,
        codebase: CodebaseFacts,
        reachability: ReachabilityAnalyzer,
    ) -> List[ExploitableFinding]:
        sink_calls = self.sink_detector.candidate_calls(codebase)
        findings: List[ExploitableFinding] = []

        for source in sources:
            for path in flow.track(source, sink_calls):
                if not path.sink_call:
                    continue
                for sm in self._sink_matches(path):
                    findings.append(
                        self._to_finding(source, path, sm, codebase, reachability)
                    )

        uniq: Dict[Tuple[Any, Any, Any], ExploitableFinding] = {}
        for finding in findings:
            key = (
                finding.cve_id,
                finding.taint_sink.get("location"),
                finding.taint_source.get("location"),
            )
            if key not in uniq:
                uniq[key] = finding
        return list(uniq.values())

    def _sink_matches(self, path: TracedPath) -> List[SinkMatch]:
        assert path.sink_call is not None
        matches = self.sink_detector.match_call(path.sink_call, cve_filter=self.cve_ids)
        if matches:
            return matches
        matches = self.sink_detector.match_call(path.sink_call, cve_filter=None)
        if self.cve_ids:
            matches = [
                m for m in matches if m.cve in self.cve_ids or m.cve.startswith("GENERIC")
            ]
        return matches

    def _to_finding(
        self,
        source: TaintSource,
        path: TracedPath,
        sm: SinkMatch,
        codebase: CodebaseFacts,
        reachability: ReachabilityAnalyzer,
    ) -> ExploitableFinding:
        mitigation = self.mitigation_detector.detect(path, codebase)
        risk = self.mitigation_detector.adjust_risk(sm.severity, mitigation)
        endpoint, reachable, path_desc = reachability.describe(
            source.function, source.class_name
        )

        if mitigation and mitigation.kind in STRONG_MITIGATION_KINDS:
            status = FindingStatus.MITIGATED
        elif path.incomplete and not (reachable or endpoint):
            status = FindingStatus.UNKNOWN
        else:
            status = FindingStatus.EXPLOITABLE

        notes: List[str] = []
        if path.incomplete:
            notes.append("Taint BFS hit max depth; analysis may be incomplete.")
        if not reachable:
            notes.append("HTTP route mapping incomplete or missing for this view.")
        if mitigation and mitigation.kind == "type_check":
            notes.append("Only weak type-check mitigation detected.")

        if status == FindingStatus.MITIGATED:
            priority = "MONITOR"
        elif risk in {RiskLevel.MEDIUM, RiskLevel.LOW}:
            priority = "REVIEW"
        elif status == FindingStatus.UNKNOWN:
            priority = "MANUAL_REVIEW"
        else:
            priority = "IMMEDIATE"

        flow_steps = [s.to_dict() for s in path.steps]
        chain = " → ".join(
            s.get("function") or s.get("var") or s.get("type", "") for s in flow_steps
        )
        if endpoint:
            path_desc = f"{endpoint} → {chain}"

        return ExploitableFinding(
            cve_id=sm.cve,
            package=sm.package,
            severity=sm.severity,
            status=status,
            risk_level=risk,
            http_endpoint=endpoint,
            reachable=reachable,
            taint_source={
                "location": source.location,
                "expression": source.expression,
                "source_type": source.source_type,
                "var": source.var,
            },
            taint_sink={
                "location": sm.location,
                "function": sm.sink,
                "expression": sm.expression,
                "pattern_matched": sm.pattern_matched,
            },
            data_flow_path=flow_steps,
            mitigation_detected=mitigation.kind if mitigation else None,
            mitigation_location=mitigation.location if mitigation else None,
            attack_payload_example=_payload_for(source.source_type, endpoint),
            remediation=sm.remediation,
            priority=priority,
            path_description=path_desc,
            analysis_notes=notes,
        )
