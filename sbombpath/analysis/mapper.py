"""Match taint paths to CVE sinks and build findings."""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Set, Tuple

from ..collect import CodebaseFacts
from ..models import (
    ExposureKind,
    ExploitableFinding,
    FindingStatus,
    RiskLevel,
    SinkMatch,
    TaintSource,
)
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


def _contaminated_symbols(path: TracedPath, source: TaintSource) -> List[str]:
    symbols: List[str] = []
    if source.function:
        symbols.append(source.function)
    for step in path.steps:
        fn = step.function
        if fn and fn not in symbols:
            symbols.append(fn)
        var = step.var
        if var and var not in symbols:
            symbols.append(var)
    return symbols


class VulnerabilityMapper:
    def __init__(
        self,
        symbols_catalog: Dict[str, Any],
        cve_report: List[Dict[str, Any]],
    ) -> None:
        self.symbols = symbols_catalog
        self.cve_report = cve_report or []
        reported: Optional[Set[str]] = None
        self._severity_by_id: Dict[str, str] = {}
        if cve_report:
            reported = set()
            for c in cve_report:
                reported.add(c["id"])
                sev = str(c.get("severity") or "")
                if sev:
                    self._severity_by_id[c["id"]] = sev
                for alias in c.get("aliases") or []:
                    if alias:
                        reported.add(str(alias))
                        if sev:
                            self._severity_by_id[str(alias)] = sev
        self.cve_ids = reported
        self.sink_detector = SinkDetector(symbols_catalog, cve_filter=reported)
        self.mitigation_detector = MitigationDetector()

    def _sbom_severity(self, cve_id: str, fallback: str) -> str:
        """Prefer sBOMBox severity when present and not UNKNOWN."""
        sev = self._severity_by_id.get(cve_id) or ""
        if sev and sev.upper() not in {"UNKNOWN", "NONE", ""}:
            return sev.upper()
        return fallback

    def find_exploitable(
        self,
        sources: List[TaintSource],
        flow: DataFlowAnalyzer,
        codebase: CodebaseFacts,
        reachability: ReachabilityAnalyzer,
    ) -> List[ExploitableFinding]:
        sink_calls = self.sink_detector.candidate_calls(codebase)
        findings: List[ExploitableFinding] = []
        covered_sinks: Set[Tuple[str, str]] = set()

        for source in sources:
            for path in flow.track(source, sink_calls):
                if not path.sink_call:
                    continue
                for sm in self._sink_matches(path):
                    finding = self._to_finding(
                        source, path, sm, codebase, reachability
                    )
                    findings.append(finding)
                    covered_sinks.add(
                        (sm.cve, sm.location)
                    )

        # Package / API surface: call sites for CVEs listed by SBOM/SCA, even
        # when we could not prove user→sink taint. Skip GENERIC here to avoid
        # flooding with every open()/filter() in the tree — those still appear
        # in A/B when a real taint path exists.
        # Collapse to one finding per CVE (list extra locations in notes).
        package_hits: Dict[str, List[SinkMatch]] = {}
        if self.cve_ids:
            for call in sink_calls:
                for sm in self.sink_detector.match_call(
                    call, cve_filter=self.cve_ids
                ):
                    if sm.cve.startswith("GENERIC"):
                        continue
                    if sm.cve not in self.cve_ids:
                        continue
                    key = (sm.cve, sm.location)
                    if key in covered_sinks:
                        continue
                    package_hits.setdefault(sm.cve, []).append(sm)

        for cve, matches in package_hits.items():
            primary = matches[0]
            finding = self._package_surface_finding(primary)
            if len(matches) > 1:
                extra = [m.location for m in matches[1:6]]
                more = len(matches) - 1
                finding.analysis_notes.append(
                    f"{more} additional call site(s), e.g. {', '.join(extra)}"
                    + ("…" if more > 5 else "")
                )
                finding.path_description = (
                    f"Dangerous API used in {len(matches)} place(s); "
                    f"primary `{primary.expression}` at {primary.location}."
                )
            findings.append(finding)
            for m in matches:
                covered_sinks.add((m.cve, m.location))


        uniq: Dict[Tuple[Any, Any, Any, Any], ExploitableFinding] = {}
        for finding in findings:
            key = (
                finding.cve_id,
                finding.exposure.value,
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
            return self._filter_path_matches(matches)
        matches = self.sink_detector.match_call(path.sink_call, cve_filter=None)
        if self.cve_ids:
            matches = [
                m
                for m in matches
                if m.cve in self.cve_ids or m.cve.startswith("GENERIC")
            ]
        return self._filter_path_matches(matches)

    def _filter_path_matches(self, matches: List[SinkMatch]) -> List[SinkMatch]:
        """Drop catalog entries marked package_surface_only from taint paths."""
        only_surface = {
            str(e.get("cve"))
            for e in self.symbols.get("sinks") or []
            if e.get("package_surface_only")
        }
        return [m for m in matches if m.cve not in only_surface]

    def _to_finding(
        self,
        source: TaintSource,
        path: TracedPath,
        sm: SinkMatch,
        codebase: CodebaseFacts,
        reachability: ReachabilityAnalyzer,
    ) -> ExploitableFinding:
        mitigation = self.mitigation_detector.detect(path, codebase)
        severity = self._sbom_severity(sm.cve, sm.severity)
        risk = self.mitigation_detector.adjust_risk(severity, mitigation)
        endpoint, reachable, path_desc = reachability.describe(
            source.function, source.class_name
        )

        if mitigation and mitigation.kind in STRONG_MITIGATION_KINDS:
            status = FindingStatus.MITIGATED
        elif path.incomplete and not (reachable or endpoint):
            status = FindingStatus.UNKNOWN
        else:
            status = FindingStatus.EXPLOITABLE

        if status == FindingStatus.MITIGATED:
            exposure = (
                ExposureKind.USER_FACING
                if (reachable or endpoint)
                else ExposureKind.INTERNAL_TAINT
            )
        elif reachable or endpoint:
            exposure = ExposureKind.USER_FACING
        else:
            exposure = ExposureKind.INTERNAL_TAINT

        notes: List[str] = []
        if path.incomplete:
            notes.append("Taint BFS hit max depth; analysis may be incomplete.")
        if exposure == ExposureKind.INTERNAL_TAINT:
            notes.append(
                "No clear public HTTP route mapped — still contaminated code "
                "(internal caller, job, webhook, or unmapped view)."
            )
        elif not reachable:
            notes.append("HTTP route mapping incomplete or missing for this view.")
        if mitigation and mitigation.kind == "type_check":
            notes.append("Only weak type-check mitigation detected.")

        if status == FindingStatus.MITIGATED:
            priority = "MONITOR"
        elif risk in {RiskLevel.MEDIUM, RiskLevel.LOW}:
            priority = "REVIEW"
        elif status == FindingStatus.UNKNOWN:
            priority = "MANUAL_REVIEW"
        elif exposure == ExposureKind.USER_FACING:
            priority = "IMMEDIATE"
        else:
            priority = "REVIEW"

        flow_steps = [s.to_dict() for s in path.steps]
        chain = " → ".join(
            s.get("function") or s.get("var") or s.get("type", "") for s in flow_steps
        )
        if endpoint:
            path_desc = f"{endpoint} → {chain}"
        elif not path_desc:
            path_desc = chain

        return ExploitableFinding(
            cve_id=sm.cve,
            package=sm.package,
            severity=severity,
            status=status,
            risk_level=risk,
            exposure=exposure,
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
            attack_payload_example=(
                _payload_for(source.source_type, endpoint)
                if exposure == ExposureKind.USER_FACING
                else None
            ),
            remediation=sm.remediation,
            priority=priority,
            path_description=path_desc,
            title=sm.title,
            contaminated_symbols=_contaminated_symbols(path, source),
            analysis_notes=notes,
        )

    def _package_surface_finding(self, sm: SinkMatch) -> ExploitableFinding:
        severity = self._sbom_severity(sm.cve, sm.severity)
        try:
            risk = RiskLevel(severity)
        except ValueError:
            risk = RiskLevel.MEDIUM
        return ExploitableFinding(
            cve_id=sm.cve,
            package=sm.package,
            severity=severity,
            status=FindingStatus.AT_RISK,
            risk_level=risk,
            exposure=ExposureKind.PACKAGE_SURFACE,
            http_endpoint=None,
            reachable=False,
            taint_source={},
            taint_sink={
                "location": sm.location,
                "function": sm.sink,
                "expression": sm.expression,
                "pattern_matched": sm.pattern_matched,
            },
            data_flow_path=[],
            mitigation_detected=None,
            mitigation_location=None,
            attack_payload_example=None,
            remediation=sm.remediation,
            priority="REVIEW",
            path_description=(
                f"Dangerous API `{sm.expression}` used in codebase "
                f"(no proven user-input path)."
            ),
            title=sm.title,
            contaminated_symbols=[],
            analysis_notes=[
                "Package/API surface: this call site matters if the dependency "
                "is vulnerable or if untrusted data reaches it via a path we "
                "did not fully trace (e.g. internal service, queue, admin tool)."
            ],
        )
