"""Orchestrates all sBOMBPath analysis stages."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, Optional

from .analysis import (
    DataFlowAnalyzer,
    ReachabilityAnalyzer,
    SinkDetector,
    SourceDetector,
    VulnerabilityMapper,
)
from .analysis.triage import build_cve_comparison
from .collect import collect_codebase
from .config import load_cve_report, load_sources_catalog, load_symbols_catalog
from .report import ReportGenerator


class PathRecognitionEngine:
    def __init__(
        self,
        code_dir: Path,
        cves_path: Optional[Path] = None,
        symbols_path: Optional[Path] = None,
        sources_path: Optional[Path] = None,
        output_dir: Optional[Path] = None,
        max_depth: int = 25,
    ) -> None:
        self.code_dir = code_dir
        self.cves_path = cves_path
        self.symbols_path = symbols_path
        self.sources_path = sources_path
        self.output_dir = output_dir or Path("path-recognition-report")
        self.max_depth = max_depth

    def run(self) -> Dict[str, Any]:
        sources_catalog = load_sources_catalog(self.sources_path)
        symbols_catalog = load_symbols_catalog(self.symbols_path)
        cve_report = load_cve_report(self.cves_path)

        codebase = collect_codebase(self.code_dir)
        taint_sources = SourceDetector(sources_catalog).detect(codebase)

        flow = DataFlowAnalyzer(codebase, max_depth=self.max_depth)
        reachability = ReachabilityAnalyzer(codebase)
        findings = VulnerabilityMapper(symbols_catalog, cve_report).find_exploitable(
            taint_sources, flow, codebase, reachability
        )

        comparison = build_cve_comparison(cve_report, findings, symbols_catalog)

        if cve_report:
            cves_analyzed = len(cve_report)
        else:
            cves_analyzed = len({e.get("cve") for e in symbols_catalog.get("sinks", [])})

        debug = {
            "taint-sources": [s.to_dict() for s in taint_sources],
            "flow-graph": flow.graph_as_dict(),
            "sinks": [s.to_dict() for s in SinkDetector(symbols_catalog).scan_all(codebase)],
            "paths-traced": [f.to_dict() for f in findings],
            "parse-errors": codebase.parse_errors,
            "endpoints": [e.to_dict() for e in reachability.endpoints],
            "cve-comparison": comparison,
        }

        meta = ReportGenerator(self.output_dir).write(
            findings, cves_analyzed, debug, comparison=comparison
        )
        return {
            "meta": meta,
            "findings": findings,
            "comparison": comparison,
            "parse_errors": codebase.parse_errors,
        }
