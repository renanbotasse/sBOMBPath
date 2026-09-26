"""Smoke tests for sBOMBPath."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from sbombpath.analysis.sources import SourceDetector
from sbombpath.collect import collect_codebase
from sbombpath.config import load_cve_report, load_sources_catalog, load_symbols_catalog
from sbombpath.engine import PathRecognitionEngine
from sbombpath.models import FindingStatus


ROOT = Path(__file__).resolve().parent.parent
FIXTURES = ROOT / "fixtures"
BACKEND = FIXTURES / "sample_backend"
VULNS = FIXTURES / "sample_vuln_report.json"


class SourceDetectionTests(unittest.TestCase):
    def test_detects_request_get_sources(self):
        codebase = collect_codebase(BACKEND)
        catalog = load_sources_catalog()
        sources = SourceDetector(catalog).detect(codebase)
        types = {s.source_type for s in sources}
        self.assertIn("request.GET", types)
        self.assertTrue(any(s.var in {"term", "search_query", "filters"} or "GET" in s.expression for s in sources))


class EngineIntegrationTests(unittest.TestCase):
    def test_end_to_end_finds_exploitable_paths(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "report"
            engine = PathRecognitionEngine(
                code_dir=BACKEND,
                cves_path=VULNS,
                output_dir=out,
            )
            result = engine.run()
            findings = result["findings"]
            self.assertTrue(out.joinpath("exploitable-paths.md").exists())
            self.assertTrue(out.joinpath("exploitable-paths.json").exists())
            self.assertTrue(out.joinpath("exploitable-paths.csv").exists())
            self.assertTrue(out.joinpath("debug", "taint-sources.json").exists())

            cves = {f.cve_id for f in findings}
            self.assertIn("CVE-2025-64459", cves)
            self.assertIn("CVE-2026-32597", cves)

            exploitable = [f for f in findings if f.status == FindingStatus.EXPLOITABLE]
            self.assertGreaterEqual(len(exploitable), 1)

            django_hits = [
                f
                for f in findings
                if f.cve_id == "CVE-2025-64459"
                and "filter" in (f.taint_sink.get("expression") or "")
            ]
            self.assertGreaterEqual(len(django_hits), 1)

            payload = json.loads((out / "exploitable-paths.json").read_text(encoding="utf-8"))
            self.assertIn("report_meta", payload)
            self.assertIn("exploitable_paths", payload)

    def test_mitigated_path_detected(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "report"
            result = PathRecognitionEngine(
                code_dir=BACKEND,
                cves_path=VULNS,
                output_dir=out,
            ).run()
            mitigated = [
                f
                for f in result["findings"]
                if f.status == FindingStatus.MITIGATED
                or f.mitigation_detected == "whitelist_validation"
            ]
            self.assertTrue(
                mitigated
                or any(
                    "ALLOWED" in str(f.to_dict()) or f.mitigation_detected
                    for f in result["findings"]
                )
            )


class ConfigTests(unittest.TestCase):
    def test_load_cve_report(self):
        rows = load_cve_report(VULNS)
        self.assertEqual(len(rows), 4)
        self.assertEqual(rows[0]["id"], "CVE-2025-64459")

    def test_symbols_catalog(self):
        catalog = load_symbols_catalog()
        self.assertTrue(catalog.get("sinks"))

    def test_severity_from_cvss_when_unknown(self):
        from sbombpath.severity import normalize_severity

        # Mirrors old sBOMBox reports: Deferred + CVSS, severity still UNKNOWN
        self.assertEqual(
            normalize_severity({"severity": "UNKNOWN", "cvss": 5.3}),
            "MEDIUM",
        )
        self.assertEqual(
            normalize_severity({"severity": "UNKNOWN", "cvss": 7.5}),
            "HIGH",
        )
        self.assertEqual(
            normalize_severity({"severity": "MODERATE"}),
            "MEDIUM",
        )
        self.assertEqual(
            normalize_severity({"severity": "CRITICAL", "cvss": 1.0}),
            "CRITICAL",
        )
        self.assertEqual(
            normalize_severity({"severity": "UNKNOWN"}),
            "UNKNOWN",
        )

    def test_load_cve_report_derives_severity(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "vulns.json"
            path.write_text(
                json.dumps(
                    {
                        "findings": [
                            {
                                "id": "CVE-2024-47081",
                                "package": "requests",
                                "severity": "UNKNOWN",
                                "cvss": 5.3,
                                "nvd_status": "Deferred",
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            rows = load_cve_report(path)
            self.assertEqual(rows[0]["severity"], "MEDIUM")
            self.assertEqual(rows[0]["cvss"], 5.3)


if __name__ == "__main__":
    unittest.main()
