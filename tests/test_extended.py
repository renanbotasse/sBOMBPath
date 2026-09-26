"""Extended tests: CLI, reachability, cross-file, HTML, no-cves mode."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from sbombpath.analysis.flow import DataFlowAnalyzer
from sbombpath.analysis.reachability import ReachabilityAnalyzer
from sbombpath.analysis.sinks import SinkDetector
from sbombpath.cli import main
from sbombpath.collect import collect_codebase
from sbombpath.config import load_symbols_catalog
from sbombpath.engine import PathRecognitionEngine
from sbombpath.models import FindingStatus


ROOT = Path(__file__).resolve().parent.parent
BACKEND = ROOT / "fixtures" / "sample_backend"
VULNS = ROOT / "fixtures" / "sample_vuln_report.json"


class ReachabilityTests(unittest.TestCase):
    def test_maps_search_and_auth_routes(self):
        codebase = collect_codebase(BACKEND)
        reach = ReachabilityAnalyzer(codebase)
        paths = {e.path for e in reach.endpoints}
        self.assertTrue(any("search" in p for p in paths))
        self.assertTrue(any("refresh" in p for p in paths))
        label, ok, _ = reach.describe("SearchAPIView.post", "SearchAPIView")
        self.assertTrue(ok)
        self.assertIn("search", (label or "").lower())


class CrossFileTests(unittest.TestCase):
    def test_jwt_path_crosses_views_to_services(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = PathRecognitionEngine(
                code_dir=BACKEND,
                cves_path=VULNS,
                output_dir=Path(tmp) / "out",
            ).run()
        jwt_hits = [
            f
            for f in result["findings"]
            if f.cve_id == "CVE-2026-32597"
            and "services.py" in (f.taint_sink.get("location") or "")
        ]
        self.assertGreaterEqual(len(jwt_hits), 1)
        self.assertEqual(jwt_hits[0].status, FindingStatus.EXPLOITABLE)

    def test_import_aware_resolve_validate_token(self):
        codebase = collect_codebase(BACKEND)
        flow = DataFlowAnalyzer(codebase)
        edge_funcs = {
            e.meta.get("function")
            for e in flow.edges
            if e.kind == "function_call"
        }
        self.assertIn("validate_token", edge_funcs)


class CliTests(unittest.TestCase):
    def test_cli_writes_all_formats(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "report"
            code = main(
                [
                    "--code-dir",
                    str(BACKEND),
                    "--cves",
                    str(VULNS),
                    "--output-dir",
                    str(out),
                ]
            )
            self.assertEqual(code, 0)
            self.assertTrue((out / "exploitable-paths.html").exists())
            self.assertTrue((out / "exploitable-paths.md").exists())

    def test_cli_fail_on_exploitable(self):
        with tempfile.TemporaryDirectory() as tmp:
            code = main(
                [
                    "--code-dir",
                    str(BACKEND),
                    "--cves",
                    str(VULNS),
                    "--output-dir",
                    str(Path(tmp) / "r"),
                    "--fail-on-exploitable",
                ]
            )
            self.assertEqual(code, 1)

    def test_runs_without_cves(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = PathRecognitionEngine(
                code_dir=BACKEND,
                cves_path=None,
                output_dir=Path(tmp) / "out",
            ).run()
            self.assertGreaterEqual(len(result["findings"]), 1)


class SinkCatalogTests(unittest.TestCase):
    def test_starstar_filter_matched(self):
        codebase = collect_codebase(BACKEND)
        sinks = SinkDetector(load_symbols_catalog()).scan_all(codebase)
        self.assertTrue(
            any(
                s.sink == "filter" and s.pattern_matched == "starstar_kwargs"
                for s in sinks
            )
        )

    def test_rejects_false_friend_sinks(self):
        """json.loads / str.join / obj.eval must not match pickle/path/eval sinks."""
        import ast

        from sbombpath.collect import CallFact

        det = SinkDetector(load_symbols_catalog())
        dummy = ast.parse("f(x)").body[0].value  # type: ignore[attr-defined]
        cases = [
            ("json.loads", "GENERIC-PICKLE"),
            ("signing.loads", "GENERIC-PICKLE"),
            ("', '.join", "GENERIC-PATH-TRAVERSAL"),
            ("str.join", "GENERIC-PATH-TRAVERSAL"),
            ("evaluator.eval", "GENERIC-RCE-EVAL"),
            ("SimpleEval.eval", "GENERIC-RCE-EVAL"),
            ("Image.open", "GENERIC-PATH-TRAVERSAL"),
        ]
        for func_name, cve in cases:
            call = CallFact(
                file="x.py",
                lineno=1,
                func_name=func_name,
                full_expr=f"{func_name}(x)",
                arg_names=["x"],
                keyword_names={},
                has_starargs=False,
                has_kwargs=False,
                shell_true=False,
                function=None,
                class_name=None,
                node=dummy,
            )
            matched = [m for m in det.match_call(call) if m.cve == cve]
            self.assertEqual(matched, [], f"{func_name} should not match {cve}")

    def test_named_filter_not_flagged_without_starstar(self):
        import ast

        from sbombpath.collect import CallFact

        det = SinkDetector(load_symbols_catalog())
        dummy = ast.parse("f(x)").body[0].value  # type: ignore[attr-defined]
        call = CallFact(
            file="x.py",
            lineno=1,
            func_name="Product.objects.filter",
            full_expr="Product.objects.filter(name=value)",
            arg_names=[],
            keyword_names={"name": "value"},
            has_starargs=False,
            has_kwargs=False,
            shell_true=False,
            function=None,
            class_name=None,
            node=dummy,
        )
        matched = [m for m in det.match_call(call) if m.cve == "CVE-2025-64459"]
        self.assertEqual(matched, [])


class ParallelCollectTests(unittest.TestCase):
    def test_collect_finds_fixture_files(self):
        codebase = collect_codebase(BACKEND)
        self.assertGreaterEqual(len(codebase.files), 4)
        self.assertFalse(codebase.parse_errors)


if __name__ == "__main__":
    unittest.main()
