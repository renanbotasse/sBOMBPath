"""CLI for sBOMBPath."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import List, Optional

from . import __version__
from .engine import PathRecognitionEngine
from .models import FindingStatus


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sbombpath",
        description=(
            "sBOMBPath — detect exploitable taint paths "
            "from user input to vulnerable sinks (CVE reachability)."
        ),
    )
    parser.add_argument(
        "--code-dir",
        required=True,
        type=Path,
        help="Root directory of Python application source",
    )
    parser.add_argument(
        "--cves",
        type=Path,
        default=None,
        help="Optional CVE list JSON from an external scanner. Not required.",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("path-recognition-report"),
        help="Directory for reports (default: path-recognition-report)",
    )
    parser.add_argument(
        "--symbols",
        type=Path,
        default=None,
        help="CVE → sink catalog JSON (default: rules/symbols.json)",
    )
    parser.add_argument(
        "--sources",
        type=Path,
        default=None,
        help="Taint source catalog JSON (default: rules/sources.json)",
    )
    parser.add_argument(
        "--max-depth",
        type=int,
        default=25,
        help="Max BFS depth for taint propagation (default: 25)",
    )
    parser.add_argument(
        "--fail-on-exploitable",
        action="store_true",
        help="Exit with code 1 when EXPLOITABLE findings exist (CI)",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if not args.code_dir.exists():
        print(f"error: code directory not found: {args.code_dir}", file=sys.stderr)
        return 2

    result = PathRecognitionEngine(
        code_dir=args.code_dir,
        cves_path=args.cves,
        symbols_path=args.symbols,
        sources_path=args.sources,
        output_dir=args.output_dir,
        max_depth=args.max_depth,
    ).run()

    meta = result["meta"]
    findings = result["findings"]

    print("sBOMBPath — complete")
    print(f"  CVEs analyzed:     {meta.cves_analyzed}")
    print(f"  User-facing:       {meta.user_facing}")
    print(f"  Internal taint:    {meta.internal_taint}")
    print(f"  Package surface:   {meta.package_surface}")
    print(f"  EXPLOITABLE:       {meta.exploitable_paths}")
    print(f"  MITIGATED:         {meta.mitigated_paths}")
    print(f"  UNKNOWN / AT_RISK: {meta.unknown_paths}")
    print(f"  Reports written to: {args.output_dir.resolve()}")
    if result["parse_errors"]:
        print(f"  Parse warnings:    {len(result['parse_errors'])}")

    if args.fail_on_exploitable and any(
        f.status == FindingStatus.EXPLOITABLE for f in findings
    ):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
