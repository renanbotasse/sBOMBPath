"""JSON, CSV, and debug report writers."""

from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..models import ExploitableFinding, ReportMeta


def write_json(
    output_dir: Path,
    meta: ReportMeta,
    findings: List[ExploitableFinding],
    comparison: Optional[Dict[str, Any]] = None,
) -> None:
    payload = {
        "report_meta": meta.to_dict(),
        "exploitable_paths": [f.to_dict() for f in findings],
        "sbom_comparison": comparison or {},
    }
    path = output_dir / "exploitable-paths.json"
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def write_csv(output_dir: Path, findings: List[ExploitableFinding]) -> None:
    path = output_dir / "exploitable-paths.csv"
    fields = [
        "cve_id",
        "package",
        "exposure",
        "status",
        "risk_level",
        "http_endpoint",
        "severity",
        "priority",
        "source_location",
        "sink_location",
        "contaminated_symbols",
        "mitigation_detected",
    ]
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for f in findings:
            writer.writerow(
                {
                    "cve_id": f.cve_id,
                    "package": f.package,
                    "exposure": f.exposure.value,
                    "status": f.status.value,
                    "risk_level": f.risk_level.value,
                    "http_endpoint": f.http_endpoint or "",
                    "severity": f.severity,
                    "priority": f.priority,
                    "source_location": f.taint_source.get("location", ""),
                    "sink_location": f.taint_sink.get("location", ""),
                    "contaminated_symbols": ";".join(f.contaminated_symbols),
                    "mitigation_detected": f.mitigation_detected or "",
                }
            )


def write_debug(debug_dir: Path, debug: Dict[str, Any]) -> None:
    for name, data in debug.items():
        path = debug_dir / f"{name}.json"
        path.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
