"""Orchestrate report writers for all output formats."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

from ..models import ExploitableFinding, FindingStatus, ReportMeta
from .html import write_html
from .json_csv import write_csv, write_debug, write_json
from .markdown import write_markdown


class ReportGenerator:
    def __init__(self, output_dir: Path) -> None:
        self.output_dir = output_dir
        self.debug_dir = output_dir / "debug"

    def write(
        self,
        findings: List[ExploitableFinding],
        cves_analyzed: int,
        debug: Dict[str, Any],
    ) -> ReportMeta:
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.debug_dir.mkdir(parents=True, exist_ok=True)

        by_status = {
            status: [f for f in findings if f.status == status]
            for status in FindingStatus
        }
        meta = ReportMeta(
            generated_at=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            cves_analyzed=cves_analyzed,
            exploitable_paths=len(by_status[FindingStatus.EXPLOITABLE]),
            mitigated_paths=len(by_status[FindingStatus.MITIGATED]),
            unknown_paths=len(by_status[FindingStatus.UNKNOWN]),
            not_exploitable=len(by_status[FindingStatus.NOT_EXPLOITABLE]),
        )

        write_json(self.output_dir, meta, findings)
        write_markdown(self.output_dir, meta, findings)
        write_csv(self.output_dir, findings)
        write_html(self.output_dir, meta, findings)
        write_debug(self.debug_dir, debug)
        return meta
