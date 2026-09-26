"""Shared dataclasses for sBOMBPath."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional

from .enums import FindingStatus, RiskLevel


@dataclass
class Location:
    file: str
    line: int
    col: int = 0

    def __str__(self) -> str:
        return f"{self.file}:{self.line}"

    def to_dict(self) -> Dict[str, Any]:
        return {"file": self.file, "line": self.line, "col": self.col}


@dataclass
class TaintSource:
    file: str
    line: int
    var: str
    source_type: str
    expression: str
    function: Optional[str] = None
    class_name: Optional[str] = None

    @property
    def location(self) -> str:
        return f"{self.file}:{self.line}"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class FlowStep:
    step: int
    type: str
    location: str
    code: str
    var: Optional[str] = None
    function: Optional[str] = None
    param_name: Optional[str] = None
    arg_position: Optional[int] = None
    pattern_matched: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {k: v for k, v in asdict(self).items() if v is not None}


@dataclass
class SinkMatch:
    cve: str
    package: str
    sink: str
    location: str
    expression: str
    pattern_matched: str
    severity: str = "HIGH"
    title: str = ""
    remediation: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class Mitigation:
    kind: str
    location: str
    detail: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class Endpoint:
    method: str
    path: str
    view: str
    location: str

    @property
    def label(self) -> str:
        return f"{self.method} {self.path}"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ExploitableFinding:
    cve_id: str
    package: str
    severity: str
    status: FindingStatus
    risk_level: RiskLevel
    http_endpoint: Optional[str]
    reachable: bool
    taint_source: Dict[str, Any]
    taint_sink: Dict[str, Any]
    data_flow_path: List[Dict[str, Any]]
    mitigation_detected: Optional[str]
    mitigation_location: Optional[str]
    attack_payload_example: Optional[str]
    remediation: str
    priority: str
    path_description: str
    analysis_notes: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["status"] = self.status.value
        data["risk_level"] = self.risk_level.value
        return data


@dataclass
class ReportMeta:
    generated_at: str
    cves_analyzed: int
    exploitable_paths: int
    mitigated_paths: int
    unknown_paths: int
    not_exploitable: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
