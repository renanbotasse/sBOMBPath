"""Flow graph edge and traced taint path types."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional

from ...collect import CallFact
from ...models import FlowStep, TaintSource

from .keys import VarKey


@dataclass
class FlowEdge:
    src: VarKey
    dst: VarKey
    kind: str
    location: str
    code: str
    meta: Dict[str, str] = field(default_factory=dict)


@dataclass
class TracedPath:
    source: TaintSource
    steps: List[FlowStep]
    sink_call: Optional[CallFact]
    sink_var: Optional[str]
    incomplete: bool = False
