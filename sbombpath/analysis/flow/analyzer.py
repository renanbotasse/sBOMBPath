"""DataFlowAnalyzer facade: index functions, build graph, track taint."""

from __future__ import annotations

from collections import defaultdict
from typing import Dict, List, Tuple

from ...collect import CallFact, CodebaseFacts, FunctionInfo
from ...models import TaintSource

from .builder import FlowGraphBuilder
from .resolve import CalleeResolver
from .tracker import FlowTracker
from .types import TracedPath


class DataFlowAnalyzer:
    def __init__(self, codebase: CodebaseFacts, max_depth: int = 25) -> None:
        self.codebase = codebase
        self.max_depth = max_depth
        self.function_index: Dict[str, List[Tuple[str, FunctionInfo]]] = defaultdict(list)
        self._index_functions()
        resolver = CalleeResolver(self.function_index)
        self.edges, self.adjacency = FlowGraphBuilder(codebase, resolver).build()
        self._tracker = FlowTracker(self.adjacency, max_depth)

    def _index_functions(self) -> None:
        for rel, ff in self.codebase.files.items():
            for fn in ff.functions:
                self.function_index[fn.name].append((rel, fn))
                self.function_index[fn.qualname].append((rel, fn))

    def graph_as_dict(self) -> Dict[str, List[Dict]]:
        out: Dict[str, List[Dict]] = defaultdict(list)
        for edge in self.edges:
            if edge.kind == "parameter" and edge.src == edge.dst:
                continue
            out[edge.src].append(
                {
                    "to": edge.dst,
                    "kind": edge.kind,
                    "location": edge.location,
                    "code": edge.code,
                    "meta": edge.meta,
                }
            )
        return dict(out)

    def track(self, source: TaintSource, sink_calls: List[CallFact]) -> List[TracedPath]:
        return self._tracker.track(source, sink_calls)
