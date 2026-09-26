"""BFS taint tracking from sources to sink calls."""

from __future__ import annotations

from collections import defaultdict, deque
from typing import Deque, Dict, List, Set, Tuple

from ...collect import CallFact
from ...models import TaintSource

from .keys import VarKey, re_ident_in, split_key, var_key
from .steps import edges_to_steps
from .types import FlowEdge, TracedPath


class FlowTracker:
    def __init__(self, adjacency: Dict[VarKey, List[FlowEdge]], max_depth: int) -> None:
        self.adjacency = adjacency
        self.max_depth = max_depth

    def track(self, source: TaintSource, sink_calls: List[CallFact]) -> List[TracedPath]:
        seed = var_key(source.file, source.function, source.var)
        sink_index = self._index_sinks(sink_calls)
        results = self._bfs(source, seed, sink_index)

        uniq: Dict[Tuple[str, str], TracedPath] = {}
        for path in results:
            sink_loc = (
                f"{path.sink_call.file}:{path.sink_call.lineno}"
                if path.sink_call
                else "none"
            )
            key = (source.location, sink_loc)
            if key not in uniq or len(path.steps) < len(uniq[key].steps):
                uniq[key] = path
        return list(uniq.values())

    def _index_sinks(self, sink_calls: List[CallFact]) -> Dict[str, List[CallFact]]:
        by_scope: Dict[str, List[CallFact]] = defaultdict(list)
        for call in sink_calls:
            scope = f"{call.file}::{call.function or '<module>'}::"
            by_scope[scope].append(call)
        return by_scope

    def _bfs(
        self,
        source: TaintSource,
        seed: VarKey,
        sink_index: Dict[str, List[CallFact]],
    ) -> List[TracedPath]:
        results: List[TracedPath] = []
        queue: Deque[Tuple[VarKey, int, List[FlowEdge]]] = deque()
        queue.append((seed, 0, []))
        visited: Set[VarKey] = set()
        reported_sinks: Set[str] = set()

        while queue:
            var, depth, edge_path = queue.popleft()
            if depth > self.max_depth or var in visited:
                continue
            visited.add(var)

            file, func, name = split_key(var)
            scope_prefix = f"{file}::{func or '<module>'}::"
            for call in sink_index.get(scope_prefix, []):
                sink_id = f"{call.file}:{call.lineno}:{call.func_name}"
                if sink_id in reported_sinks:
                    continue
                if self._var_reaches_call(name, call, edge_path):
                    reported_sinks.add(sink_id)
                    results.append(
                        TracedPath(
                            source=source,
                            steps=edges_to_steps(source, edge_path, call),
                            sink_call=call,
                            sink_var=name,
                            incomplete=depth >= self.max_depth,
                        )
                    )

            for edge in self.adjacency.get(var, []):
                if edge.kind == "parameter" and edge.src == edge.dst and not edge_path:
                    continue
                queue.append((edge.dst, depth + 1, edge_path + [edge]))

        return results

    def _var_reaches_call(
        self, name: str, call: CallFact, edge_path: List[FlowEdge]
    ) -> bool:
        call_loc = f"{call.file}:{call.lineno}"
        if name.startswith("<") and name.endswith(">"):
            return name.strip("<>") in call.full_expr or any(
                e.location == call_loc for e in edge_path
            )
        if name in call.arg_names:
            return True
        if call.has_kwargs and call.keyword_names.get("**") == name:
            return True
        for value in call.keyword_names.values():
            if value == name or re_ident_in(name, value):
                return True

        call_simple = call.func_name.split(".")[-1]
        for edge in edge_path[-3:]:
            if edge.location != call_loc:
                continue
            if edge.kind in {"kwargs_unpack", "function_call"}:
                return True
            candidate = edge.meta.get("sink_candidate", "")
            if candidate and candidate.split(".")[-1] == call_simple:
                return True
        return False
