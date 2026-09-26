"""Build assignment / call / return edges for the flow graph."""

from __future__ import annotations

from collections import defaultdict
from typing import Dict, List, Tuple

from ...collect import CodebaseFacts, FileFacts, line_at

from .keys import var_key
from .resolve import CalleeResolver
from .types import FlowEdge


class FlowGraphBuilder:
    def __init__(self, codebase: CodebaseFacts, resolver: CalleeResolver) -> None:
        self.codebase = codebase
        self.resolver = resolver
        self.edges: List[FlowEdge] = []
        self.adjacency: Dict[str, List[FlowEdge]] = defaultdict(list)

    def build(self) -> Tuple[List[FlowEdge], Dict[str, List[FlowEdge]]]:
        for ff in self.codebase.files.values():
            self._add_assignments(ff)
            self._add_calls(ff)
            self._add_returns(ff)
        return self.edges, self.adjacency

    def _add_edge(self, edge: FlowEdge) -> None:
        self.edges.append(edge)
        self.adjacency[edge.src].append(edge)

    def _add_assignments(self, ff: FileFacts) -> None:
        for asn in ff.assignments:
            dst = var_key(ff.path, asn.function, asn.target)
            for name in asn.value_names:
                self._add_edge(
                    FlowEdge(
                        src=var_key(ff.path, asn.function, name),
                        dst=dst,
                        kind="assignment",
                        location=f"{ff.path}:{asn.lineno}",
                        code=line_at(ff, asn.lineno) or f"{asn.target} = {asn.value_expr}",
                        meta={"var": asn.target},
                    )
                )

    def _add_calls(self, ff: FileFacts) -> None:
        for call in ff.calls:
            resolved = self.resolver.resolve_callee(call, ff)
            if resolved:
                file_r, fn = resolved
                params = [a for a in fn.args if a not in ("self", "cls")]
                for idx, arg_name in enumerate(call.arg_names):
                    if idx >= len(params):
                        break
                    src = var_key(ff.path, call.function, arg_name)
                    dst = var_key(file_r, fn.qualname, params[idx])
                    self._add_edge(
                        FlowEdge(
                            src=src,
                            dst=dst,
                            kind="function_call",
                            location=f"{ff.path}:{call.lineno}",
                            code=line_at(ff, call.lineno) or call.full_expr,
                            meta={
                                "function": fn.qualname,
                                "arg_position": str(idx),
                                "param_name": params[idx],
                            },
                        )
                    )
                    self._add_edge(
                        FlowEdge(
                            src=dst,
                            dst=dst,
                            kind="parameter",
                            location=f"{file_r}:{fn.lineno}",
                            code=f"def {fn.name}(... {params[idx]} ...)",
                            meta={"param_name": params[idx], "function": fn.qualname},
                        )
                    )

            if call.has_kwargs and "**" in call.keyword_names:
                kw_name = call.keyword_names["**"].strip()
                if kw_name.isidentifier():
                    src = var_key(ff.path, call.function, kw_name)
                    dst = var_key(
                        ff.path, call.function, f"__kwargs_to__{call.func_name}"
                    )
                    self._add_edge(
                        FlowEdge(
                            src=src,
                            dst=dst,
                            kind="kwargs_unpack",
                            location=f"{ff.path}:{call.lineno}",
                            code=line_at(ff, call.lineno) or call.full_expr,
                            meta={"sink_candidate": call.func_name},
                        )
                    )

    def _add_returns(self, ff: FileFacts) -> None:
        returns_by_fn: Dict[str, List] = defaultdict(list)
        for ret in ff.returns:
            if ret.function:
                returns_by_fn[ret.function].append(ret)

        for call in ff.calls:
            resolved = self.resolver.resolve_callee(call, ff)
            if not resolved:
                continue
            file_r, fn = resolved
            for asn in ff.assignments:
                if asn.function != call.function:
                    continue
                call_in_expr = (
                    call.func_name.split(".")[-1] in asn.value_expr
                    or call.full_expr in asn.value_expr
                )
                if not call_in_expr and asn.lineno != call.lineno:
                    continue
                for ret in returns_by_fn.get(fn.qualname, []):
                    for name in ret.names:
                        self._add_edge(
                            FlowEdge(
                                src=var_key(file_r, fn.qualname, name),
                                dst=var_key(ff.path, asn.function, asn.target),
                                kind="return",
                                location=f"{file_r}:{ret.lineno}",
                                code=f"return {ret.expr}",
                                meta={"assigned_to": asn.target},
                            )
                        )
