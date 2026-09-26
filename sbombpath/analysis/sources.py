"""Detect taint sources from AST facts + pattern catalog."""

from __future__ import annotations

import ast
from typing import Any, Dict, List, Optional, Set, Tuple

from ..collect import CodebaseFacts, FileFacts, call_func_name, expr_to_str
from ..models import TaintSource
from .sources_match import (
    call_matches_qualnames,
    enclosing_function,
    find_nested_source,
    is_source_node,
    resolve_source_type,
    target_name,
)


class SourceDetector:
    def __init__(self, catalog: Dict[str, Any]) -> None:
        self.attr_chains: List[Tuple[str, List[str]]] = []
        for item in catalog.get("sources", []):
            chain = item.get("attr_chain") or []
            if chain:
                source_type = item.get("source_type", ".".join(chain))
                self.attr_chains.append((source_type, list(chain)))
        self.call_sources = catalog.get("call_sources", [])

    def detect(self, codebase: CodebaseFacts) -> List[TaintSource]:
        sources: List[TaintSource] = []
        seen: Set[Tuple[str, int, str]] = set()
        for ff in codebase.files.values():
            sources.extend(self._detect_in_file(ff, seen))
        return sources

    def _emit(
        self,
        found: List[TaintSource],
        seen: Set[Tuple[str, int, str]],
        ff: FileFacts,
        lineno: int,
        var: str,
        source_type: str,
        expression: str,
        function: Optional[str] = None,
        class_name: Optional[str] = None,
    ) -> None:
        key = (ff.path, lineno, var)
        if key in seen:
            return
        seen.add(key)
        if function is None and class_name is None:
            function, class_name = enclosing_function(ff, lineno)
        found.append(
            TaintSource(
                file=ff.path,
                line=lineno,
                var=var,
                source_type=source_type,
                expression=expression,
                function=function,
                class_name=class_name,
            )
        )

    def _detect_in_file(
        self, ff: FileFacts, seen: Set[Tuple[str, int, str]]
    ) -> List[TaintSource]:
        found: List[TaintSource] = []
        chains = [c for _, c in self.attr_chains]
        type_by_chain = {".".join(c): t for t, c in self.attr_chains}
        detector = self

        class Visitor(ast.NodeVisitor):
            def visit_Assign(self, node: ast.Assign) -> None:
                self._check_value(node.value, node.targets, node.lineno)
                self.generic_visit(node)

            def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
                if node.value is not None:
                    self._check_value(node.value, [node.target], node.lineno)
                self.generic_visit(node)

            def visit_Call(self, node: ast.Call) -> None:
                fname = call_func_name(node)
                for cs in detector.call_sources:
                    quals = cs.get("qualnames") or []
                    if not call_matches_qualnames(fname, quals, use_endswith=False):
                        continue
                    arg0 = node.args[0] if node.args else None
                    if arg0 is not None and is_source_node(arg0, chains):
                        detector._emit(
                            found, seen, ff, node.lineno, fname,
                            cs.get("source_type", fname), expr_to_str(node),
                        )
                self.generic_visit(node)

            def _check_value(
                self, value: ast.AST, targets: List[ast.AST], lineno: int
            ) -> None:
                matched = is_source_node(value, chains)
                if not matched and isinstance(value, ast.Call):
                    fname = call_func_name(value)
                    for cs in detector.call_sources:
                        quals = cs.get("qualnames") or []
                        if not call_matches_qualnames(fname, quals, use_endswith=True):
                            continue
                        arg0 = value.args[0] if value.args else None
                        if arg0 is not None and is_source_node(arg0, chains):
                            var = target_name(targets) or fname
                            detector._emit(
                                found, seen, ff, lineno, var,
                                cs.get("source_type", fname), expr_to_str(value),
                            )
                            return
                if not matched:
                    matched = find_nested_source(value, chains)
                if not matched:
                    return
                source_type = resolve_source_type(
                    matched, type_by_chain, detector.attr_chains
                )
                var = target_name(targets) or expr_to_str(value)
                detector._emit(
                    found, seen, ff, lineno, var, source_type, expr_to_str(value)
                )

        Visitor().visit(ff.tree)
        self._detect_direct_call_args(ff, found, seen, chains, type_by_chain)
        return found

    def _detect_direct_call_args(
        self,
        ff: FileFacts,
        found: List[TaintSource],
        seen: Set[Tuple[str, int, str]],
        chains: List[List[str]],
        type_by_chain: Dict[str, str],
    ) -> None:
        for call in ff.calls:
            arg_nodes = list(call.node.args)
            arg_nodes.extend(
                kw.value for kw in call.node.keywords if kw.value is not None
            )
            for arg_node in arg_nodes:
                matched = is_source_node(arg_node, chains)
                if not matched:
                    continue
                source_type = resolve_source_type(
                    matched, type_by_chain, self.attr_chains
                )
                synth_var = f"<{expr_to_str(arg_node)}>"
                self._emit(
                    found, seen, ff, call.lineno, synth_var, source_type,
                    expr_to_str(arg_node),
                    function=call.function, class_name=call.class_name,
                )
