"""AST visitor that extracts imports, calls, assignments, and returns."""

from __future__ import annotations

import ast
from typing import Dict, List, Optional

from .ast_utils import call_func_name, collect_names, expr_to_str, has_shell_true
from .facts import AssignmentFact, CallFact, FunctionInfo, ReturnFact


class FactsVisitor(ast.NodeVisitor):
    def __init__(self, file_rel: str, source: str) -> None:
        self.file_rel = file_rel
        self.source = source
        self.lines = source.splitlines()
        self.imports: Dict[str, str] = {}
        self.functions: List[FunctionInfo] = []
        self.assignments: List[AssignmentFact] = []
        self.calls: List[CallFact] = []
        self.returns: List[ReturnFact] = []
        self.classes: Dict[str, List[str]] = {}
        self._class_stack: List[str] = []
        self._func_stack: List[str] = []

    def _current_class(self) -> Optional[str]:
        return self._class_stack[-1] if self._class_stack else None

    def _current_func(self) -> Optional[str]:
        if not self._func_stack:
            return None
        cls = self._current_class()
        name = self._func_stack[-1]
        return f"{cls}.{name}" if cls else name

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            self.imports[alias.asname or alias.name.split(".")[0]] = alias.name
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        module = node.module or ""
        for alias in node.names:
            local = alias.asname or alias.name
            self.imports[local] = f"{module}.{alias.name}" if module else alias.name
        self.generic_visit(node)

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        methods = [n.name for n in node.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]
        self.classes[node.name] = methods
        self._class_stack.append(node.name)
        self.generic_visit(node)
        self._class_stack.pop()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._visit_function(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._visit_function(node)

    def _visit_function(self, node: ast.AST) -> None:
        assert isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        class_name = self._current_class()
        qual = f"{class_name}.{node.name}" if class_name else node.name
        args = [a.arg for a in node.args.args]
        self.functions.append(
            FunctionInfo(
                name=node.name,
                qualname=qual,
                file=self.file_rel,
                lineno=node.lineno,
                end_lineno=getattr(node, "end_lineno", node.lineno) or node.lineno,
                args=args,
                class_name=class_name,
                node=node,
            )
        )
        self._func_stack.append(node.name)
        self.generic_visit(node)
        self._func_stack.pop()

    def visit_Assign(self, node: ast.Assign) -> None:
        value_names = collect_names(node.value)
        value_expr = expr_to_str(node.value)
        for target in node.targets:
            self._record_target(target, value_expr, value_names, node.lineno)
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        if node.value is not None:
            self._record_assign_value(node.target, node.value, node.lineno)
        self.generic_visit(node)

    def visit_AugAssign(self, node: ast.AugAssign) -> None:
        self._record_assign_value(node.target, node.value, node.lineno)
        self.generic_visit(node)

    def _record_assign_value(self, target: ast.AST, value: ast.AST, lineno: int) -> None:
        self._record_target(target, expr_to_str(value), collect_names(value), lineno)

    def _record_target(
        self,
        target: ast.AST,
        value_expr: str,
        value_names: List[str],
        lineno: int,
    ) -> None:
        if isinstance(target, ast.Name):
            self.assignments.append(
                AssignmentFact(
                    file=self.file_rel,
                    lineno=lineno,
                    target=target.id,
                    value_expr=value_expr,
                    value_names=value_names,
                    function=self._current_func(),
                    class_name=self._current_class(),
                )
            )
        elif isinstance(target, (ast.Tuple, ast.List)):
            for elt in target.elts:
                self._record_target(elt, value_expr, value_names, lineno)

    def visit_Call(self, node: ast.Call) -> None:
        arg_names: List[str] = []
        for arg in node.args:
            arg_names.extend(collect_names(arg) or [expr_to_str(arg)])
        keywords: Dict[str, str] = {}
        has_kwargs = False
        for kw in node.keywords:
            if kw.arg is None:
                has_kwargs = True
                keywords["**"] = expr_to_str(kw.value)
            else:
                keywords[kw.arg] = expr_to_str(kw.value)
        self.calls.append(
            CallFact(
                file=self.file_rel,
                lineno=node.lineno,
                func_name=call_func_name(node),
                full_expr=expr_to_str(node),
                arg_names=arg_names,
                keyword_names=keywords,
                has_starargs=any(isinstance(a, ast.Starred) for a in node.args),
                has_kwargs=has_kwargs,
                shell_true=has_shell_true(node),
                function=self._current_func(),
                class_name=self._current_class(),
                node=node,
            )
        )
        self.generic_visit(node)

    def visit_Return(self, node: ast.Return) -> None:
        self.returns.append(
            ReturnFact(
                file=self.file_rel,
                lineno=node.lineno,
                expr=expr_to_str(node.value),
                names=collect_names(node.value),
                function=self._current_func(),
                class_name=self._current_class(),
            )
        )
        self.generic_visit(node)
