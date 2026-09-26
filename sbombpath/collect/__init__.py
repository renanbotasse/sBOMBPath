"""Codebase collection: parse Python sources into AST facts."""

from .ast_utils import attr_chain, call_func_name, collect_names, expr_to_str, has_shell_true
from .codebase import collect_codebase, iter_python_files, line_at
from .facts import (
    AssignmentFact,
    CallFact,
    CodebaseFacts,
    FileFacts,
    FunctionInfo,
    ReturnFact,
)

__all__ = [
    "AssignmentFact",
    "CallFact",
    "CodebaseFacts",
    "FileFacts",
    "FunctionInfo",
    "ReturnFact",
    "attr_chain",
    "call_func_name",
    "collect_codebase",
    "collect_names",
    "expr_to_str",
    "has_shell_true",
    "iter_python_files",
    "line_at",
]
