"""AST fact dataclasses produced by the collector."""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional


@dataclass
class FunctionInfo:
    name: str
    qualname: str
    file: str
    lineno: int
    end_lineno: int
    args: List[str]
    class_name: Optional[str]
    node: ast.AST


@dataclass
class AssignmentFact:
    file: str
    lineno: int
    target: str
    value_expr: str
    value_names: List[str]
    function: Optional[str]
    class_name: Optional[str]


@dataclass
class CallFact:
    file: str
    lineno: int
    func_name: str
    full_expr: str
    arg_names: List[str]
    keyword_names: Dict[str, str]
    has_starargs: bool
    has_kwargs: bool
    shell_true: bool
    function: Optional[str]
    class_name: Optional[str]
    node: ast.Call


@dataclass
class ReturnFact:
    file: str
    lineno: int
    expr: str
    names: List[str]
    function: Optional[str]
    class_name: Optional[str]


@dataclass
class FileFacts:
    path: str
    tree: ast.AST
    source: str
    lines: List[str]
    imports: Dict[str, str] = field(default_factory=dict)
    functions: List[FunctionInfo] = field(default_factory=list)
    assignments: List[AssignmentFact] = field(default_factory=list)
    calls: List[CallFact] = field(default_factory=list)
    returns: List[ReturnFact] = field(default_factory=list)
    classes: Dict[str, List[str]] = field(default_factory=dict)


@dataclass
class CodebaseFacts:
    root: Path
    files: Dict[str, FileFacts] = field(default_factory=dict)
    parse_errors: List[str] = field(default_factory=list)

    def rel(self, path: Path) -> str:
        try:
            return str(path.resolve().relative_to(self.root.resolve()))
        except ValueError:
            return str(path)
