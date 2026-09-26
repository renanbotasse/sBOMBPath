"""Small AST helpers used by collectors and analyzers."""

from __future__ import annotations

import ast
from typing import List, Optional


def attr_chain(node: ast.AST) -> Optional[List[str]]:
    parts: List[str] = []
    cur: ast.AST = node
    while True:
        if isinstance(cur, ast.Name):
            parts.append(cur.id)
            break
        if isinstance(cur, ast.Attribute):
            parts.append(cur.attr)
            cur = cur.value
            continue
        return None
    parts.reverse()
    return parts


def expr_to_str(node: Optional[ast.AST]) -> str:
    if node is None:
        return ""
    try:
        return ast.unparse(node)
    except Exception:
        return type(node).__name__


def collect_names(node: Optional[ast.AST]) -> List[str]:
    if node is None:
        return []
    names: List[str] = []
    for child in ast.walk(node):
        if isinstance(child, ast.Name):
            names.append(child.id)
    return names


def call_func_name(node: ast.Call) -> str:
    chain = attr_chain(node.func)
    if chain:
        return ".".join(chain)
    return expr_to_str(node.func)


def has_shell_true(node: ast.Call) -> bool:
    for kw in node.keywords:
        if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
            return True
    return False
