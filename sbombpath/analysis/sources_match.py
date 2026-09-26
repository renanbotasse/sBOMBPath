"""Helpers for matching taint-source AST patterns."""

from __future__ import annotations

import ast
from typing import Dict, List, Optional, Sequence, Tuple

from ..collect import FileFacts, attr_chain


def matches_attr_chain(node: ast.AST, expected: Sequence[str]) -> bool:
    chain = attr_chain(node)
    if not chain or len(chain) < len(expected):
        return False
    expected_list = list(expected)
    if chain == expected_list:
        return True
    return chain[-len(expected) :] == expected_list


def is_source_node(node: ast.AST, attr_chains: List[List[str]]) -> Optional[List[str]]:
    target = node
    if isinstance(node, ast.Subscript):
        target = node.value
    elif isinstance(node, ast.Call):
        if isinstance(node.func, ast.Attribute) and node.func.attr == "get":
            target = node.func.value
        else:
            return None
    for chain in attr_chains:
        if matches_attr_chain(target, chain):
            return chain
    return None


def enclosing_function(
    file_facts: FileFacts, lineno: int
) -> Tuple[Optional[str], Optional[str]]:
    best = None
    for fn in file_facts.functions:
        if fn.lineno <= lineno <= fn.end_lineno:
            if best is None or fn.lineno >= best.lineno:
                best = fn
    if not best:
        return None, None
    return best.qualname, best.class_name


def resolve_source_type(
    matched: List[str],
    type_by_chain: Dict[str, str],
    attr_chains: List[Tuple[str, List[str]]],
) -> str:
    source_type = type_by_chain.get(".".join(matched))
    if source_type is not None:
        return source_type
    for source_type, chain in attr_chains:
        if matched[-len(chain) :] == chain:
            return source_type
    return ".".join(matched)


def target_name(targets: List[ast.AST]) -> Optional[str]:
    for target in targets:
        if isinstance(target, ast.Name):
            return target.id
        if isinstance(target, (ast.Tuple, ast.List)) and target.elts:
            if isinstance(target.elts[0], ast.Name):
                return target.elts[0].id
    return None


def call_matches_qualnames(fname: str, quals: List[str], *, use_endswith: bool) -> bool:
    if fname in quals:
        return True
    if use_endswith:
        return any(fname.endswith(q) for q in quals)
    simple_names = {q.split(".")[-1] for q in quals}
    return fname.split(".")[-1] in simple_names


def find_nested_source(value: ast.AST, chains: List[List[str]]) -> Optional[List[str]]:
    for child in ast.walk(value):
        nested = is_source_node(child, chains)
        if nested:
            return nested
        if isinstance(child, ast.Call) and isinstance(child.func, ast.Attribute):
            nested = is_source_node(child.func.value, chains)
            if nested:
                return nested
    return None
