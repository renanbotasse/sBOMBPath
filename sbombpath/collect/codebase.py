"""Walk a code directory and build CodebaseFacts."""

from __future__ import annotations

import ast
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import List, Optional, Tuple

from .constants import SKIP_DIR_NAMES
from .facts import CodebaseFacts, FileFacts
from .visitor import FactsVisitor


def iter_python_files(root: Path) -> List[Path]:
    files: List[Path] = []
    for path in root.rglob("*.py"):
        if any(part in SKIP_DIR_NAMES for part in path.parts):
            continue
        files.append(path)
    return sorted(files)


def line_at(facts: FileFacts, lineno: int) -> str:
    if 1 <= lineno <= len(facts.lines):
        return facts.lines[lineno - 1].strip()
    return ""


def collect_codebase(code_dir: Path, workers: Optional[int] = None) -> CodebaseFacts:
    """Parse all Python files under code_dir (optionally in parallel)."""
    root = code_dir.resolve()
    facts = CodebaseFacts(root=root)
    paths = iter_python_files(root)
    if not paths:
        return facts

    def _parse_one(path: Path) -> Tuple[str, Optional[FileFacts], Optional[str]]:
        rel = facts.rel(path)
        try:
            source = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            return rel, None, f"{rel}: read error: {exc}"
        try:
            tree = ast.parse(source, filename=str(path))
        except SyntaxError as exc:
            return rel, None, f"{rel}: syntax error: {exc}"
        visitor = FactsVisitor(rel, source)
        visitor.visit(tree)
        return (
            rel,
            FileFacts(
                path=rel,
                tree=tree,
                source=source,
                lines=visitor.lines,
                imports=visitor.imports,
                functions=visitor.functions,
                assignments=visitor.assignments,
                calls=visitor.calls,
                returns=visitor.returns,
                classes=visitor.classes,
            ),
            None,
        )

    max_workers = workers
    if max_workers is None:
        max_workers = min(8, max(1, len(paths)))

    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = [pool.submit(_parse_one, p) for p in paths]
        for fut in as_completed(futures):
            rel, file_facts, err = fut.result()
            if err:
                facts.parse_errors.append(err)
            elif file_facts is not None:
                facts.files[rel] = file_facts
    return facts
