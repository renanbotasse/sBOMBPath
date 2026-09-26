"""Callee and import-map resolution for call edges."""

from __future__ import annotations

from typing import Dict, List, Optional, Tuple

from ...collect import CallFact, FileFacts, FunctionInfo


class CalleeResolver:
    def __init__(
        self, function_index: Dict[str, List[Tuple[str, FunctionInfo]]]
    ) -> None:
        self.function_index = function_index

    def pick_candidate(
        self, candidates: List[Tuple[str, FunctionInfo]], prefer_file: str
    ) -> Optional[Tuple[str, FunctionInfo]]:
        if not candidates:
            return None
        for file, fn in candidates:
            if file == prefer_file:
                return file, fn
        return candidates[0]

    def resolve_callee(
        self, call: CallFact, ff: FileFacts
    ) -> Optional[Tuple[str, FunctionInfo]]:
        name = call.func_name
        simple = name.split(".")[-1]

        imported = self.resolve_via_imports(call, ff)
        if imported:
            return imported

        if call.class_name and name.startswith("self."):
            qual = f"{call.class_name}.{simple}"
            picked = self.pick_candidate(self.function_index.get(qual) or [], ff.path)
            if picked:
                return picked

        for key in (name, simple):
            picked = self.pick_candidate(self.function_index.get(key) or [], ff.path)
            if picked:
                return picked
        return None

    def resolve_via_imports(
        self, call: CallFact, ff: FileFacts
    ) -> Optional[Tuple[str, FunctionInfo]]:
        name = call.func_name
        parts = name.split(".")
        simple = parts[-1]

        if name in ff.imports or simple in ff.imports:
            target = ff.imports.get(name) or ff.imports.get(simple)
            if target:
                return self.match_import_target(target, simple)

        if len(parts) >= 2:
            head, rest = parts[0], parts[-1]
            if head in ff.imports:
                module = ff.imports[head]
                qualified = f"{module}.{rest}"
                return self.match_import_target(qualified, rest)
        return None

    def match_import_target(
        self, import_target: str, func_simple: str
    ) -> Optional[Tuple[str, FunctionInfo]]:
        module_parts = import_target.split(".")
        if module_parts and module_parts[-1] == func_simple:
            module = ".".join(module_parts[:-1])
        else:
            module = import_target

        module_path = module.replace(".", "/")
        candidates = self.function_index.get(func_simple) or []
        scored: List[Tuple[str, FunctionInfo]] = []
        for file, fn in candidates:
            norm = file.replace("\\", "/")
            if norm == f"{module_path}.py" or norm.endswith(f"/{module_path}.py"):
                scored.append((file, fn))
            elif module_path and module_path in norm:
                scored.append((file, fn))
        if scored:
            return scored[0]

        for file, fn in self.function_index.get(func_simple) or []:
            if fn.name == func_simple:
                if module_path.split("/")[0] in file.replace("\\", "/"):
                    return file, fn
        return None
