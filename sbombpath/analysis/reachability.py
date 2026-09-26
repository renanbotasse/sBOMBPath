"""Map HTTP routes to views (Django/DRF-oriented)."""

from __future__ import annotations

import ast
from typing import Dict, List, Optional, Tuple

from ..collect import CodebaseFacts, FileFacts, expr_to_str
from ..models import Endpoint


HTTP_METHODS = {"get", "post", "put", "patch", "delete", "head", "options"}


def _extract_route(node: ast.Call) -> Tuple[Optional[str], Optional[str], List[str]]:
    route = None
    view_name = None
    methods = ["GET", "POST"]

    if node.args:
        if isinstance(node.args[0], ast.Constant):
            route = str(node.args[0].value)
            if not route.startswith("/"):
                route = "/" + route
        if len(node.args) >= 2:
            view_expr = expr_to_str(node.args[1])
            view_name = view_expr.replace(".as_view()", "").strip().split(".")[-1]

    for kw in node.keywords:
        if kw.arg == "view":
            view_name = expr_to_str(kw.value).replace(".as_view()", "").split(".")[-1]

    if view_name:
        methods = ["GET", "POST", "PUT", "PATCH", "DELETE"]
    return route, view_name, methods


class ReachabilityAnalyzer:
    def __init__(self, codebase: CodebaseFacts) -> None:
        self.codebase = codebase
        self.endpoints: List[Endpoint] = []
        self.view_to_endpoints: Dict[str, List[Endpoint]] = {}
        self._discover()

    def _discover(self) -> None:
        for ff in self.codebase.files.values():
            self.endpoints.extend(self._parse_urls(ff))
        for ep in self.endpoints:
            view_key = ep.view.split(".")[-1]
            self.view_to_endpoints.setdefault(view_key, []).append(ep)
            self.view_to_endpoints.setdefault(ep.view, []).append(ep)

    def _parse_urls(self, ff: FileFacts) -> List[Endpoint]:
        found: List[Endpoint] = []

        class Visitor(ast.NodeVisitor):
            def visit_Call(self, node: ast.Call) -> None:
                fname = expr_to_str(node.func)
                simple = fname.split(".")[-1]
                if simple in {"path", "re_path", "url"}:
                    route, view_name, methods = _extract_route(node)
                    if view_name:
                        for method in methods:
                            found.append(
                                Endpoint(
                                    method=method,
                                    path=route or "/?",
                                    view=view_name,
                                    location=f"{ff.path}:{node.lineno}",
                                )
                            )
                elif simple == "register" and node.args:
                    prefix = None
                    view_name = None
                    if isinstance(node.args[0], ast.Constant):
                        prefix = str(node.args[0].value)
                    if len(node.args) >= 2:
                        view_name = expr_to_str(node.args[1]).replace(".as_view()", "")
                    if prefix is not None and view_name:
                        for method in ("GET", "POST", "PUT", "PATCH", "DELETE"):
                            found.append(
                                Endpoint(
                                    method=method,
                                    path=f"/api/{prefix.strip('/')}/",
                                    view=view_name.split(".")[-1],
                                    location=f"{ff.path}:{node.lineno}",
                                )
                            )
                self.generic_visit(node)

        Visitor().visit(ff.tree)
        return found

    def endpoints_for_function(
        self, function: Optional[str], class_name: Optional[str]
    ) -> List[Endpoint]:
        if not function and not class_name:
            return []
        keys: List[str] = []
        if class_name:
            keys.append(class_name)
        if function:
            keys.append(function)
            keys.append(function.split(".")[-1])
            if "." in function:
                keys.append(function.split(".")[0])

        results: List[Endpoint] = []
        seen = set()
        for key in keys:
            for ep in self.view_to_endpoints.get(key, []):
                sig = (ep.method, ep.path, ep.view)
                if sig not in seen:
                    seen.add(sig)
                    results.append(ep)
        return results

    def describe(
        self, function: Optional[str], class_name: Optional[str]
    ) -> Tuple[Optional[str], bool, str]:
        eps = self.endpoints_for_function(function, class_name)
        if not eps:
            if function and "." in function:
                method = function.split(".")[-1].upper()
                if method.lower() in HTTP_METHODS and class_name:
                    return (
                        f"{method} /<unmapped>",
                        False,
                        f"{method} /<unmapped> → {function} (URL pattern not found)",
                    )
            return None, False, "No HTTP route mapped to this code path"

        ep = eps[0]
        if function and "." in function:
            method = function.split(".")[-1].upper()
            for candidate in eps:
                if candidate.method == method:
                    ep = candidate
                    break

        desc = f"{ep.label} → {ep.view}"
        if function:
            if "." in function:
                desc += f".{function.split('.')[-1]}()"
            else:
                desc += f" → {function}()"
        return ep.label, True, desc
