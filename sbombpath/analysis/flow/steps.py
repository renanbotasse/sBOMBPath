"""Convert flow edges into report FlowStep lists."""

from __future__ import annotations

from typing import List, Optional, Set, Tuple

from ...collect import CallFact
from ...models import FlowStep, TaintSource

from .types import FlowEdge


def edges_to_steps(
    source: TaintSource, edge_path: List[FlowEdge], call: CallFact
) -> List[FlowStep]:
    steps: List[FlowStep] = [
        FlowStep(
            step=1,
            type="source",
            location=source.location,
            code=source.expression,
            var=source.var,
        )
    ]
    step_no = 2
    seen_param: Set[Tuple[str, Optional[str]]] = set()
    for edge in edge_path:
        if edge.kind == "parameter":
            key = (edge.location, edge.meta.get("param_name"))
            if key in seen_param:
                continue
            seen_param.add(key)
            steps.append(
                FlowStep(
                    step=step_no,
                    type="parameter",
                    location=edge.location,
                    code=edge.code,
                    param_name=edge.meta.get("param_name"),
                    function=edge.meta.get("function"),
                )
            )
        elif edge.kind == "function_call":
            arg_pos = edge.meta.get("arg_position")
            steps.append(
                FlowStep(
                    step=step_no,
                    type="function_call",
                    location=edge.location,
                    code=edge.code,
                    function=edge.meta.get("function"),
                    arg_position=int(arg_pos) if arg_pos is not None else None,
                    param_name=edge.meta.get("param_name"),
                )
            )
        elif edge.kind == "kwargs_unpack":
            steps.append(
                FlowStep(
                    step=step_no,
                    type="assignment",
                    location=edge.location,
                    code=edge.code,
                    var=edge.meta.get("sink_candidate"),
                    pattern_matched="**kwargs",
                )
            )
        else:
            steps.append(
                FlowStep(
                    step=step_no,
                    type=edge.kind,
                    location=edge.location,
                    code=edge.code,
                    var=edge.meta.get("var") or edge.meta.get("assigned_to"),
                )
            )
        step_no += 1

    steps.append(
        FlowStep(
            step=step_no,
            type="sink",
            location=f"{call.file}:{call.lineno}",
            code=call.full_expr,
            function=call.func_name,
            pattern_matched="**kwargs" if call.has_kwargs else "tainted_arg",
        )
    )
    return steps
