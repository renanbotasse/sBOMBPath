"""Variable keys for the data-flow graph."""

from __future__ import annotations

import re
from typing import Optional, Tuple

VarKey = str  # "file::function::varname"


def var_key(file: str, function: Optional[str], name: str) -> VarKey:
    return f"{file}::{function or '<module>'}::{name}"


def re_ident_in(name: str, expr: str) -> bool:
    return re.search(rf"\b{re.escape(name)}\b", expr) is not None


def split_key(key: VarKey) -> Tuple[str, Optional[str], str]:
    parts = key.split("::")
    if len(parts) != 3:
        return key, None, key
    file, func, name = parts
    return file, None if func == "<module>" else func, name
