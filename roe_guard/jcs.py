"""RFC 8785 (JCS) canonicalization subset for audit hashing (SPEC §14.7).

Only the value set the audit records need is supported: strings, integers
with |n| ≤ 2^53−1, booleans, null, string-keyed objects and arrays.
Floats, other types and non-string keys raise ``TypeError``; out-of-range
integers, lone surrogates and nesting deeper than 64 objects/arrays raise
``ValueError``. Only the stdlib is used.
"""

from __future__ import annotations

import json
from typing import Any

_MAX_SAFE_INTEGER = 2**53 - 1
# A fixed bound keeps the result independent of the caller's stack depth.
MAX_DEPTH = 64


def _sort_key(key: str) -> bytes:
    """UTF-16 code-unit ordering per RFC 8785 §3.2.3."""
    return key.encode("utf-16-be")


def _dump_string(value: str) -> str:
    # json.dumps with ensure_ascii=False uses exactly the RFC 8785 escaping
    # rules for the characters JCS escapes (", \, control chars).
    return json.dumps(value, ensure_ascii=False)


def canonicalize(value: object) -> bytes:
    """Return the RFC 8785 canonical UTF-8 serialization of *value*."""
    # A lone surrogate fails here: UnicodeEncodeError is a ValueError.
    return _canonical(value, 0).encode("utf-8")


def _canonical(value: Any, depth: int) -> str:
    if value is True:
        return "true"
    if value is False:
        return "false"
    if value is None:
        return "null"
    if isinstance(value, str):
        return _dump_string(value)
    if isinstance(value, int):
        if abs(value) > _MAX_SAFE_INTEGER:
            raise ValueError(f"integer out of the safe range: {value}")
        # int.__repr__ keeps int subclasses (IntEnum) numeric on every
        # Python version; str() would not.
        return int.__repr__(value)
    if isinstance(value, (list, dict)):
        depth += 1
        if depth > MAX_DEPTH:
            raise ValueError(f"nesting deeper than {MAX_DEPTH} objects/arrays")
    if isinstance(value, list):
        return "[" + ",".join([_canonical(item, depth) for item in value]) + "]"
    if isinstance(value, dict):
        for key in value:
            if not isinstance(key, str):
                raise TypeError(
                    f"object keys must be strings, got {type(key).__name__}"
                )
        items = []
        for key in sorted(value, key=_sort_key):
            items.append(_dump_string(key) + ":" + _canonical(value[key], depth))
        return "{" + ",".join(items) + "}"
    raise TypeError(f"unsupported type for JCS: {type(value).__name__}")


__all__ = ["canonicalize"]
