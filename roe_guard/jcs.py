"""RFC 8785 (JCS) canonicalization subset for audit hashing (SPEC §14.7).

Only the value set the audit records need is supported: strings, integers
with |n| ≤ 2^53−1, booleans, null, string-keyed objects and arrays.
Floats and other types raise ``TypeError``; out-of-range integers, non-
string keys and lone surrogates raise ``ValueError``. Only the stdlib is
used.
"""

from __future__ import annotations

import json
from typing import Any

_MAX_SAFE_INTEGER = 2**53 - 1


def _sort_key(key: str) -> bytes:
    """UTF-16 code-unit ordering per RFC 8785 §3.2.3."""
    return key.encode("utf-16-be")


def _dump_string(value: str) -> str:
    # json.dumps with ensure_ascii=False uses exactly the RFC 8785 escaping
    # rules for the characters JCS escapes (", \, control chars).
    return json.dumps(value, ensure_ascii=False)


def canonicalize(value: object) -> bytes:
    """Return the RFC 8785 canonical UTF-8 serialization of *value*."""
    return _canonical(value).encode("utf-8")


def _canonical(value: Any) -> str:
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
        return str(value)
    if isinstance(value, list):
        return "[" + ",".join(_canonical(item) for item in value) + "]"
    if isinstance(value, dict):
        for key in value:
            if not isinstance(key, str):
                raise TypeError(
                    f"object keys must be strings, got {type(key).__name__}"
                )
        items = []
        for key in sorted(value, key=_sort_key):
            # Reading value[key] raises ValueError for lone surrogates via
            # the recursive string path; keys are validated above.
            items.append(_dump_string(key) + ":" + _canonical(value[key]))
        return "{" + ",".join(items) + "}"
    raise TypeError(f"unsupported type for JCS: {type(value).__name__}")


__all__ = ["canonicalize"]
