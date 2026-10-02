"""
roe_guard.policy

YAML policy loading and schema validation (spec §5).

The public entry point is :func:`load_policy` (``MAX_SCHEMA_VERSION`` is the
highest supported policy ``schema_version``), which:
    - reads a YAML file with ``yaml.safe_load`` (never ``yaml.load`` — RCE risk),
    - rejects an unsupported ``schema_version`` right after the top-level
      mapping check, before the required-field checks,
    - checks keys per level: for ``schema_version >= 2`` an unknown key
      (other than ``x-*``) is rejected; for v1 the v2-reserved top-level
      blocks are rejected and other unknown keys raise
      :class:`~roe_guard.exceptions.UnknownKeyWarning` and are ignored,
    - validates the top-level structure against spec §5,
    - converts ISO-8601 timestamps to timezone-aware UTC datetimes,
    - validates every CIDR with :func:`ipaddress.ip_network`,
    - builds the immutable :class:`~roe_guard.models.Policy` object.

All failures raise :class:`~roe_guard.exceptions.PolicyParseError`.
"""

from __future__ import annotations

import ipaddress
import warnings
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

from roe_guard.exceptions import PolicyParseError, UnknownKeyWarning
from roe_guard.models import BlackoutWindow, Policy, Scope, ScopeEntry

_REQUIRED_TOP_LEVEL = ("engagement_id", "valid_from", "valid_until", "scope")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _parse_iso8601_utc(value: str, *, field: str) -> datetime:
    """Parse an ISO-8601 string into a timezone-aware UTC datetime.

    Accepts trailing ``Z`` as UTC (Python's ``fromisoformat`` before 3.11
    does not).  Raises :class:`PolicyParseError` with field context on
    failure.
    """
    if not isinstance(value, str) or not value:
        raise PolicyParseError(
            f"expected non-empty ISO-8601 string, got {value!r}", field=field
        )
    # Normalise 'Z' suffix to '+00:00' for cross-version compatibility.
    normalised = value.replace("Z", "+00:00") if value.endswith("Z") else value
    try:
        dt = datetime.fromisoformat(normalised)
    except (TypeError, ValueError) as exc:
        raise PolicyParseError(
            f"invalid ISO-8601 timestamp {value!r}: {exc}", field=field
        ) from exc
    if dt.tzinfo is None:
        # Naive datetimes are ambiguous; coerce to UTC per spec.
        dt = dt.replace(tzinfo=timezone.utc)
    else:
        dt = dt.astimezone(timezone.utc)
    return dt


def _validate_cidr(value: Any, *, field: str) -> str:
    """Return the CIDR string after validating it with :mod:`ipaddress`."""
    if not isinstance(value, str) or not value:
        raise PolicyParseError(
            f"expected non-empty CIDR string, got {value!r}", field=field
        )
    try:
        ipaddress.ip_network(value, strict=False)
    except ValueError as exc:
        raise PolicyParseError(f"invalid CIDR {value!r}: {exc}", field=field) from exc
    return value


def _parse_scope_entry(entry: Any, *, field_prefix: str, index: int) -> ScopeEntry:
    """Validate and convert one scope entry (dict)."""
    if not isinstance(entry, dict):
        raise PolicyParseError(
            f"expected mapping, got {type(entry).__name__}",
            field=f"{field_prefix}[{index}]",
        )
    if "cidr" in entry and "hostname" in entry:
        raise PolicyParseError(
            "scope entry must contain exactly one of 'cidr' or 'hostname'",
            field=f"{field_prefix}[{index}]",
        )

    cidr = entry.get("cidr")
    hostname = entry.get("hostname")
    field = f"{field_prefix}[{index}]"

    try:
        if cidr is not None:
            return ScopeEntry(cidr=_validate_cidr(cidr, field=field + ".cidr"))
        if hostname is not None:
            if not isinstance(hostname, str) or not hostname:
                raise PolicyParseError(
                    f"expected non-empty hostname string, got {hostname!r}",
                    field=field + ".hostname",
                )
            return ScopeEntry(hostname=hostname)
    except PolicyParseError:
        raise
    except ValueError as exc:  # ScopeEntry __post_init__ validation
        raise PolicyParseError(str(exc), field=field) from exc

    raise PolicyParseError(
        "scope entry must contain at least one of 'cidr' or 'hostname'",
        field=field,
    )


def _parse_scope(scope: Any) -> Scope:
    if not isinstance(scope, dict):
        raise PolicyParseError(
            f"'scope' must be a mapping, got {type(scope).__name__}", field="scope"
        )
    allow_raw = scope.get("allow", []) or []
    deny_raw = scope.get("deny", []) or []
    if not isinstance(allow_raw, list):
        raise PolicyParseError("'scope.allow' must be a list", field="scope.allow")
    if not isinstance(deny_raw, list):
        raise PolicyParseError("'scope.deny' must be a list", field="scope.deny")

    allow = [
        _parse_scope_entry(e, field_prefix="scope.allow", index=i)
        for i, e in enumerate(allow_raw)
    ]
    deny = [
        _parse_scope_entry(e, field_prefix="scope.deny", index=i)
        for i, e in enumerate(deny_raw)
    ]
    return Scope(allow=allow, deny=deny)


def _parse_blackout_window(bw: Any, *, index: int) -> BlackoutWindow:
    field = f"blackout_windows[{index}]"
    if not isinstance(bw, dict):
        raise PolicyParseError(
            f"expected mapping, got {type(bw).__name__}", field=field
        )
    try:
        start = _parse_iso8601_utc(bw["start"], field=field + ".start")
        end = _parse_iso8601_utc(bw["end"], field=field + ".end")
    except KeyError as exc:
        raise PolicyParseError(
            f"missing required field {exc.args[0]!r}", field=field
        ) from exc
    if not (start < end):
        raise PolicyParseError(
            f"start ({start.isoformat()}) must be strictly before end "
            f"({end.isoformat()})",
            field=field,
        )
    reason = bw.get("reason", "") or ""
    if not isinstance(reason, str):
        raise PolicyParseError(
            f"'reason' must be a string, got {type(reason).__name__}",
            field=field + ".reason",
        )
    return BlackoutWindow(start=start, end=end, reason=reason)


def _parse_str_list(value: Any, *, field: str) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise PolicyParseError(
            f"expected list, got {type(value).__name__}", field=field
        )
    out: list[str] = []
    for i, item in enumerate(value):
        if not isinstance(item, str) or not item:
            raise PolicyParseError(
                f"expected non-empty string, got {item!r}",
                field=f"{field}[{i}]",
            )
        out.append(item)
    return out


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

MAX_SCHEMA_VERSION = 2

_TOP_KEYS = frozenset(
    {
        "engagement_id",
        "valid_from",
        "valid_until",
        "scope",
        "actions",
        "blackout_windows",
        "approval_required_for",
        "approvers",
        "schema_version",
    }
)
_V2_RESERVED_TOP = frozenset({"mode", "agent", "sandbox", "egress", "approval"})
_SCOPE_KEYS = frozenset({"allow", "deny"})
_SCOPE_ENTRY_KEYS = frozenset({"cidr", "hostname"})
_ACTIONS_KEYS = frozenset({"allow", "deny"})
_BLACKOUT_KEYS = frozenset({"start", "end", "reason"})


def _check_keys(
    mapping: dict[Any, Any],
    allowed: frozenset[str],
    *,
    path: str,
    strict: bool,
    ignored: list[str],
) -> None:
    """Reject unknown keys (strict) or collect them in ``ignored`` (v1).

    ``x-*`` keys are skipped. The caller warns for the collected paths so
    the warning points at the code that loaded the policy.
    """
    for key in mapping:
        if isinstance(key, str) and key.startswith("x-"):
            continue
        if key in allowed:
            continue
        full = f"{path}.{key}" if path else str(key)
        if strict:
            raise PolicyParseError(
                f"unknown key: {full}",
                field=full,
            )
        ignored.append(full)


def _parse_schema_version(raw: dict[str, Any]) -> int:
    """Validate the optional ``schema_version`` key (fail-closed).

    Missing means ``1``. Anything that is not an ``int`` in
    ``[1, MAX_SCHEMA_VERSION]`` (bools explicitly excluded) raises
    :class:`PolicyParseError` with ``field="schema_version"``.
    """
    v = raw.get("schema_version", 1)
    if isinstance(v, bool) or not isinstance(v, int):
        raise PolicyParseError(
            f"schema_version must be an integer, got {type(v).__name__}",
            field="schema_version",
        )
    if v < 1 or v > MAX_SCHEMA_VERSION:
        raise PolicyParseError(
            f"unsupported schema_version {v} (this roe-guard supports up to {MAX_SCHEMA_VERSION})",
            field="schema_version",
        )
    return v


def load_policy(path: str | Path) -> Policy:
    """Load and validate a policy from a YAML file (spec §5).

    Uses ``yaml.safe_load`` (never ``yaml.load``) to eliminate RCE risk.

    Validates:
        - ``schema_version`` (optional int in ``[1, MAX_SCHEMA_VERSION]``),
          checked before the required fields.
        - Keys per level: unknown keys (except ``x-*``) are rejected for
          ``schema_version >= 2`` with ``field`` set to the dotted path;
          for v1 the keys ``mode``, ``agent``, ``sandbox``, ``egress`` and
          ``approval`` are rejected and other unknown keys are ignored.
        - Required top-level fields (``engagement_id``, ``valid_from``,
          ``valid_until``, ``scope``).
        - ISO-8601 datetime format for all timestamps (timezone-aware UTC).
        - CIDR validity for every ``cidr`` entry via :mod:`ipaddress`.
        - Every scope entry has exactly one of ``cidr`` / ``hostname``.

    Args:
        path: Path to the policy YAML file.

    Returns:
        A fully-populated, immutable :class:`~roe_guard.models.Policy`.

    Warns:
        roe_guard.exceptions.UnknownKeyWarning: For each unknown key that
            a v1 policy ignores.

    Raises:
        roe_guard.exceptions.PolicyParseError: On any structural or
            semantic validation failure (unsupported ``schema_version``,
            missing fields, invalid dates, invalid CIDR, malformed YAML, or
            empty scope entry).
    """
    p = Path(path)
    if not p.exists():
        raise PolicyParseError(f"policy file not found: {p}", field=str(p))

    try:
        with p.open("r", encoding="utf-8") as fh:
            raw = yaml.safe_load(fh)
    except yaml.YAMLError as exc:
        raise PolicyParseError(f"YAML syntax error: {exc}", field=str(p)) from exc

    if raw is None:
        raise PolicyParseError("policy file is empty", field=str(p))
    if not isinstance(raw, dict):
        raise PolicyParseError(
            f"top-level YAML must be a mapping, got {type(raw).__name__}",
            field=str(p),
        )

    # --- Schema version (before required fields; fail-closed) -----------
    schema_version = _parse_schema_version(raw)
    strict = schema_version >= 2

    if not strict:
        # Document order keeps the reported field stable across runs.
        for key in raw:
            if key in _V2_RESERVED_TOP:
                raise PolicyParseError(
                    f"'{key}' requires schema_version: 2",
                    field=key,
                )

    # --- Unknown-key validation (per level; x-* skipped) ----------------
    ignored: list[str] = []
    _check_keys(raw, _TOP_KEYS, path="", strict=strict, ignored=ignored)
    scope_raw = raw.get("scope", {})
    if isinstance(scope_raw, dict):
        _check_keys(
            scope_raw, _SCOPE_KEYS, path="scope", strict=strict, ignored=ignored
        )
        for list_key in ("allow", "deny"):
            entries = scope_raw.get(list_key, [])
            if isinstance(entries, list):
                for idx, entry in enumerate(entries):
                    if isinstance(entry, dict):
                        _check_keys(
                            entry,
                            _SCOPE_ENTRY_KEYS,
                            path=f"scope.{list_key}[{idx}]",
                            strict=strict,
                            ignored=ignored,
                        )
    actions_raw = raw.get("actions", {})
    if isinstance(actions_raw, dict):
        _check_keys(
            actions_raw, _ACTIONS_KEYS, path="actions", strict=strict, ignored=ignored
        )
    windows = raw.get("blackout_windows", [])
    if isinstance(windows, list):
        for idx, window in enumerate(windows):
            if isinstance(window, dict):
                _check_keys(
                    window,
                    _BLACKOUT_KEYS,
                    path=f"blackout_windows[{idx}]",
                    strict=strict,
                    ignored=ignored,
                )
    for full in ignored:
        warnings.warn(f"unknown key ignored: {full}", UnknownKeyWarning, stacklevel=2)

    # --- Required fields ------------------------------------------------
    missing = [f for f in _REQUIRED_TOP_LEVEL if f not in raw]
    if missing:
        raise PolicyParseError(
            f"missing required field(s): {', '.join(missing)}",
            field="<top>",
        )

    engagement_id = raw["engagement_id"]
    if not isinstance(engagement_id, str) or not engagement_id:
        raise PolicyParseError(
            "'engagement_id' must be a non-empty string",
            field="engagement_id",
        )

    valid_from = _parse_iso8601_utc(raw["valid_from"], field="valid_from")
    valid_until = _parse_iso8601_utc(raw["valid_until"], field="valid_until")
    if not (valid_from < valid_until):
        raise PolicyParseError(
            f"valid_from ({valid_from.isoformat()}) must be strictly before "
            f"valid_until ({valid_until.isoformat()})",
            field="valid_from/valid_until",
        )

    scope = _parse_scope(raw["scope"])

    # --- Optional fields (default to empty) ----------------------------
    actions = raw.get("actions", {}) or {}
    if not isinstance(actions, dict):
        raise PolicyParseError(
            f"'actions' must be a mapping, got {type(actions).__name__}",
            field="actions",
        )
    actions_allow = _parse_str_list(actions.get("allow", []), field="actions.allow")
    actions_deny = _parse_str_list(actions.get("deny", []), field="actions.deny")

    blackout_raw = raw.get("blackout_windows", []) or []
    if not isinstance(blackout_raw, list):
        raise PolicyParseError(
            f"'blackout_windows' must be a list, got {type(blackout_raw).__name__}",
            field="blackout_windows",
        )
    blackout_windows = [
        _parse_blackout_window(bw, index=i) for i, bw in enumerate(blackout_raw)
    ]

    approval_required_for = _parse_str_list(
        raw.get("approval_required_for", []), field="approval_required_for"
    )
    approvers = _parse_str_list(raw.get("approvers", []), field="approvers")

    return Policy(
        engagement_id=engagement_id,
        valid_from=valid_from,
        valid_until=valid_until,
        scope=scope,
        actions_allow=actions_allow,
        actions_deny=actions_deny,
        blackout_windows=blackout_windows,
        approval_required_for=approval_required_for,
        approvers=approvers,
        schema_version=schema_version,
    )


__all__ = ["MAX_SCHEMA_VERSION", "load_policy"]
