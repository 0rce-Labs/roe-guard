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

import hashlib
import ipaddress
import re
import warnings
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

from roe_guard.exceptions import PolicyParseError, UnknownKeyWarning
from roe_guard.models import (
    ApprovalSpec,
    BlackoutWindow,
    CredentialSpec,
    EnforcementMode,
    FilesystemSpec,
    Policy,
    ResourceSpec,
    SandboxSpec,
    Scope,
    ScopeEntry,
    SyscallSpec,
)

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
        "mode",
        "sandbox",
        "approval",
    }
)
_V2_RESERVED_TOP = frozenset({"mode", "agent", "sandbox", "egress", "approval"})
_SCOPE_KEYS = frozenset({"allow", "deny"})
_SCOPE_ENTRY_KEYS = frozenset({"cidr", "hostname"})
_ACTIONS_KEYS = frozenset({"allow", "deny"})
_BLACKOUT_KEYS = frozenset({"start", "end", "reason"})
_SANDBOX_KEYS = frozenset(
    {"filesystem", "syscalls", "resources", "credentials", "imds"}
)
_FILESYSTEM_KEYS = frozenset({"read", "write", "deny"})
_SYSCALL_KEYS = frozenset({"profile", "deny"})
_RESOURCE_KEYS = frozenset({"pids_max", "memory_max", "cpu_max"})
_CREDENTIAL_KEYS = frozenset({"max_ttl_seconds"})
_APPROVAL_KEYS = frozenset({"timeout_seconds", "on_timeout"})
_INT_VALUE_RE = re.compile(r"^[0-9]+$", re.ASCII)


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
          for v1 the top-level keys ``mode``, ``agent``, ``sandbox``, ``egress``
          and ``approval`` are rejected and other unknown keys are ignored.
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
    # stacklevel 3: load_policy -> _load_policy -> warnings.warn, so the
    # warning points at the code that called load_policy.
    return _load_policy(path, _stacklevel=3)


def parse_policy(raw: dict[str, Any]) -> Policy:
    """Validate an already-parsed policy mapping and build the Policy.

    All structural validation lives here; :func:`load_policy` only reads
    the file, decodes it and attaches ``source_sha256``.

    Raises:
        roe_guard.exceptions.PolicyParseError: On any structural or
            semantic validation failure.
    """
    # parse_policy callers receive warnings with the default stacklevel:
    # _parse_policy -> warnings.warn is one frame deep.
    return _parse_policy(raw, _stacklevel=2)


def _load_policy(path: str | Path, *, _stacklevel: int) -> Policy:
    """Implementation of :func:`load_policy`; ``_stacklevel`` targets the user call site."""
    p = Path(path)
    if not p.exists():
        raise PolicyParseError(f"policy file not found: {p}", field=str(p))

    data = p.read_bytes()
    sha = hashlib.sha256(data).hexdigest()
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise PolicyParseError(
            f"policy file is not valid UTF-8: {exc}", field=str(p)
        ) from exc

    try:
        raw = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise PolicyParseError(f"YAML syntax error: {exc}", field=str(p)) from exc

    if raw is None:
        raise PolicyParseError("policy file is empty", field=str(p))
    if not isinstance(raw, dict):
        raise PolicyParseError(
            f"top-level YAML must be a mapping, got {type(raw).__name__}",
            field=str(p),
        )

    # +1 frame: load_policy -> _load_policy -> _parse_policy -> warn.
    policy = _parse_policy(raw, _stacklevel=_stacklevel + 1)
    if policy.source_sha256:
        raise PolicyParseError("source_sha256 already set", field="<top>")
    from dataclasses import replace as _dc_replace

    return _dc_replace(policy, source_sha256=sha)


def _parse_policy(raw: dict[str, Any], *, _stacklevel: int) -> Policy:
    """Structural + semantic validation shared by file and mapping input."""

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
        warnings.warn(
            f"unknown key ignored: {full}", UnknownKeyWarning, stacklevel=_stacklevel
        )

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

    if schema_version >= 2 and not isinstance(raw["scope"], dict):
        raise PolicyParseError(
            f"'scope' must be a mapping, got {type(raw['scope']).__name__}",
            field="scope",
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

    # --- mode (v2; default enforce) --------------------------------------
    mode_raw = raw.get("mode")
    if mode_raw is None or mode_raw == "enforce":
        mode = EnforcementMode.ENFORCE
    elif mode_raw == "observe":
        mode = EnforcementMode.OBSERVE
    else:
        raise PolicyParseError(
            f"'mode' must be 'enforce' or 'observe', got {mode_raw!r}",
            field="mode",
        )

    # --- sandbox (v2) -----------------------------------------------------
    sandbox = _parse_sandbox(raw.get("sandbox")) if "sandbox" in raw else None

    # --- approval (v2) ----------------------------------------------------
    approval = _parse_approval(raw.get("approval")) if "approval" in raw else None

    # --- top-level x-* extensions (v1 and v2) ------------------------------
    extensions = {
        key: value
        for key, value in raw.items()
        if isinstance(key, str) and key.startswith("x-")
    }

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
        mode=mode,
        sandbox=sandbox,
        approval=approval,
        extensions=extensions,
    )


def _require_int(value: Any, *, field: str) -> int:
    """Strict positive-int check: no bool, no integral float (256.0)."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise PolicyParseError(
            f"'{field}' must be an integer, got {type(value).__name__}",
            field=field,
        )
    if value < 1:
        raise PolicyParseError(f"'{field}' must be >= 1, got {value}", field=field)
    return value


def _parse_str_tuple_list(value: Any, *, field: str) -> tuple[str, ...]:
    """v2 string lists: list of non-empty strings; null is NOT accepted."""
    if not isinstance(value, list):
        raise PolicyParseError(
            f"'{field}' must be a list, got {type(value).__name__}",
            field=field,
        )
    items = []
    for idx, item in enumerate(value):
        if not isinstance(item, str) or not item:
            raise PolicyParseError(
                f"'{field}[{idx}]' must be a non-empty string, got {item!r}",
                field=f"{field}[{idx}]",
            )
        items.append(item)
    return tuple(items)


def _parse_sandbox(raw: Any) -> SandboxSpec:
    if not isinstance(raw, dict):
        raise PolicyParseError(
            f"'sandbox' must be a mapping, got {type(raw).__name__}",
            field="sandbox",
        )
    _check_keys(
        raw,
        _SANDBOX_KEYS,
        path="sandbox",
        strict=raw.get("schema_version", 1) >= 2,
        ignored=[],
    )
    filesystem = None
    if "filesystem" in raw:
        fs = raw["filesystem"]
        if not isinstance(fs, dict):
            raise PolicyParseError(
                f"'sandbox.filesystem' must be a mapping, got {type(fs).__name__}",
                field="sandbox.filesystem",
            )
        _check_keys(
            fs, _FILESYSTEM_KEYS, path="sandbox.filesystem", strict=True, ignored=[]
        )
        filesystem = FilesystemSpec(
            read=_parse_str_tuple_list(
                fs.get("read", []), field="sandbox.filesystem.read"
            ),
            write=_parse_str_tuple_list(
                fs.get("write", []), field="sandbox.filesystem.write"
            ),
            deny=_parse_str_tuple_list(
                fs.get("deny", []), field="sandbox.filesystem.deny"
            ),
        )
    syscalls = None
    if "syscalls" in raw:
        sc = raw["syscalls"]
        if not isinstance(sc, dict):
            raise PolicyParseError(
                f"'sandbox.syscalls' must be a mapping, got {type(sc).__name__}",
                field="sandbox.syscalls",
            )
        _check_keys(sc, _SYSCALL_KEYS, path="sandbox.syscalls", strict=True, ignored=[])
        profile = sc.get("profile")
        if profile is not None and (not isinstance(profile, str) or not profile):
            raise PolicyParseError(
                f"'sandbox.syscalls.profile' must be a non-empty string, got {profile!r}",
                field="sandbox.syscalls.profile",
            )
        syscalls = SyscallSpec(
            profile=profile,
            deny=_parse_str_tuple_list(
                sc.get("deny", []), field="sandbox.syscalls.deny"
            ),
        )
    resources = None
    if "resources" in raw:
        rs = raw["resources"]
        if not isinstance(rs, dict):
            raise PolicyParseError(
                f"'sandbox.resources' must be a mapping, got {type(rs).__name__}",
                field="sandbox.resources",
            )
        _check_keys(
            rs, _RESOURCE_KEYS, path="sandbox.resources", strict=True, ignored=[]
        )
        pids_max = (
            _require_int(rs["pids_max"], field="sandbox.resources.pids_max")
            if "pids_max" in rs
            else None
        )
        memory_max = rs.get("memory_max")
        if memory_max is not None and (
            not isinstance(memory_max, str) or not memory_max
        ):
            raise PolicyParseError(
                f"'sandbox.resources.memory_max' must be a non-empty string, got {memory_max!r}",
                field="sandbox.resources.memory_max",
            )
        cpu_max = rs.get("cpu_max")
        if cpu_max is not None and (not isinstance(cpu_max, str) or not cpu_max):
            raise PolicyParseError(
                f"'sandbox.resources.cpu_max' must be a non-empty string, got {cpu_max!r}",
                field="sandbox.resources.cpu_max",
            )
        resources = ResourceSpec(
            pids_max=pids_max, memory_max=memory_max, cpu_max=cpu_max
        )
    credentials = None
    if "credentials" in raw:
        cr = raw["credentials"]
        if not isinstance(cr, dict):
            raise PolicyParseError(
                f"'sandbox.credentials' must be a mapping, got {type(cr).__name__}",
                field="sandbox.credentials",
            )
        _check_keys(
            cr, _CREDENTIAL_KEYS, path="sandbox.credentials", strict=True, ignored=[]
        )
        max_ttl = (
            _require_int(
                cr["max_ttl_seconds"], field="sandbox.credentials.max_ttl_seconds"
            )
            if "max_ttl_seconds" in cr
            else None
        )
        credentials = CredentialSpec(max_ttl_seconds=max_ttl)
    imds = raw.get("imds", "deny")
    if imds != "deny":
        raise PolicyParseError(
            f"'sandbox.imds' accepts only 'deny', got {imds!r}",
            field="sandbox.imds",
        )
    return SandboxSpec(
        filesystem=filesystem,
        syscalls=syscalls,
        resources=resources,
        credentials=credentials,
        imds=imds,
    )


def _parse_approval(raw: Any) -> ApprovalSpec:
    if not isinstance(raw, dict):
        raise PolicyParseError(
            f"'approval' must be a mapping, got {type(raw).__name__}",
            field="approval",
        )
    _check_keys(raw, _APPROVAL_KEYS, path="approval", strict=True, ignored=[])
    if "timeout_seconds" not in raw:
        raise PolicyParseError(
            "missing required field: approval.timeout_seconds",
            field="approval.timeout_seconds",
        )
    timeout_seconds = _require_int(
        raw["timeout_seconds"], field="approval.timeout_seconds"
    )
    on_timeout = raw.get("on_timeout", "deny")
    if on_timeout != "deny":
        raise PolicyParseError(
            f"'approval.on_timeout' accepts only 'deny', got {on_timeout!r}",
            field="approval.on_timeout",
        )
    return ApprovalSpec(timeout_seconds=timeout_seconds, on_timeout=on_timeout)


__all__ = ["MAX_SCHEMA_VERSION", "load_policy", "parse_policy"]
