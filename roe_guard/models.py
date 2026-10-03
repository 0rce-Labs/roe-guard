"""
roe_guard.models

Core immutable data models for roe-guard.

All dataclasses are frozen (immutable).  Structural validation lives in
``__post_init__`` so that an object can never exist in an invalid state.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any

from roe_guard.exceptions import OutOfScopeError

# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class DecisionType(str, Enum):
    """Possible outcomes of a policy check.

    ALLOW              — the action is permitted.
    DENY               — the action is blocked (fail-closed default).
    REQUIRES_APPROVAL  — the action needs human sign-off before proceeding.
    """

    ALLOW = "ALLOW"
    DENY = "DENY"
    REQUIRES_APPROVAL = "REQUIRES_APPROVAL"


class EnforcementMode(str, Enum):
    """How the platform treats DENY decisions (SPEC §14.3).

    ENFORCE  — DENY blocks the action (default).
    OBSERVE  — the verdict is recorded but the action passes; DENYs are
               still attempt-level signals. Hard-stops stay enforced.
    """

    ENFORCE = "enforce"
    OBSERVE = "observe"


class ReasonCode(str, Enum):
    """Machine-readable ladder step codes (SPEC §14.4); value == name."""

    POLICY_INVALID = "POLICY_INVALID"
    POLICY_NOT_ACTIVE = "POLICY_NOT_ACTIVE"
    BLACKOUT_WINDOW = "BLACKOUT_WINDOW"
    TARGET_DENIED = "TARGET_DENIED"
    TARGET_NOT_IN_SCOPE = "TARGET_NOT_IN_SCOPE"
    ACTION_DENIED = "ACTION_DENIED"
    APPROVAL_REQUIRED = "APPROVAL_REQUIRED"
    ACTION_ALLOWED = "ACTION_ALLOWED"
    ACTION_NOT_ALLOWED = "ACTION_NOT_ALLOWED"
    AGENT_ID_MISSING = "AGENT_ID_MISSING"
    AGENT_ID_MISMATCH = "AGENT_ID_MISMATCH"
    AGENT_RUNTIME_NOT_ALLOWED = "AGENT_RUNTIME_NOT_ALLOWED"


# ---------------------------------------------------------------------------
# v2 sandbox / approval specs (SPEC §14.2) — validated only; enforcement is
# the enforcing platform's job.
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class FilesystemSpec:
    """sandbox.filesystem globs; lists are tuples for deep immutability."""

    read: tuple[str, ...] = ()
    write: tuple[str, ...] = ()
    deny: tuple[str, ...] = ()


@dataclass(frozen=True)
class SyscallSpec:
    """sandbox.syscalls: optional named profile plus denied syscalls."""

    profile: str | None = None
    deny: tuple[str, ...] = ()


@dataclass(frozen=True)
class ResourceSpec:
    """sandbox.resources: cgroup-level limits (validated only)."""

    pids_max: int | None = None
    memory_max: str | None = None
    cpu_max: str | None = None


@dataclass(frozen=True)
class CredentialSpec:
    """sandbox.credentials: short-lived credential ceiling (validated only)."""

    max_ttl_seconds: int | None = None


@dataclass(frozen=True)
class AgentSpec:
    """agent block: caller identity glob plus optional runtime allowlist."""

    id: str
    runtime: tuple[str, ...] = ()


@dataclass(frozen=True)
class AgentIdentity:
    """Caller-supplied identity; roe-guard only matches it, never verifies it."""

    id: str
    runtime: str | None = None


@dataclass(frozen=True)
class SandboxSpec:
    """sandbox block; imds accepts only "deny" (validated in the loader)."""

    filesystem: FilesystemSpec | None = None
    syscalls: SyscallSpec | None = None
    resources: ResourceSpec | None = None
    credentials: CredentialSpec | None = None
    imds: str = "deny"


@dataclass(frozen=True)
class ApprovalSpec:
    """approval block; on_timeout accepts only "deny" (fail-closed)."""

    timeout_seconds: int
    on_timeout: str = "deny"


# ---------------------------------------------------------------------------
# Scope
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ScopeEntry:
    """A single allow/deny entry — exactly one of ``cidr`` / ``hostname``.

    Attributes:
        cidr:     CIDR notation string, e.g. ``"10.20.0.0/16"``.
        hostname: Hostname glob, e.g. ``"*.staging.acme.internal"``.
    """

    cidr: str | None = None
    hostname: str | None = None

    def __post_init__(self) -> None:
        if self.cidr is None and self.hostname is None:
            raise ValueError("ScopeEntry requires at least one of 'cidr' or 'hostname'")


@dataclass(frozen=True)
class Scope:
    """Collection of allowed and denied scope entries.

    ``deny`` always takes precedence over ``allow`` (spec §5).

    Attributes:
        allow: Entries describing permitted targets.
        deny:  Entries describing explicitly forbidden targets (carve-outs).
    """

    allow: list[ScopeEntry] = field(default_factory=list)
    deny: list[ScopeEntry] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Blackout window
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class BlackoutWindow:
    """A time-range during which **all** actions are denied.

    Attributes:
        start:  UTC datetime — window begins (inclusive).
        end:    UTC datetime — window ends (exclusive).
        reason: Human-readable explanation.
    """

    start: datetime
    end: datetime
    reason: str = ""


# ---------------------------------------------------------------------------
# Policy
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Policy:
    """Fully-parsed engagement policy (spec §5 schema).

    Populated by :func:`roe_guard.policy.load_policy` (T3).

    Attributes:
        engagement_id:          Unique identifier for the engagement.
        valid_from:             Engagement start (inclusive, UTC).
        valid_until:            Engagement end (exclusive, UTC).
        scope:                  Allowed/denied targets.
        actions_allow:          Permitted action types.
        actions_deny:           Explicitly denied action types.
        blackout_windows:       Time-ranges where everything is denied.
        approval_required_for:  Action types needing human approval.
        approvers:              Email/identifier list of authorised approvers.
        schema_version:         Policy schema version (1 unless stated).
    """

    engagement_id: str
    valid_from: datetime
    valid_until: datetime
    scope: Scope = field(default_factory=Scope)
    actions_allow: list[str] = field(default_factory=list)
    actions_deny: list[str] = field(default_factory=list)
    blackout_windows: list[BlackoutWindow] = field(default_factory=list)
    approval_required_for: list[str] = field(default_factory=list)
    approvers: list[str] = field(default_factory=list)
    schema_version: int = 1
    mode: EnforcementMode = EnforcementMode.ENFORCE
    sandbox: SandboxSpec | None = None
    approval: ApprovalSpec | None = None
    extensions: dict[str, Any] = field(default_factory=dict)
    source_sha256: str = ""
    agent: AgentSpec | None = None


# ---------------------------------------------------------------------------
# Engagement
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Engagement:
    """A :class:`Policy` bound to a concrete operation context.

    This is the primary user-facing object.  Created from a policy file
    via ``Engagement.from_file()`` and queried with ``check()`` (a thin
    wrapper around :func:`roe_guard.engine.enforce`).

    Attributes:
        policy: The parsed engagement policy.
    """

    policy: Policy

    # --- Public API ------------------------------------------------------

    @classmethod
    def from_file(cls, path: str | Path) -> Engagement:
        """Load a policy from a YAML file and return an :class:`Engagement`.

        Raises :class:`roe_guard.exceptions.PolicyParseError` if the file
        does not exist, is not valid UTF-8 or YAML, or fails policy
        validation (see :func:`roe_guard.policy.load_policy`).  Other OS
        errors (e.g. ``IsADirectoryError``, ``PermissionError``) propagate
        unchanged.  In every failure case no :class:`Engagement` is created.
        """
        from roe_guard.policy import _load_policy

        # stacklevel 3: from_file -> _load_policy -> warnings.warn, so an
        # UnknownKeyWarning points at the code that called from_file.
        return cls(policy=_load_policy(path, _stacklevel=3))

    def check(
        self,
        target: str,
        action_type: str,
        now: datetime | None = None,
        *,
        agent: AgentIdentity | None = None,
    ) -> Decision:
        """Evaluate a single action against the policy.

        Thin wrapper around :func:`roe_guard.engine.enforce` that binds
        the engagement automatically.
        """
        # Local import to avoid circular dependency at module load time.
        from roe_guard.engine import enforce

        return enforce(
            engagement=self,
            target=target,
            action_type=action_type,
            now=now,
            agent=agent,
        )

    def window(self) -> Any:
        """Activate this engagement as a context manager (spec §6).

        Thin wrapper around
        :func:`roe_guard.integrations.context.window`.  Returns a
        context manager so callers can write ``with engagement.window():``.

        Import is local to avoid a circular dependency (integrations
        imports from models).
        """
        from roe_guard.integrations.context import window

        return window(self)


# ---------------------------------------------------------------------------
# Decision
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Decision:
    """The outcome of a single policy evaluation.

    Attributes:
        outcome:     ALLOW, DENY, or REQUIRES_APPROVAL.
        reason:      Human-readable explanation of the decision.
        target:      The evaluated target string.
        action_type: The evaluated action type.
        timestamp:   UTC datetime when the decision was made.
    """

    outcome: DecisionType
    reason: str
    target: str
    action_type: str
    timestamp: datetime
    mode: EnforcementMode = EnforcementMode.ENFORCE
    reason_code: str = ""
    matched_rule: str = ""
    agent_id: str = ""

    @property
    def allowed(self) -> bool:
        """``True`` only when the outcome is ALLOW."""
        return self.outcome is DecisionType.ALLOW

    @property
    def denied(self) -> bool:
        """``True`` only when the outcome is DENY."""
        return self.outcome is DecisionType.DENY

    def raise_if_denied(self) -> None:
        """Raise :class:`OutOfScopeError` if this decision is DENY.

        No-op for ALLOW and REQUIRES_APPROVAL.
        """
        if self.outcome is DecisionType.DENY:
            raise OutOfScopeError(
                f"Denied: target={self.target!r} action={self.action_type!r} "
                f"reason={self.reason}"
            )


# ---------------------------------------------------------------------------
# Audit
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AuditEntry:
    """A single record in the append-only audit chain (T5).

    Mirrors the :class:`Decision` payload (so the audit line is
    self-describing without referring back to other records) and adds
    the hash-chain fields ``prev_hash`` and ``entry_hash``.

    Attributes:
        engagement_id: Engagement this entry belongs to (spec §6).
        timestamp:     UTC datetime of the decision.
        target:        The evaluated target.
        action_type:   The evaluated action type.
        decision:      ALLOW / DENY / REQUIRES_APPROVAL.
        reason:        Human-readable explanation.
        prev_hash:     SHA-256 of the previous entry's canonical JSON,
                       or the genesis constant for the first entry.
        entry_hash:    SHA-256 of this entry's canonical JSON
                       (including ``prev_hash``).
    """

    engagement_id: str
    timestamp: datetime
    target: str
    action_type: str
    decision: DecisionType
    reason: str
    prev_hash: str
    entry_hash: str


@dataclass(frozen=True)
class AuditVerificationResult:
    """Result of an :class:`~roe_guard.audit.AuditLog.verify` call.

    Attributes:
        valid:            True iff every line's hash chain is intact.
        total_entries:    Total number of entries inspected.
        broken_at_index:  Index (0-based) of the first broken entry, or
                          ``None`` when ``valid``.
        reason:           Human-readable explanation of the failure, or
                          ``None`` when ``valid``.
    """

    valid: bool
    total_entries: int
    broken_at_index: int | None = None
    reason: str | None = None


__all__ = [
    "AgentIdentity",
    "AgentSpec",
    "ApprovalSpec",
    "AuditEntry",
    "AuditVerificationResult",
    "BlackoutWindow",
    "CredentialSpec",
    "Decision",
    "DecisionType",
    "EnforcementMode",
    "Engagement",
    "FilesystemSpec",
    "Policy",
    "ReasonCode",
    "ResourceSpec",
    "SandboxSpec",
    "Scope",
    "ScopeEntry",
    "SyscallSpec",
]
