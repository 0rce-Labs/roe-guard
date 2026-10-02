"""
roe_guard — Rules of Engagement policy-enforcement library.

Provides programmatic scope-control for security operations: define what
targets, time-windows, and action types are allowed, and every out-of-scope
action is automatically denied and logged to a tamper-evident audit chain.

The public API is exported at the package root: policies are loaded with
:class:`Engagement` / :func:`load_policy`, enforced with :func:`enforce`,
:func:`guarded` and :func:`window`, and recorded to a tamper-evident audit
chain through :class:`AuditLog`.
"""

from roe_guard.audit import GENESIS_PREV_HASH, AuditLog
from roe_guard.engine import enforce, raise_if_expired
from roe_guard.exceptions import (
    ApprovalRequiredError,
    AuditIntegrityError,
    OutOfScopeError,
    PolicyExpiredError,
    PolicyParseError,
    RoeGuardError,
    UnknownKeyWarning,
)
from roe_guard.integrations.context import window
from roe_guard.integrations.decorator import guarded
from roe_guard.models import (
    AuditEntry,
    AuditVerificationResult,
    BlackoutWindow,
    Decision,
    DecisionType,
    Engagement,
    Policy,
    Scope,
    ScopeEntry,
)
from roe_guard.policy import MAX_SCHEMA_VERSION, load_policy

__version__ = "0.1.0a1"

__all__ = [
    "GENESIS_PREV_HASH",
    "MAX_SCHEMA_VERSION",
    "ApprovalRequiredError",
    "AuditEntry",
    "AuditIntegrityError",
    "AuditLog",
    "AuditVerificationResult",
    "BlackoutWindow",
    "Decision",
    "DecisionType",
    "Engagement",
    "OutOfScopeError",
    "Policy",
    "PolicyExpiredError",
    "PolicyParseError",
    "RoeGuardError",
    "Scope",
    "ScopeEntry",
    "UnknownKeyWarning",
    "__version__",
    "enforce",
    "guarded",
    "load_policy",
    "raise_if_expired",
    "window",
]
