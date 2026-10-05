"""Public API surface: root package exports and Engagement.from_file."""

from datetime import datetime, timezone
from pathlib import Path

import pytest

import roe_guard
from roe_guard import Engagement
from roe_guard.exceptions import PolicyParseError

FIXTURES = Path(__file__).parent / "fixtures"
NOW = datetime(2026, 8, 10, 12, 0, tzinfo=timezone.utc)

EXPECTED_ALL = [
    "ApprovalSpec",
    "ApprovalRequiredError",
    "AgentIdentity",
    "AgentSpec",
    "AuditLogV2",
    "AuditReasonCode",
    "AuditWriterLockedError",
    "CheckpointSigner",
    "Ed25519Signer",
    "verify_chain",
    "AuditEntry",
    "AuditIntegrityError",
    "AuditLog",
    "AuditVerificationResult",
    "BlackoutWindow",
    "Decision",
    "DecisionType",
    "Engagement",
    "GENESIS_PREV_HASH",
    "MAX_SCHEMA_VERSION",
    "OutOfScopeError",
    "parse_policy",
    "SyscallSpec",
    "SandboxSpec",
    "ResourceSpec",
    "ReasonCode",
    "FilesystemSpec",
    "EnforcementMode",
    "CredentialSpec",
    "Policy",
    "PolicyExpiredError",
    "PolicyParseError",
    "RoeGuardError",
    "Scope",
    "ScopeEntry",
    "__version__",
    "enforce",
    "enforce_egress",
    "HttpEgressSpec",
    "HttpDenyRule",
    "HttpAllowRule",
    "EgressSpec",
    "DnsEgressSpec",
    "guarded",
    "load_policy",
    "raise_if_expired",
    "UnknownKeyWarning",
    "window",
]


def test_all_matches_expected() -> None:
    assert sorted(roe_guard.__all__) == sorted(EXPECTED_ALL)


def test_all_names_resolve() -> None:
    for name in roe_guard.__all__:
        assert getattr(roe_guard, name) is not None


def test_import_from_root() -> None:
    from roe_guard import Engagement as E
    from roe_guard import OutOfScopeError as O
    from roe_guard import guarded as g

    assert E is Engagement
    assert issubclass(O, roe_guard.RoeGuardError)
    assert callable(g)


def test_from_file_accepts_str_and_path() -> None:
    from_str = Engagement.from_file(str(FIXTURES / "valid_policy.yaml"))
    from_path = Engagement.from_file(FIXTURES / "valid_policy.yaml")
    assert from_str.policy.engagement_id == "acme-fintech-2026-08"
    assert from_path.policy.engagement_id == "acme-fintech-2026-08"


def test_check_in_scope_allowed() -> None:
    e = Engagement.from_file(FIXTURES / "valid_policy.yaml")
    assert e.check("10.20.3.5", "recon", now=NOW).allowed is True


def test_check_out_of_scope_denied() -> None:
    e = Engagement.from_file(FIXTURES / "valid_policy.yaml")
    d = e.check("203.0.113.7", "recon", now=NOW)
    assert d.denied is True
    assert d.reason == "target not in allowed scope"


@pytest.mark.parametrize(
    "name",
    [
        "invalid_cidr.yaml",
        "malformed_dates.yaml",
        "missing_required_field.yaml",
    ],
)
def test_from_file_invalid_policy_raises(name: str) -> None:
    with pytest.raises(PolicyParseError):
        Engagement.from_file(FIXTURES / name)


def test_from_file_missing_file_raises() -> None:
    with pytest.raises(PolicyParseError):
        Engagement.from_file(FIXTURES / "does-not-exist.yaml")


def test_from_file_subclass_returns_subclass() -> None:
    class Sub(Engagement):
        pass

    obj = Sub.from_file(FIXTURES / "valid_policy.yaml")
    assert isinstance(obj, Sub)


def test_version_unchanged() -> None:
    assert roe_guard.__version__ == "0.1.0a1"
