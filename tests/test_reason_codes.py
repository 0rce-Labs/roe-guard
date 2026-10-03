"""Reason-code tests: every ladder step carries reason_code and matched_rule.

The v1 ``reason`` texts are asserted byte-for-byte: T20 must not change them.
"""

from datetime import datetime, timezone
from pathlib import Path

import pytest

from roe_guard import EnforcementMode, ReasonCode, load_policy
from roe_guard.engine import enforce
from roe_guard.models import DecisionType, Engagement

FIXTURE = (
    Path(__file__).resolve().parent.parent / "tests" / "fixtures" / "valid_policy.yaml"
)

NOW = datetime(2026, 8, 10, 12, 0, 0, tzinfo=timezone.utc)
BLACKOUT = datetime(
    2026, 8, 15, 0, 0, 0, tzinfo=timezone.utc
)  # window start, inclusive

TARGET_DENIED = "10.20.5.10"
TARGET_OUT_OF_SCOPE = "203.0.113.7"
TARGET_IN_SCOPE = "10.20.3.5"


@pytest.fixture(scope="module")
def policy():
    return load_policy(FIXTURE)


@pytest.fixture(scope="module")
def engagement(policy):
    return Engagement(policy=policy)


def _decide(engagement, target, action, now=NOW):
    return enforce(engagement, target, action, now=now)


def test_step1_expired(engagement):
    d = _decide(
        engagement,
        TARGET_IN_SCOPE,
        "recon",
        now=datetime(2026, 9, 1, tzinfo=timezone.utc),
    )
    assert d.outcome is DecisionType.DENY
    assert d.reason_code == ReasonCode.POLICY_NOT_ACTIVE.value
    assert d.matched_rule == "valid_from/valid_until"
    assert d.reason == "policy expired or not yet active"
    assert d.mode is EnforcementMode.ENFORCE


def test_step2_blackout(engagement):
    d = _decide(engagement, TARGET_IN_SCOPE, "recon", now=BLACKOUT)
    assert d.outcome is DecisionType.DENY
    assert d.reason_code == ReasonCode.BLACKOUT_WINDOW.value
    assert d.matched_rule == "blackout_windows[0]"
    assert d.reason == "inside blackout window: müşteri bakım penceresi"


def test_step3_scope_deny(engagement):
    d = _decide(engagement, TARGET_DENIED, "recon")
    assert d.outcome is DecisionType.DENY
    assert d.reason_code == ReasonCode.TARGET_DENIED.value
    assert d.matched_rule == "scope.deny[0]"
    assert d.reason == "target explicitly denied in scope"


def test_step4_not_in_scope(engagement):
    d = _decide(engagement, TARGET_OUT_OF_SCOPE, "recon")
    assert d.outcome is DecisionType.DENY
    assert d.reason_code == ReasonCode.TARGET_NOT_IN_SCOPE.value
    assert d.matched_rule == "scope.allow"
    assert d.reason == "target not in allowed scope"


def test_step5_action_deny(engagement):
    d = _decide(engagement, TARGET_IN_SCOPE, "destructive")
    assert d.outcome is DecisionType.DENY
    assert d.reason_code == ReasonCode.ACTION_DENIED.value
    assert d.matched_rule == "actions.deny"
    assert d.reason == "action type 'destructive' explicitly denied"


def test_step6_approval_required(engagement):
    d = _decide(engagement, TARGET_IN_SCOPE, "persistence-test")
    assert d.outcome is DecisionType.REQUIRES_APPROVAL
    assert d.reason_code == ReasonCode.APPROVAL_REQUIRED.value
    assert d.matched_rule == "approval_required_for"
    assert d.reason == "action type 'persistence-test' requires human approval"


def test_step7_action_allowed(engagement):
    d = _decide(engagement, TARGET_IN_SCOPE, "recon")
    assert d.outcome is DecisionType.ALLOW
    assert d.reason_code == ReasonCode.ACTION_ALLOWED.value
    assert d.matched_rule == "actions.allow"
    assert d.reason == "action type 'recon' allowed"


def test_step8_fail_closed(engagement):
    d = _decide(engagement, TARGET_IN_SCOPE, "unknown-action")
    assert d.outcome is DecisionType.DENY
    assert d.reason_code == ReasonCode.ACTION_NOT_ALLOWED.value
    assert d.matched_rule == ""
    assert d.reason == "action type not explicitly allowed"


def test_reason_code_member_count_grows_with_ladder():
    # T20 added 9; T21 adds the three AGENT_ codes.
    assert len(ReasonCode) == 12


def test_reason_code_value_equals_name():
    assert {m.value for m in ReasonCode} == {m.name for m in ReasonCode}


def test_mode_defaults_on_decision():
    d = _decide(
        engagement if False else Engagement(policy=load_policy(FIXTURE)),
        TARGET_IN_SCOPE,
        "recon",
    )
    assert d.mode is EnforcementMode.ENFORCE
    assert isinstance(d.reason_code, str) and d.reason_code


def test_reason_code_names():
    assert {m.name for m in ReasonCode} == {
        "POLICY_INVALID",
        "POLICY_NOT_ACTIVE",
        "BLACKOUT_WINDOW",
        "TARGET_DENIED",
        "TARGET_NOT_IN_SCOPE",
        "ACTION_DENIED",
        "APPROVAL_REQUIRED",
        "ACTION_ALLOWED",
        "ACTION_NOT_ALLOWED",
        "AGENT_ID_MISSING",
        "AGENT_ID_MISMATCH",
        "AGENT_RUNTIME_NOT_ALLOWED",
    }


def test_scope_deny_matched_rule_is_first_match(policy):
    from dataclasses import replace

    from roe_guard.models import Scope, ScopeEntry

    scope = Scope(
        allow=policy.scope.allow,
        deny=[ScopeEntry(cidr="10.20.5.0/24"), ScopeEntry(cidr="10.20.0.0/16")],
    )
    d = enforce(
        Engagement(policy=replace(policy, scope=scope)), TARGET_DENIED, "recon", now=NOW
    )
    assert d.reason_code == ReasonCode.TARGET_DENIED.value
    assert d.matched_rule == "scope.deny[0]"


def test_model_defaults_fail_closed():
    from roe_guard import ApprovalSpec, SandboxSpec
    from roe_guard.models import Policy, Scope

    assert SandboxSpec().imds == "deny"
    assert ApprovalSpec(1).on_timeout == "deny"
    p = Policy(
        engagement_id="e",
        valid_from=NOW,
        valid_until=BLACKOUT,
        scope=Scope(allow=[], deny=[]),
        actions_allow=[],
        actions_deny=[],
        blackout_windows=[],
        approval_required_for=[],
        approvers=[],
    )
    assert p.mode is EnforcementMode.ENFORCE
    assert p.schema_version == 1 and p.source_sha256 == ""


def test_new_fields_are_appended():
    from dataclasses import fields

    from roe_guard.models import Decision, Policy

    assert [f.name for f in fields(Policy)][9:] == [
        "schema_version",
        "mode",
        "sandbox",
        "approval",
        "extensions",
        "source_sha256",
        "agent",
    ]
    assert [f.name for f in fields(Decision)][5:] == [
        "mode",
        "reason_code",
        "matched_rule",
        "agent_id",
    ]
