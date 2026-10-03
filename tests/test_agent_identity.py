"""Agent identity tests: v2 agent block, ladder step 0, keyword-only agent=.

Step 0 runs only when the policy has an agent block, before step 1, and is
fail-closed: a policy with an agent block denies identity-less callers
(SPEC §14.4).
"""

from datetime import datetime, timezone
from pathlib import Path

import pytest

from roe_guard import (
    AgentIdentity,
    AgentSpec,
    PolicyParseError,
    load_policy,
    parse_policy,
)
from roe_guard.engine import enforce
from roe_guard.exceptions import OutOfScopeError
from roe_guard.integrations.decorator import guarded
from roe_guard.models import DecisionType, Engagement

REPO = Path(__file__).resolve().parent.parent
V2 = REPO / "tests" / "fixtures" / "v2"

NOW = datetime(2026, 10, 1, 10, 0, 0, tzinfo=timezone.utc)
OK = AgentIdentity("spiffe://example.org/tenant/t1/agent/a1/sandbox/s-42", "mcp")


@pytest.fixture(scope="module")
def engagement():
    return Engagement(policy=load_policy(V2 / "valid_agent.yaml"))


def _decide(eng, target, action, *, agent=OK, now=NOW):
    return enforce(eng, target, action, now=now, agent=agent)


# --- loading -----------------------------------------------------------------


def test_agent_block_parsed():
    policy = load_policy(V2 / "valid_agent.yaml")
    assert policy.agent == AgentSpec(
        id="spiffe://example.org/tenant/t1/agent/a1/sandbox/*", runtime=("mcp",)
    )


def test_invalid_agent_id_fixture():
    with pytest.raises(PolicyParseError) as exc:
        load_policy(V2 / "invalid_agent_id.yaml")
    assert exc.value.field == "agent.id"


def _parse_mutated(mutate):
    import yaml

    with open(V2 / "valid_agent.yaml", encoding="utf-8") as fh:
        document = yaml.safe_load(fh)
    mutate(document)
    return parse_policy(document)


def test_missing_id_rejected():
    with pytest.raises(PolicyParseError) as exc:
        _parse_mutated(lambda d: d["agent"].pop("id"))
    assert exc.value.field == "agent.id"


def test_empty_runtime_item_rejected():
    with pytest.raises(PolicyParseError) as exc:
        _parse_mutated(lambda d: d["agent"].__setitem__("runtime", [""]))
    assert exc.value.field == "agent.runtime[0]"


def test_unknown_agent_key_rejected():
    with pytest.raises(PolicyParseError) as exc:
        _parse_mutated(lambda d: d["agent"].__setitem__("foo", 1))
    assert exc.value.field == "agent.foo"


def test_agent_x_note_accepted():
    policy = _parse_mutated(lambda d: d["agent"].__setitem__("x-note", "n"))
    assert policy.agent is not None


def test_manifest_agent_files_agree():
    import json

    with open(V2 / "manifest.json", encoding="utf-8") as fh:
        manifest = json.load(fh)
    for name, entry in manifest.items():
        if entry["block"] != "agent":
            continue
        if entry["valid"]:
            assert load_policy(V2 / name).schema_version == 2
        else:
            with pytest.raises(PolicyParseError) as exc:
                load_policy(V2 / name)
            assert exc.value.field == entry["field"]


# --- step 0 ------------------------------------------------------------------


def test_agent_none_denied(engagement):
    d = _decide(engagement, "api.x.api.example.com", "tool.http.get", agent=None)
    assert d.outcome is DecisionType.DENY
    assert d.reason_code == "AGENT_ID_MISSING"
    assert d.matched_rule == "agent.id"
    assert d.reason == "agent identity missing"


def test_empty_id_denied(engagement):
    d = _decide(
        engagement,
        "api.x.api.example.com",
        "tool.http.get",
        agent=AgentIdentity(""),
    )
    assert d.outcome is DecisionType.DENY
    assert d.reason_code == "AGENT_ID_MISSING"


def test_other_agent_denied(engagement):
    other = AgentIdentity("spiffe://example.org/tenant/t1/agent/a2/sandbox/s-1", "mcp")
    d = _decide(engagement, "api.x.api.example.com", "tool.http.get", agent=other)
    assert d.outcome is DecisionType.DENY
    assert d.reason_code == "AGENT_ID_MISMATCH"


def test_case_difference_denied(engagement):
    other = AgentIdentity("spiffe://example.org/tenant/t1/Agent/a1/sandbox/s-42", "mcp")
    d = _decide(engagement, "api.x.api.example.com", "tool.http.get", agent=other)
    assert d.outcome is DecisionType.DENY
    assert d.reason_code == "AGENT_ID_MISMATCH"


def test_runtime_none_denied(engagement):
    d = _decide(
        engagement,
        "api.x.api.example.com",
        "tool.http.get",
        agent=AgentIdentity(OK.id, None),
    )
    assert d.outcome is DecisionType.DENY
    assert d.reason_code == "AGENT_RUNTIME_NOT_ALLOWED"


def test_runtime_not_listed_denied(engagement):
    d = _decide(
        engagement,
        "api.x.api.example.com",
        "tool.http.get",
        agent=AgentIdentity(OK.id, "foundry"),
    )
    assert d.outcome is DecisionType.DENY
    assert d.reason_code == "AGENT_RUNTIME_NOT_ALLOWED"


def test_ok_agent_allowed(engagement):
    d = _decide(engagement, "api.x.api.example.com", "tool.http.get")
    assert d.outcome is DecisionType.ALLOW
    assert d.reason_code == "ACTION_ALLOWED"
    assert d.agent_id == OK.id


def test_step0_before_step1(engagement):
    d = _decide(
        engagement,
        "api.x.api.example.com",
        "tool.http.get",
        agent=None,
        now=datetime(2026, 10, 3, 0, 0, 0, tzinfo=timezone.utc),
    )
    assert d.reason_code == "AGENT_ID_MISSING"


def test_no_agent_block_skips_step0():
    policy = load_policy(V2 / "valid_minimal.yaml")
    eng = Engagement(policy=policy)
    d = enforce(eng, "api.x.api.example.com", "tool.http.get", now=NOW, agent=OK)
    assert d.outcome is DecisionType.ALLOW
    assert d.agent_id == OK.id
    d2 = enforce(eng, "api.x.api.example.com", "tool.http.get", now=NOW, agent=None)
    assert d2.agent_id == ""


def test_guarded_denies_and_never_calls(engagement):
    calls = {"count": 0}

    @guarded(
        engagement, "tool.http.get", agent=AgentIdentity("spiffe://example.org/other")
    )
    def do_work(target):
        calls["count"] += 1
        return "ok"

    with pytest.raises(OutOfScopeError):
        do_work(target="api.x.api.example.com")
    assert calls["count"] == 0


def test_engagement_check_agent(engagement):
    d = engagement.check("api.x.api.example.com", "tool.http.get", now=NOW, agent=OK)
    assert d.outcome is DecisionType.ALLOW


def test_agent_is_keyword_only(engagement):
    with pytest.raises(TypeError):
        enforce(engagement, "api.x.api.example.com", "tool.http.get", NOW, None, OK)
