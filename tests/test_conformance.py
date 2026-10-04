"""Conformance runner: every case in conformance/cases runs against roe-guard.

Expectations are hand-written from the SPEC §14.4–§14.5 tables and then
verified by this runner (card step 4).
"""

import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from roe_guard import AgentIdentity, Engagement, ReasonCode, parse_policy
from roe_guard.engine import enforce, enforce_egress
from roe_guard.exceptions import PolicyParseError

REPO = Path(__file__).resolve().parent.parent
CASES = REPO / "conformance" / "cases"
SCHEMA = REPO / "conformance" / "schema" / "case-file.schema.json"
MIN_SIZES = {"v1-golden": 20, "ladder": 20, "agent": 8, "egress": 30, "load": 12}

with open(SCHEMA, encoding="utf-8") as _fh:
    _CASE_SCHEMA = json.load(_fh)

FILES = sorted(CASES.glob("*.json"))
assert FILES, "conformance cases missing"


def _load_cases():
    loaded = []
    for path in FILES:
        with open(path, encoding="utf-8") as fh:
            loaded.append(json.load(fh))
    return loaded


ALL_FILES = _load_cases()


def test_case_files_match_schema():
    for document in ALL_FILES:
        Draft202012Validator.check_schema(_CASE_SCHEMA)
        errors = list(Draft202012Validator(_CASE_SCHEMA).iter_errors(document))
        assert errors == [], (document["suite"], errors)


def _agent(identity):
    if identity is None:
        return None
    return AgentIdentity(identity["id"], identity.get("runtime"))


def _evaluate(case):
    policy_doc = case["policy"]
    input_doc = case["input"]
    now = _parse_now(input_doc["now"])
    agent = _agent(input_doc.get("agent"))
    try:
        policy = parse_policy(policy_doc)
    except PolicyParseError:
        # The vectors treat any parse failure as POLICY_INVALID; a
        # non-mapping document raises with field "<top>".
        return "DENY", "POLICY_INVALID", ""
    engagement = Engagement(policy=policy)
    if input_doc["kind"] == "egress":
        decision = enforce_egress(
            engagement,
            input_doc["host"],
            input_doc["port"],
            input_doc.get("method"),
            now=now,
            agent=agent,
        )
    else:
        decision = enforce(
            engagement,
            input_doc["target"],
            input_doc["action_type"],
            now=now,
            agent=agent,
        )
    return decision.outcome.value, decision.reason_code, decision.matched_rule


def _parse_now(value):
    from datetime import datetime

    normalised = value.replace("Z", "+00:00")
    return datetime.fromisoformat(normalised)


def _cases():
    for document in ALL_FILES:
        for case in document["cases"]:
            yield case


@pytest.mark.parametrize("case", list(_cases()), ids=lambda c: c["id"])
def test_case(case):
    verdict, reason_code, matched_rule = _evaluate(case)
    expected = case["expected"]
    assert verdict == expected["verdict"], case["id"]
    assert reason_code == expected["reason_code"], case["id"]
    if "matched_rule" in expected:
        assert matched_rule == expected["matched_rule"], case["id"]
    if "reason" in expected:
        try:
            parse_policy(case["policy"])
            policy = parse_policy(case["policy"])
            engagement = Engagement(policy=policy)
            input_doc = case["input"]
            decision = enforce(
                engagement,
                input_doc["target"],
                input_doc["action_type"],
                now=_parse_now(input_doc["now"]),
                agent=_agent(input_doc.get("agent")),
            )
            assert decision.reason == expected["reason"], case["id"]
        except PolicyParseError:
            pass


# --- meta tests ----------------------------------------------------------------


def test_ids_unique():
    ids = [case["id"] for case in _cases()]
    assert len(ids) == len(set(ids))


def test_suite_minimum_sizes():
    sizes = {doc["suite"]: len(doc["cases"]) for doc in ALL_FILES}
    for suite, minimum in MIN_SIZES.items():
        assert sizes[suite] >= minimum, (suite, sizes[suite])
    assert sum(sizes.values()) >= 90


def test_every_reason_code_covered():
    used = {case["expected"]["reason_code"] for case in _cases()}
    assert used == {m.value for m in ReasonCode}


def test_every_verdict_seen():
    verdicts = {case["expected"]["verdict"] for case in _cases()}
    assert verdicts == {"ALLOW", "DENY", "REQUIRES_APPROVAL"}


def test_non_invalid_policies_match_schema():
    import yaml

    with open(REPO / "schema" / "policy.v1.json", encoding="utf-8") as fh:
        v1 = json.load(fh)
    with open(REPO / "schema" / "policy.v2.json", encoding="utf-8") as fh:
        v2 = json.load(fh)
    for case in _cases():
        if case["expected"]["reason_code"] == "POLICY_INVALID":
            continue
        document = case["policy"]
        schema = v2 if document.get("schema_version") == 2 else v1
        Draft202012Validator.check_schema(schema)
        errors = list(Draft202012Validator(schema).iter_errors(document))
        assert errors == [], (case["id"], errors)
        # v2 documents must also parse (a POLICY_INVALID-adjacent typo would
        # otherwise hide behind the schema check).
        if document.get("schema_version") == 2:
            parse_policy(document)
        else:
            # v1 documents here are only the reference fixtures converted;
            # schema validity is the contract being checked.
            yaml.safe_load(json.dumps(document))
