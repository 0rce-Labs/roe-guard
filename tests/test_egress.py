"""Egress tests: v2 egress block, enforce_egress ladder E0–E10, IMDS hard-stop.

Scope and actions never apply to egress; the IMDS/link-local deny runs
before allow rules and cannot be overridden by policy (SPEC §14.5).
"""

from datetime import datetime, timezone
from pathlib import Path

import pytest

from roe_guard import (
    Engagement,
    PolicyParseError,
    enforce_egress,
    load_policy,
    parse_policy,
)
from roe_guard.engine import enforce
from roe_guard.models import DecisionType, DnsEgressSpec, EgressSpec

REPO = Path(__file__).resolve().parent.parent
V2 = REPO / "tests" / "fixtures" / "v2"

NOW = datetime(2026, 10, 1, 10, 0, 0, tzinfo=timezone.utc)
LATER = datetime(2026, 10, 20, 10, 0, 0, tzinfo=timezone.utc)
BLACKOUT = datetime(2026, 10, 1, 11, 0, 0, tzinfo=timezone.utc)


def _policy(egress_block, **extra):
    base = {
        "schema_version": 2,
        "engagement_id": "fx-egress",
        "valid_from": "2026-10-01T00:00:00Z",
        "valid_until": "2026-10-15T00:00:00Z",
        "scope": {"allow": [{"hostname": "*.api.example.com"}]},
        "actions": {"allow": ["tool.http.get"]},
    }
    base.update(extra)
    if egress_block is not None:
        base["egress"] = egress_block
    return parse_policy(base)


P = _policy(
    {
        "default": "deny",
        "http": {
            "allow": [
                {"host": "api.example.com", "ports": [443], "methods": ["GET"]},
                {"host": "*.cdn.example.com", "ports": [443, 8443]},
                {"cidr": "198.51.100.0/24", "ports": [443]},
            ],
            "deny": [
                {"host": "bad.cdn.example.com"},
                {"cidr": "198.51.100.128/25"},
            ],
        },
        "dns": {"allow": ["*.example.com"]},
    }
)
ENG_P = Engagement(policy=P)

# Q: allow-all shapes; every IMDS/link-local target must still be denied.
Q = _policy(
    {
        "default": "deny",
        "http": {
            "allow": [
                {"host": "*", "ports": [80, 443]},
                {"cidr": "0.0.0.0/0", "ports": [80, 443]},
                {"cidr": "::/0", "ports": [80, 443]},
            ]
        },
    }
)
ENG_Q = Engagement(policy=Q)


def _eg(eng, host, port, method=None, now=NOW):
    return enforce_egress(eng, host, port, method, now=now)


# --- ladder table (SPEC §14.5 card table) ------------------------------------


def test_allow_first_entry():
    d = _eg(ENG_P, "api.example.com", 443, "GET")
    assert d.outcome is DecisionType.ALLOW
    assert d.reason_code == "EGRESS_ALLOWED"
    assert d.matched_rule == "egress.http.allow[0]"


@pytest.mark.parametrize("method", ["POST", None, "get"])
def test_method_not_allowed(method):
    d = _eg(ENG_P, "api.example.com", 443, method)
    assert d.reason_code == "EGRESS_METHOD_NOT_ALLOWED"


def test_port_not_allowed():
    d = _eg(ENG_P, "api.example.com", 80, "GET")
    assert d.reason_code == "EGRESS_PORT_NOT_ALLOWED"
    assert d.matched_rule == "egress.http.allow[0]"


def test_second_entry_allowed_no_method():
    d = _eg(ENG_P, "img.cdn.example.com", 8443)
    assert d.outcome is DecisionType.ALLOW
    assert d.reason_code == "EGRESS_ALLOWED"
    assert d.matched_rule == "egress.http.allow[1]"


def test_uppercase_and_trailing_dot_normalized():
    d = _eg(ENG_P, "IMG.CDN.EXAMPLE.COM.", 443)
    assert d.outcome is DecisionType.ALLOW
    assert d.reason_code == "EGRESS_ALLOWED"


def test_host_deny_wins():
    d = _eg(ENG_P, "bad.cdn.example.com", 443)
    assert d.reason_code == "EGRESS_HOST_DENIED"
    assert d.matched_rule == "egress.http.deny[0]"


def test_cidr_allow():
    d = _eg(ENG_P, "198.51.100.10", 443)
    assert d.outcome is DecisionType.ALLOW
    assert d.matched_rule == "egress.http.allow[2]"


def test_cidr_deny_wins():
    d = _eg(ENG_P, "198.51.100.200", 443)
    assert d.reason_code == "EGRESS_HOST_DENIED"
    assert d.matched_rule == "egress.http.deny[1]"


@pytest.mark.parametrize("host", ["203.0.113.5", "other.example.org"])
def test_host_not_allowed(host):
    d = _eg(ENG_P, host, 443)
    assert d.reason_code == "EGRESS_HOST_NOT_ALLOWED"
    assert d.matched_rule == "egress.http.allow"


# --- IMDS hard-stop (E4) before allow rules, cannot be overridden ------------

IMDS_TARGETS = [
    ("169.254.169.254", 80),
    ("168.63.129.16", 80),
    ("100.100.100.200", 80),
    ("fd00:ec2::254", 80),
    ("::ffff:169.254.169.254", 80),
    ("::ffff:100.100.100.200", 80),
    ("fe80::1", 443),
    ("metadata.google.internal", 80),
    ("METADATA.GOOGLE.INTERNAL.", 80),
]


@pytest.mark.parametrize(("host", "port"), IMDS_TARGETS)
def test_imds_denied_on_allow_all(host, port):
    d = _eg(ENG_Q, host, port)
    assert d.outcome is DecisionType.DENY
    assert d.reason_code == "EGRESS_IMDS_DENIED"


def test_observe_mode_still_denies_imds():
    q_observe = _policy(
        {
            "default": "deny",
            "http": {"allow": [{"host": "*", "ports": [80, 443]}]},
        },
        mode="observe",
    )
    d = enforce_egress(Engagement(policy=q_observe), "169.254.169.254", 80, now=NOW)
    assert d.outcome is DecisionType.DENY
    assert d.reason_code == "EGRESS_IMDS_DENIED"
    assert d.mode.value == "observe"


def test_host_glob_never_matches_ip_literal():
    q2 = _policy(
        {"default": "deny", "http": {"allow": [{"host": "*", "ports": [443]}]}}
    )
    d = enforce_egress(Engagement(policy=q2), "203.0.113.5", 443, now=NOW)
    assert d.reason_code == "EGRESS_HOST_NOT_ALLOWED"


# --- E3 validation -----------------------------------------------------------

INVALID_TARGETS = [
    "",
    "exa mple.com",
    "[2001:db8::1]",
    "3232235777",
    "10.0x1",
    "010.0.0.1",
    "a" * 64 + ".example.com",
    "api.example.com\n",
]


@pytest.mark.parametrize("host", INVALID_TARGETS)
def test_invalid_host(host):
    d = _eg(ENG_P, host, 443)
    assert d.reason_code == "EGRESS_TARGET_INVALID"


@pytest.mark.parametrize("port", [0, 65536, True, "443", 443.0])
def test_invalid_port(port):
    d = _eg(ENG_P, "api.example.com", port, "GET")
    assert d.reason_code == "EGRESS_TARGET_INVALID"


@pytest.mark.parametrize(("host", "port"), [("2001:db8::1", 443)])
def test_ipv6_literal_valid_target(host, port):
    d = _eg(ENG_P, host, port)
    assert d.reason_code == "EGRESS_HOST_NOT_ALLOWED"


def test_empty_method_invalid():
    d = _eg(ENG_P, "api.example.com", 443, "")
    assert d.reason_code == "EGRESS_TARGET_INVALID"


# --- E5: no egress block ------------------------------------------------------


def test_v2_without_egress():
    policy = _policy(None)
    d = enforce_egress(Engagement(policy=policy), "api.example.com", 443, now=NOW)
    assert d.reason_code == "EGRESS_NOT_CONFIGURED"
    assert d.matched_rule == "egress"


def test_v1_policy():
    d = enforce_egress(
        Engagement(
            policy=load_policy(REPO / "tests" / "fixtures" / "valid_policy.yaml")
        ),
        "api.example.com",
        443,
        now=datetime(2026, 8, 10, 12, 0, tzinfo=timezone.utc),
    )
    assert d.reason_code == "EGRESS_NOT_CONFIGURED"
    assert d.matched_rule == "egress"


def test_dns_only_egress():
    policy = _policy({"default": "deny", "dns": {"allow": ["*.example.com"]}})
    d = enforce_egress(Engagement(policy=policy), "api.example.com", 443, now=NOW)
    assert d.reason_code == "EGRESS_HOST_NOT_ALLOWED"


# --- E1/E2 --------------------------------------------------------------------


def test_time_window_outside():
    d = _eg(ENG_P, "api.example.com", 443, "GET", now=LATER)
    assert d.reason_code == "POLICY_NOT_ACTIVE"
    assert d.reason == "policy expired or not yet active"


def test_blackout():
    policy = _policy(
        {
            "default": "deny",
            "http": {"allow": [{"host": "api.example.com", "ports": [443]}]},
            "dns": {"allow": ["*.example.com"]},
        },
        blackout_windows=[
            {
                "start": "2026-10-01T10:30:00Z",
                "end": "2026-10-01T11:30:00Z",
                "reason": "bakım",
            }
        ],
    )
    d = enforce_egress(Engagement(policy=policy), "api.example.com", 443, now=BLACKOUT)
    assert d.reason_code == "BLACKOUT_WINDOW"
    assert d.reason == "inside blackout window: bakım"


# --- Decision fields ----------------------------------------------------------


def test_decision_target_and_action_type():
    d = _eg(ENG_P, "api.example.com", 443, "GET")
    assert d.target == "api.example.com:443"
    assert d.action_type == "egress:GET"
    d2 = _eg(ENG_P, "img.cdn.example.com", 8443)
    assert d2.action_type == "egress"


def test_ipv6_target_bracketed():
    policy = _policy(
        {
            "default": "deny",
            "http": {"allow": [{"cidr": "2001:db8::/32", "ports": [443]}]},
        }
    )
    d = enforce_egress(Engagement(policy=policy), "2001:db8::1", 443, now=NOW)
    assert d.outcome is DecisionType.ALLOW
    assert d.target == "[2001:db8::1]:443"


# --- 8-step enforce() untouched -----------------------------------------------


def test_enforce_unchanged_by_egress_block():
    d = enforce(ENG_P, "api.x.api.example.com", "tool.http.get", now=NOW)
    assert d.outcome is DecisionType.ALLOW
    assert d.reason_code == "ACTION_ALLOWED"


# --- loader -------------------------------------------------------------------


def test_manifest_egress_files_agree():
    import json

    with open(V2 / "manifest.json", encoding="utf-8") as fh:
        manifest = json.load(fh)
    for name, entry in manifest.items():
        if entry["block"] != "egress":
            continue
        if entry["valid"]:
            assert load_policy(V2 / name).schema_version == 2
        else:
            with pytest.raises(PolicyParseError) as exc:
                load_policy(V2 / name)
            assert exc.value.field == entry["field"]


def test_invalid_egress_cidr_fixture():
    with pytest.raises(PolicyParseError) as exc:
        load_policy(V2 / "invalid_egress_cidr.yaml")
    assert exc.value.field == "egress.http.deny[0].cidr"


def _parse_egress_mutated(mutate):
    import yaml

    with open(V2 / "valid_egress.yaml", encoding="utf-8") as fh:
        document = yaml.safe_load(fh)
    mutate(document)
    return parse_policy(document)


def test_lowercase_method_rejected():
    with pytest.raises(PolicyParseError) as exc:
        _parse_egress_mutated(
            lambda d: d["egress"]["http"]["allow"][0].__setitem__("methods", ["get"])
        )
    assert exc.value.field == "egress.http.allow[0].methods[0]"


def test_method_with_newline_rejected():
    with pytest.raises(PolicyParseError) as exc:
        _parse_egress_mutated(
            lambda d: d["egress"]["http"]["allow"][0].__setitem__("methods", ["GET\n"])
        )
    assert exc.value.field == "egress.http.allow[0].methods[0]"


def test_empty_methods_list_rejected():
    with pytest.raises(PolicyParseError) as exc:
        _parse_egress_mutated(
            lambda d: d["egress"]["http"]["allow"][0].__setitem__("methods", [])
        )
    assert exc.value.field == "egress.http.allow[0].methods"


def test_record_type_mx_rejected():
    with pytest.raises(PolicyParseError) as exc:
        _parse_egress_mutated(
            lambda d: d["egress"]["dns"].__setitem__("record_types", ["MX"])
        )
    assert exc.value.field == "egress.dns.record_types[0]"


def test_record_types_unique_rejected():
    with pytest.raises(PolicyParseError) as exc:
        _parse_egress_mutated(
            lambda d: d["egress"]["dns"].__setitem__("record_types", ["A", "A"])
        )
    assert exc.value.field == "egress.dns.record_types"


# --- null lists are rejected, never treated as empty (SPEC §14.2) -------------


@pytest.mark.parametrize(
    ("mutate", "field"),
    [
        (lambda d: d["egress"]["http"].__setitem__("allow", None), "egress.http.allow"),
        (lambda d: d["egress"]["http"].__setitem__("deny", None), "egress.http.deny"),
        (lambda d: d["egress"]["dns"].__setitem__("allow", None), "egress.dns.allow"),
        (lambda d: d["egress"]["dns"].__setitem__("deny", None), "egress.dns.deny"),
        (
            lambda d: d["egress"]["dns"].__setitem__("record_types", None),
            "egress.dns.record_types",
        ),
        (
            lambda d: d["egress"]["http"]["allow"][0].__setitem__("ports", None),
            "egress.http.allow[0].ports",
        ),
        (
            lambda d: d["egress"]["http"]["allow"][0].__setitem__("methods", None),
            "egress.http.allow[0].methods",
        ),
    ],
)
def test_null_lists_rejected(mutate, field):
    with pytest.raises(PolicyParseError) as exc:
        _parse_egress_mutated(mutate)
    assert exc.value.field == field


# --- number rules: bool and integral floats (SPEC §14.8) ------------------------


@pytest.mark.parametrize("bad_port", [True, 443.0, 0, -1, 65536, "443"])
def test_ports_element_rejections(bad_port):
    with pytest.raises(PolicyParseError) as exc:
        _parse_egress_mutated(
            lambda d, b=bad_port: d["egress"]["http"]["allow"][0].__setitem__(
                "ports", [b]
            )
        )
    assert exc.value.field == "egress.http.allow[0].ports[0]"


# --- block mapping rules (SPEC §14.2) -------------------------------------------


@pytest.mark.parametrize(
    ("mutate", "field"),
    [
        (lambda d: d["egress"].__setitem__("http", None), "egress.http"),
        (lambda d: d["egress"].__setitem__("dns", None), "egress.dns"),
        (lambda d: d.__setitem__("egress", None), "egress"),
        (lambda d: d["egress"].__setitem__("http", []), "egress.http"),
        (lambda d: d["egress"].__setitem__("dns", "x"), "egress.dns"),
    ],
)
def test_egress_blocks_must_be_mappings(mutate, field):
    with pytest.raises(PolicyParseError) as exc:
        _parse_egress_mutated(mutate)
    assert exc.value.field == field


def test_egress_default_allow_rejected_fixture():
    with pytest.raises(PolicyParseError) as exc:
        load_policy(V2 / "invalid_egress_default_allow.yaml")
    assert exc.value.field == "egress.default"


# --- model tuples ---------------------------------------------------------------


def test_valid_egress_model_tuples():
    policy = load_policy(V2 / "valid_egress.yaml")
    egress = policy.egress
    assert isinstance(egress, EgressSpec)
    assert isinstance(egress.dns, DnsEgressSpec)
    assert isinstance(egress.http.allow, tuple)
    assert egress.http.allow[0].ports == (443,)
    assert egress.http.allow[0].methods == ("GET",)
    assert egress.http.deny[0].host == "bad.example.com"
    assert egress.dns.allow == ("*.example.com",)
    assert egress.dns.record_types == ("A", "AAAA")


# --- E0: agent step on the egress ladder (T21 merged first) --------------------


def test_egress_e0_agent_missing():
    from dataclasses import replace

    from roe_guard import AgentSpec

    policy = replace(P, agent=AgentSpec(id="spiffe://example.org/agents/*"))
    d = enforce_egress(
        Engagement(policy=policy),
        "api.example.com",
        443,
        "GET",
        now=NOW,
        agent=None,
    )
    assert d.reason_code == "AGENT_ID_MISSING"
    assert d.matched_rule == "agent.id"
    assert d.agent_id == ""


def test_egress_e0_agent_ok_passes_to_ladder():
    from dataclasses import replace

    from roe_guard import AgentIdentity, AgentSpec

    policy = replace(
        P,
        agent=AgentSpec(id="spiffe://example.org/agents/*", runtime=("mcp",)),
    )
    eng = Engagement(policy=policy)
    ok = enforce_egress(
        eng,
        "api.example.com",
        443,
        "GET",
        now=NOW,
        agent=AgentIdentity("spiffe://example.org/agents/a1", "mcp"),
    )
    assert ok.outcome is DecisionType.ALLOW
    bad = enforce_egress(
        eng,
        "api.example.com",
        443,
        "GET",
        now=NOW,
        agent=AgentIdentity("spiffe://example.org/other"),
    )
    assert bad.reason_code == "AGENT_ID_MISMATCH"


def test_egress_agent_is_keyword_only():
    import inspect

    with pytest.raises(TypeError):
        enforce_egress(ENG_P, "api.example.com", 443, "GET", None)  # 5th positional
    kw = inspect.Parameter.KEYWORD_ONLY
    for fn in (enforce_egress, Engagement.check_egress):
        params = inspect.signature(fn).parameters
        assert params["agent"].kind is kw and params["now"].kind is kw


# --- E9 looks at every host+port match (SPEC §14.5) --------------------------


@pytest.mark.parametrize("reverse", [False, True])
@pytest.mark.parametrize("method", ["POST", None, "GET"])
def test_e9_mixed_restricted_and_open_entries(reverse, method):
    entries = [
        {"host": "api.example.com", "ports": [443], "methods": ["GET"]},
        {"host": "*.example.com", "ports": [443]},
    ]
    if reverse:
        entries.reverse()
    eng = Engagement(policy=_policy({"http": {"allow": entries}}))
    d = _eg(eng, "api.example.com", 443, method)
    # E10: the first entry that is unrestricted or lists the method.
    expected = next(
        i for i, e in enumerate(entries) if "methods" not in e or method in e["methods"]
    )
    assert (d.outcome, d.reason_code, d.matched_rule) == (
        DecisionType.ALLOW,
        "EGRESS_ALLOWED",
        f"egress.http.allow[{expected}]",
    )


def test_e9_all_restricted_denies_at_first_match():
    eng = Engagement(
        policy=_policy(
            {
                "http": {
                    "allow": [
                        {"host": "*.example.com", "ports": [443], "methods": ["GET"]},
                        {"host": "api.example.com", "ports": [443], "methods": ["PUT"]},
                    ]
                }
            }
        )
    )
    d = _eg(eng, "api.example.com", 443, "POST")
    assert (d.reason_code, d.matched_rule, d.reason) == (
        "EGRESS_METHOD_NOT_ALLOWED",
        "egress.http.allow[0]",
        "egress method not allowed",
    )
    assert (
        _eg(eng, "api.example.com", 443, "PUT").matched_rule == "egress.http.allow[1]"
    )


# --- E3 names: no minimum label count (SPEC §14.5) ---------------------------


def test_single_label_names_are_valid():
    d = _eg(ENG_Q, "localhost", 443)
    assert (d.reason_code, d.matched_rule) == ("EGRESS_ALLOWED", "egress.http.allow[0]")
    eng = Engagement(
        policy=_policy({"http": {"allow": [{"host": "intranet", "ports": [443]}]}})
    )
    assert _eg(eng, "INTRANET.", 443).reason_code == "EGRESS_ALLOWED"
    assert (
        _eg(Engagement(policy=_policy(None)), "intranet", 443).reason_code
        == "EGRESS_NOT_CONFIGURED"
    )
    assert _eg(ENG_Q, "3232235777", 443).reason_code == "EGRESS_TARGET_INVALID"


def test_host_pattern_with_trailing_dot_still_denies():
    eng = Engagement(
        policy=_policy(
            {
                "http": {
                    "allow": [{"host": "*", "ports": [443]}],
                    "deny": [{"host": "Bad.Example.COM."}],
                }
            }
        )
    )
    d = _eg(eng, "bad.example.com", 443)
    assert (d.reason_code, d.matched_rule) == (
        "EGRESS_HOST_DENIED",
        "egress.http.deny[0]",
    )


# --- IPv4-mapped IPv6 targets match IPv4 cidr entries (SPEC §14.5) -----------


@pytest.mark.parametrize("host", ["::ffff:198.51.100.200", "::ffff:c633:64c8"])
def test_mapped_ipv4_cannot_bypass_ipv4_deny(host):
    eng = Engagement(
        policy=_policy(
            {
                "http": {
                    "allow": [
                        {"cidr": "198.51.100.0/24", "ports": [443]},
                        {"cidr": "::/0", "ports": [443]},
                    ],
                    "deny": [{"cidr": "198.51.100.128/25"}],
                }
            }
        )
    )
    d = _eg(eng, host, 443)
    assert (d.reason_code, d.matched_rule) == (
        "EGRESS_HOST_DENIED",
        "egress.http.deny[0]",
    )


def test_mapped_ipv4_matches_ipv4_allow():
    d = _eg(ENG_P, "::ffff:198.51.100.10", 443)
    assert (d.reason_code, d.matched_rule) == ("EGRESS_ALLOWED", "egress.http.allow[2]")


# --- host/cidr null is a type error, not an absent key ----------------------


@pytest.mark.parametrize(
    ("entry_key", "entry", "field"),
    [
        (
            "allow",
            {"host": "api.example.com", "cidr": None, "ports": [443]},
            "egress.http.allow[0]",
        ),
        ("allow", {"host": None, "ports": [443]}, "egress.http.allow[0].host"),
        ("allow", {"cidr": None, "ports": [443]}, "egress.http.allow[0].cidr"),
        ("deny", {"host": "bad.example.com", "cidr": None}, "egress.http.deny[0]"),
    ],
)
def test_host_or_cidr_null_rejected(entry_key, entry, field):
    block = {"http": {"allow": [{"host": "a.example.com", "ports": [443]}]}}
    block["http"][entry_key] = [entry]
    with pytest.raises(PolicyParseError) as exc:
        _policy(block)
    assert exc.value.field == field


# --- ladder order is fixed (SPEC §14.5) --------------------------------------


def test_imds_precedes_not_configured_and_deny():
    assert (
        _eg(Engagement(policy=_policy(None)), "169.254.169.254", 80).reason_code
        == "EGRESS_IMDS_DENIED"
    )
    eng = Engagement(
        policy=_policy(
            {
                "http": {
                    "allow": [{"cidr": "0.0.0.0/0", "ports": [80]}],
                    "deny": [{"cidr": "169.254.0.0/16"}],
                }
            }
        )
    )
    assert _eg(eng, "169.254.169.254", 80).reason_code == "EGRESS_IMDS_DENIED"


def test_e0_e1_e3_order():
    from roe_guard import AgentIdentity

    agent_policy = _policy(
        {"http": {"allow": [{"host": "*", "ports": [443]}]}},
        agent={"id": "spiffe://example.org/a"},
    )
    eng = Engagement(policy=agent_policy)
    # E0 before E1: missing identity on an expired policy.
    assert (
        enforce_egress(eng, "api.example.com", 443, now=LATER).reason_code
        == "AGENT_ID_MISSING"
    )
    # E1 before E3: an invalid target on an expired policy.
    ok = AgentIdentity("spiffe://example.org/a")
    assert (
        enforce_egress(eng, "bad host", 443, now=LATER, agent=ok).reason_code
        == "POLICY_NOT_ACTIVE"
    )
    # E8 before E9: host matches, port does not.
    assert (
        _eg(ENG_P, "api.example.com", 8443, "POST").reason_code
        == "EGRESS_PORT_NOT_ALLOWED"
    )


def test_window_end_is_exclusive():
    end = datetime(2026, 10, 15, 0, 0, 0, tzinfo=timezone.utc)
    assert (
        _eg(ENG_Q, "api.example.com", 443, now=end).reason_code == "POLICY_NOT_ACTIVE"
    )


def test_non_string_method_invalid():
    assert _eg(ENG_Q, "api.example.com", 443, 5).reason_code == "EGRESS_TARGET_INVALID"


# --- first match wins for matched_rule (SPEC §14.5) --------------------------


def test_first_match_indices():
    eng = Engagement(
        policy=_policy(
            {
                "http": {
                    "allow": [
                        {"host": "*.example.com", "ports": [80]},
                        {"host": "api.example.com", "ports": [81]},
                        {"host": "*.example.com", "ports": [443]},
                        {"host": "api.example.com", "ports": [443]},
                    ],
                    "deny": [
                        {"host": "bad.example.com"},
                        {"host": "*.example.com", "x-n": 1},
                    ],
                }
            }
        )
    )
    assert _eg(eng, "bad.example.com", 443).matched_rule == "egress.http.deny[0]"
    eng2 = Engagement(policy=replace_deny(eng.policy))
    assert (
        _eg(eng2, "api.example.com", 8080).matched_rule == "egress.http.allow[0]"
    )  # E8
    assert (
        _eg(eng2, "api.example.com", 443).matched_rule == "egress.http.allow[2]"
    )  # E10


def replace_deny(policy):
    from dataclasses import replace

    http = replace(policy.egress.http, deny=())
    return replace(policy, egress=replace(policy.egress, http=http))


# --- check_egress, reasons and agent_id --------------------------------------


def test_check_egress_passes_now_and_agent():
    from roe_guard import AgentIdentity

    eng = Engagement(
        policy=_policy(
            {"http": {"allow": [{"host": "*", "ports": [443]}]}},
            agent={"id": "spiffe://example.org/a"},
        )
    )
    ok = AgentIdentity("spiffe://example.org/a")
    d = eng.check_egress("api.example.com", 443, now=NOW, agent=ok)
    assert (d.reason_code, d.agent_id) == ("EGRESS_ALLOWED", ok.id)
    assert (
        eng.check_egress("api.example.com", 443, now=LATER, agent=ok).reason_code
        == "POLICY_NOT_ACTIVE"
    )


@pytest.mark.parametrize(
    ("eng_name", "host", "port", "method", "code", "reason"),
    [
        ("Q", "bad host", 443, None, "EGRESS_TARGET_INVALID", "egress target invalid"),
        (
            "Q",
            "169.254.169.254",
            80,
            None,
            "EGRESS_IMDS_DENIED",
            "egress to instance metadata or link-local address denied",
        ),
        (
            "none",
            "api.example.com",
            443,
            None,
            "EGRESS_NOT_CONFIGURED",
            "egress not configured in policy",
        ),
        (
            "P",
            "bad.cdn.example.com",
            443,
            None,
            "EGRESS_HOST_DENIED",
            "egress host explicitly denied",
        ),
        (
            "P",
            "other.example.org",
            443,
            None,
            "EGRESS_HOST_NOT_ALLOWED",
            "egress host not allowed",
        ),
        (
            "P",
            "api.example.com",
            8443,
            None,
            "EGRESS_PORT_NOT_ALLOWED",
            "egress port not allowed",
        ),
        (
            "P",
            "api.example.com",
            443,
            "POST",
            "EGRESS_METHOD_NOT_ALLOWED",
            "egress method not allowed",
        ),
        ("P", "api.example.com", 443, "GET", "EGRESS_ALLOWED", "egress allowed"),
    ],
)
def test_reason_texts(eng_name, host, port, method, code, reason):
    eng = {"Q": ENG_Q, "P": ENG_P, "none": Engagement(policy=_policy(None))}[eng_name]
    d = _eg(eng, host, port, method)
    assert (d.reason_code, d.reason) == (code, reason)


# --- strict keys and x- keys inside egress ------------------------------------


@pytest.mark.parametrize(
    ("block", "field"),
    [
        ({"zz": 1}, "egress.zz"),
        ({"http": {"zz": 1}}, "egress.http.zz"),
        (
            {
                "http": {
                    "allow": [{"host": "a.example.com", "ports": [443], "proto": "udp"}]
                }
            },
            "egress.http.allow[0].proto",
        ),
        (
            {"http": {"deny": [{"host": "a.example.com", "zz": 1}]}},
            "egress.http.deny[0].zz",
        ),
        ({"dns": {"zz": 1}}, "egress.dns.zz"),
    ],
)
def test_unknown_egress_keys_rejected(block, field):
    with pytest.raises(PolicyParseError) as exc:
        _policy(block)
    assert exc.value.field == field


def test_x_keys_allowed_in_egress():
    p = _policy(
        {
            "x-n": 1,
            "http": {
                "x-n": 1,
                "allow": [{"host": "a.example.com", "ports": [443], "x-n": 1}],
                "deny": [{"host": "b.example.com", "x-n": 1}],
            },
            "dns": {"x-n": 1},
        }
    )
    assert p.egress is not None


# --- IMDS ranges, not just single addresses ------------------------------------


@pytest.mark.parametrize(
    "host",
    [
        "169.254.0.0",
        "169.254.255.255",
        "fe80::",
        "febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
        "::ffff:169.254.0.1",
    ],
)
def test_imds_range_edges_denied(host):
    assert _eg(ENG_Q, host, 80).reason_code == "EGRESS_IMDS_DENIED"


@pytest.mark.parametrize(
    "host",
    ["169.253.255.255", "169.255.0.0", "168.63.129.17", "100.100.100.201", "fec0::1"],
)
def test_imds_neighbours_not_denied(host):
    assert _eg(ENG_Q, host, 80).reason_code == "EGRESS_ALLOWED"
