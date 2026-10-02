"""Unknown-key validation per schema version (strict v2, warned v1)."""

import warnings
from pathlib import Path

import pytest
import yaml

from roe_guard.exceptions import PolicyParseError, UnknownKeyWarning
from roe_guard.policy import load_policy

FIXTURES = Path(__file__).parent / "fixtures"

BASE = {
    "engagement_id": "uk-test",
    "valid_from": "2026-10-01T00:00:00Z",
    "valid_until": "2026-10-02T00:00:00Z",
    "scope": {"allow": [{"cidr": "10.0.0.0/8"}]},
    "actions": {"allow": ["tool.read"]},
}

BASE_V2 = dict(BASE, schema_version=2)


def _write(tmp_path, data, name="policy.yaml"):
    p = tmp_path / name
    p.write_text(yaml.safe_dump(data), encoding="utf-8")
    return str(p)


def test_v2_root_unknown_key_rejected(tmp_path):
    p = _write(tmp_path, dict(BASE_V2, foo=1))
    with pytest.raises(PolicyParseError) as exc:
        load_policy(p)
    assert exc.value.field == "foo"
    assert "unknown key" in str(exc.value)


def test_v2_actions_unknown_key_rejected(tmp_path):
    data = dict(BASE_V2, actions={"allow": ["tool.read"], "approve": ["tool.write"]})
    p = _write(tmp_path, data)
    with pytest.raises(PolicyParseError) as exc:
        load_policy(p)
    assert exc.value.field == "actions.approve"


def test_v2_scope_entry_unknown_key_rejected(tmp_path):
    data = dict(BASE_V2, scope={"allow": [{"cidr": "10.0.0.0/8", "note": "x"}]})
    p = _write(tmp_path, data)
    with pytest.raises(PolicyParseError) as exc:
        load_policy(p)
    assert exc.value.field == "scope.allow[0].note"


def test_v2_blackout_unknown_key_rejected(tmp_path):
    data = dict(
        BASE_V2,
        blackout_windows=[
            {
                "start": "2026-10-01T10:00:00Z",
                "end": "2026-10-01T11:00:00Z",
                "color": "red",
            }
        ],
    )
    p = _write(tmp_path, data)
    with pytest.raises(PolicyParseError) as exc:
        load_policy(p)
    assert exc.value.field == "blackout_windows[0].color"


def test_v2_extension_keys_ignored(tmp_path):
    data = dict(BASE_V2, **{"x-vendor": {"a": 1}})
    data["actions"] = {"allow": ["tool.read"], "x-note": "n"}
    data["scope"] = {"allow": [{"cidr": "10.0.0.0/8", "x-tag": "t"}]}
    p = _write(tmp_path, data)
    pol = load_policy(p)
    assert pol.schema_version == 2


def test_v2_never_defined_key_rejected(tmp_path):
    p = _write(tmp_path, dict(BASE_V2, network={"a": 1}))
    with pytest.raises(PolicyParseError) as exc:
        load_policy(p)
    assert exc.value.field == "network"


def test_regression_v2_blocks_never_silently_dropped(tmp_path):
    """T20-T22 until then: either rejected (fail-closed) or fully parsed."""
    data = dict(
        BASE_V2,
        mode="observe",
        agent={"id": "spiffe://example.org/a"},
        egress={"default": "deny"},
    )
    p = _write(tmp_path, data)
    try:
        pol = load_policy(p)
    except PolicyParseError:
        return
    assert getattr(pol, "mode", None) == "observe"
    assert getattr(pol, "agent", None) is not None
    assert getattr(pol, "egress", None) is not None


@pytest.mark.parametrize("key", ["mode", "agent", "sandbox", "egress", "approval"])
def test_v1_v2_reserved_blocks_rejected(tmp_path, key):
    data = dict(BASE, **{key: {"default": "deny"}})
    p = _write(tmp_path, data)
    with pytest.raises(PolicyParseError) as exc:
        load_policy(p)
    assert exc.value.field == key
    assert "requires schema_version: 2" in str(exc.value)


def test_v1_unknown_key_warned_and_ignored(tmp_path):
    p = _write(tmp_path, dict(BASE, foo=1))
    with pytest.warns(UnknownKeyWarning) as records:
        load_policy(p)
    assert any("foo" in str(w.message) for w in records)


def test_v1_extension_key_silent(tmp_path):
    p = _write(tmp_path, dict(BASE, **{"x-foo": 1}))
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        load_policy(p)


@pytest.mark.parametrize("name", ["valid_policy.yaml", "demo_policy.yaml"])
def test_fixtures_load_without_warnings(name):
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        load_policy(str(FIXTURES / name))


@pytest.mark.parametrize(
    ("raw_key", "field"), [("1", "1"), ("true", "True"), ("null", "None")]
)
def test_v2_non_str_root_key_rejected(tmp_path, raw_key, field):
    p = tmp_path / "policy.yaml"
    p.write_text(yaml.safe_dump(BASE_V2) + f"{raw_key}: x\n", encoding="utf-8")
    with pytest.raises(PolicyParseError) as exc:
        load_policy(str(p))
    assert exc.value.field == field
    assert "unknown key" in str(exc.value)


def test_v2_non_str_key_in_scope_entry_rejected(tmp_path):
    data = dict(BASE_V2, scope={"allow": [{"cidr": "10.0.0.0/8", 7: "x"}]})
    p = _write(tmp_path, data)
    with pytest.raises(PolicyParseError) as exc:
        load_policy(p)
    assert exc.value.field == "scope.allow[0].7"


def test_v2_scope_level_unknown_key_rejected(tmp_path):
    data = dict(BASE_V2, scope={"allow": [{"cidr": "10.0.0.0/8"}], "foo": 1})
    p = _write(tmp_path, data)
    with pytest.raises(PolicyParseError) as exc:
        load_policy(p)
    assert exc.value.field == "scope.foo"


def test_v2_scope_deny_entry_unknown_key_rejected(tmp_path):
    data = dict(
        BASE_V2,
        scope={
            "allow": [{"cidr": "10.0.0.0/8"}],
            "deny": [{"cidr": "10.1.0.0/16"}, {"cidr": "10.2.0.0/16", "note": "x"}],
        },
    )
    p = _write(tmp_path, data)
    with pytest.raises(PolicyParseError) as exc:
        load_policy(p)
    assert exc.value.field == "scope.deny[1].note"


def test_v2_extension_keys_ignored_in_scope_and_blackout(tmp_path):
    data = dict(
        BASE_V2,
        scope={"allow": [{"cidr": "10.0.0.0/8"}], "x-team": "a"},
        blackout_windows=[
            {
                "start": "2026-10-01T01:00:00Z",
                "end": "2026-10-01T02:00:00Z",
                "x-ticket": "b",
            }
        ],
    )
    p = _write(tmp_path, data)
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        assert load_policy(p).schema_version == 2


def test_v1_nested_unknown_key_warned_with_path_at_caller(tmp_path):
    data = dict(BASE, scope={"allow": [{"cidr": "10.0.0.0/8", "note": "x"}]})
    p = _write(tmp_path, data)
    with pytest.warns(UnknownKeyWarning, match=r"scope\.allow\[0\]\.note") as rec:
        load_policy(p)
    assert rec[0].filename == __file__


@pytest.mark.parametrize(
    ("tail", "first"),
    [
        ("egress: {}\nmode: observe\n", "egress"),
        ("mode: observe\negress: {}\n", "mode"),
    ],
)
def test_v1_reserved_key_reported_in_document_order(tmp_path, tail, first):
    p = tmp_path / "policy.yaml"
    p.write_text(yaml.safe_dump(BASE) + tail, encoding="utf-8")
    with pytest.raises(PolicyParseError) as exc:
        load_policy(str(p))
    assert exc.value.field == first


def test_v1_warning_points_at_from_file_caller(tmp_path):
    from roe_guard import Engagement

    p = _write(tmp_path, dict(BASE, foo=1))
    with pytest.warns(UnknownKeyWarning) as rec:
        Engagement.from_file(p)
    assert rec[0].filename == __file__
