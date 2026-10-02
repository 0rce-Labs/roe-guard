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


def test_v2_blocks_never_silently_dropped(tmp_path):
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
