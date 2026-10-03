"""v2 loader tests: mode, sandbox, approval, extensions, parse_policy, sha256.

Fixture expectations come from tests/fixtures/v2/manifest.json. The two
loader_only files are schema-valid but rejected here (date order, CIDR
validity are loader checks; SPEC §14.8).
"""

import hashlib
from pathlib import Path

import pytest

from roe_guard import EnforcementMode, PolicyParseError, load_policy
from roe_guard.engine import enforce
from roe_guard.exceptions import OutOfScopeError
from roe_guard.integrations.decorator import guarded
from roe_guard.models import DecisionType, Engagement
from roe_guard.policy import parse_policy

REPO = Path(__file__).resolve().parent.parent
V2 = REPO / "tests" / "fixtures" / "v2"
MANIFEST = V2 / "manifest.json"

import json

with open(MANIFEST, encoding="utf-8") as _fh:
    MANIFEST_DATA = json.load(_fh)

RELEVANT_BLOCKS = {"core", "mode", "sandbox", "approval", "extensions"}


def _fixture(name):
    return V2 / name


def _load(name):
    return load_policy(_fixture(name))


# --- (a) manifest-driven: loader agrees with the manifest -------------------


@pytest.mark.parametrize("name", sorted(MANIFEST_DATA))
def test_manifest_block_loading(name):
    entry = MANIFEST_DATA[name]
    if entry["block"] not in RELEVANT_BLOCKS:
        return  # agent/egress blocks belong to T21/T22; see test (g)
    if entry["valid"]:
        policy = _load(name)
        assert policy.schema_version == 2
    else:
        with pytest.raises(PolicyParseError) as exc:
            _load(name)
        assert exc.value.field == entry["field"]


@pytest.mark.parametrize("name", sorted(MANIFEST_DATA))
def test_manifest_schema_decision_matches_loader(name):
    """Schema and loader agree on every relevant fixture.

    loader_only entries are valid: false in the manifest: the loader rejects
    them while the JSON Schema accepts them (date order, CIDR validity;
    SPEC §14.8).
    """
    entry = MANIFEST_DATA[name]
    if entry["block"] not in RELEVANT_BLOCKS:
        return
    # Import lazily so the schema test module stays the schema owner.
    import yaml

    from tests.test_json_schema import validate

    with open(_fixture(name), encoding="utf-8") as fh:
        document = yaml.safe_load(fh)
    errors = validate(document)
    if entry["loader_only"]:
        assert errors == [], name
        with pytest.raises(PolicyParseError):
            _load(name)
    elif entry["valid"]:
        assert errors == [], name
    else:
        assert errors, name


# --- (b) mode ----------------------------------------------------------------


def test_mode_observe():
    assert _load("valid_mode_observe.yaml").mode is EnforcementMode.OBSERVE


def test_mode_default_enforce():
    assert _load("valid_minimal.yaml").mode is EnforcementMode.ENFORCE


@pytest.mark.parametrize("name", ["valid_policy.yaml", "demo_policy.yaml"])
def test_mode_v1_is_enforce(name):
    assert (
        load_policy(REPO / "tests" / "fixtures" / name).mode is EnforcementMode.ENFORCE
    )


def test_mode_invalid_value():
    with open(V2 / "valid_minimal.yaml", encoding="utf-8") as fh:
        raw = fh.read()
    raw = raw.replace("schema_version: 2", "schema_version: 2\nmode: audit")
    import yaml

    document = yaml.safe_load(raw)
    with pytest.raises(PolicyParseError) as exc:
        parse_policy(document)
    assert exc.value.field == "mode"


# --- (c) sandbox -------------------------------------------------------------


def test_sandbox_parsed():
    policy = _load("valid_sandbox.yaml")
    sandbox = policy.sandbox
    assert sandbox is not None
    assert sandbox.resources.pids_max == 256
    assert sandbox.filesystem.read == ("/workspace/**",)
    assert isinstance(sandbox.filesystem.read, tuple)
    assert isinstance(sandbox.syscalls.deny, tuple)
    assert sandbox.imds == "deny"
    assert sandbox.credentials.max_ttl_seconds == 900


def test_sandbox_rejects_int_float():
    import yaml

    with open(V2 / "valid_sandbox.yaml", encoding="utf-8") as fh:
        document = yaml.safe_load(fh)
    document["sandbox"]["resources"]["pids_max"] = 256.0
    with pytest.raises(PolicyParseError) as exc:
        parse_policy(document)
    assert exc.value.field == "sandbox.resources.pids_max"


def test_sandbox_rejects_bool_int():
    import yaml

    with open(V2 / "valid_sandbox.yaml", encoding="utf-8") as fh:
        document = yaml.safe_load(fh)
    document["sandbox"]["resources"]["pids_max"] = True
    with pytest.raises(PolicyParseError) as exc:
        parse_policy(document)
    assert exc.value.field == "sandbox.resources.pids_max"


def test_sandbox_subblock_must_be_mapping():
    import yaml

    with open(V2 / "valid_sandbox.yaml", encoding="utf-8") as fh:
        document = yaml.safe_load(fh)
    document["sandbox"]["filesystem"] = None
    with pytest.raises(PolicyParseError) as exc:
        parse_policy(document)
    assert exc.value.field == "sandbox.filesystem"


# --- (d) approval ------------------------------------------------------------


def test_approval_parsed():
    policy = _load("valid_approval.yaml")
    assert policy.approval.timeout_seconds == 300
    assert policy.approval.on_timeout == "deny"


def test_approval_rejects_float_timeout():
    import yaml

    with open(V2 / "valid_approval.yaml", encoding="utf-8") as fh:
        document = yaml.safe_load(fh)
    document["approval"]["timeout_seconds"] = 300.5
    with pytest.raises(PolicyParseError) as exc:
        parse_policy(document)
    assert exc.value.field == "approval.timeout_seconds"


# --- (e) extensions ----------------------------------------------------------


def test_top_level_extensions():
    policy = _load("valid_extensions.yaml")
    assert policy.extensions == {"x-vendor": {"tier": 1}}


# --- (f) source_sha256 -------------------------------------------------------


def test_source_sha256_from_file():
    path = _fixture("valid_minimal.yaml")
    policy = load_policy(path)
    assert policy.source_sha256 == hashlib.sha256(path.read_bytes()).hexdigest()
    assert len(policy.source_sha256) == 64


def test_parse_policy_has_empty_sha():
    import yaml

    with open(_fixture("valid_minimal.yaml"), encoding="utf-8") as fh:
        document = yaml.safe_load(fh)
    assert parse_policy(document).source_sha256 == ""


# --- (g) unknown v2 blocks fail closed in this ticket ------------------------


@pytest.mark.parametrize(
    ("name", "block"), [("valid_agent.yaml", "agent"), ("valid_egress.yaml", "egress")]
)
def test_unparsed_block_never_dropped(name, block):
    # Either rejected with field == block (until T21/T22) or loaded with the
    # block present (after); loaded without the block must never happen.
    try:
        policy = _load(name)
    except PolicyParseError as exc:
        assert exc.field == block
    else:
        assert getattr(policy, block, None) is not None


# --- (h) observe mode is still fail-closed -----------------------------------


def test_observe_deny_and_guarded_raises():
    from dataclasses import replace
    from datetime import datetime, timedelta, timezone

    # The window must contain the real clock: guarded() calls enforce() with now=None.
    now = datetime.now(timezone.utc)
    policy = replace(
        _load("valid_mode_observe.yaml"),
        valid_from=now - timedelta(days=1),
        valid_until=now + timedelta(days=1),
    )
    engagement = Engagement(policy=policy)
    decision = enforce(engagement, "203.0.113.7", "tool.http.get")
    assert decision.outcome is DecisionType.DENY
    assert decision.reason_code == "TARGET_NOT_IN_SCOPE"
    assert decision.mode is EnforcementMode.OBSERVE

    calls = {"count": 0}

    @guarded(engagement, "tool.http.get")
    def do_work(target):
        calls["count"] += 1
        return "ok"

    with pytest.raises(OutOfScopeError):
        do_work(target="203.0.113.7")
    assert calls["count"] == 0


# --- (i) non-UTF-8 file ------------------------------------------------------


def test_invalid_utf8_rejected(tmp_path):
    bad = tmp_path / "bad.yaml"
    bad.write_bytes(b"\xff\xfe")
    with pytest.raises(PolicyParseError) as exc:
        load_policy(bad)
    assert exc.value.field == str(bad)


def test_invalid_utf8_byte_in_valid_policy_rejected(tmp_path):
    # A valid policy with one stray byte must not load (no lenient decoding).
    bad = tmp_path / "stray.yaml"
    bad.write_bytes(_fixture("valid_minimal.yaml").read_bytes() + b"# \xff\n")
    with pytest.raises(PolicyParseError) as exc:
        load_policy(bad)
    assert exc.value.field == str(bad)
    assert "UTF-8" in str(exc.value)


# --- (j) positional Decision still works -------------------------------------


def test_decision_positional_construction():
    from datetime import datetime, timezone

    from roe_guard.models import Decision

    now = datetime(2026, 8, 10, 12, 0, 0, tzinfo=timezone.utc)
    d = Decision(DecisionType.ALLOW, "r", "t", "a", now)
    assert d.reason_code == ""
    assert d.matched_rule == ""
    assert d.mode is EnforcementMode.ENFORCE


# --- fail-closed details (SPEC §14.1, §14.2) --------------------------------


def _doc(name="valid_minimal.yaml"):
    import yaml

    with open(_fixture(name), encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def _field_of(document):
    with pytest.raises(PolicyParseError) as exc:
        parse_policy(document)
    return exc.value.field


@pytest.mark.parametrize(
    ("patch", "field"),
    [
        ({"sandbox": {"foo": 1}}, "sandbox.foo"),
        ({"sandbox": {"filesytem": {"read": ["/"]}}}, "sandbox.filesytem"),
        ({"sandbox": {"schema_version": "x"}}, "sandbox.schema_version"),
        ({"sandbox": {"filesystem": {"foo": 1}}}, "sandbox.filesystem.foo"),
        ({"sandbox": {"syscalls": {"foo": 1}}}, "sandbox.syscalls.foo"),
        ({"sandbox": {"resources": {"foo": 1}}}, "sandbox.resources.foo"),
        ({"sandbox": {"credentials": {"foo": 1}}}, "sandbox.credentials.foo"),
        ({"approval": {"timeout_seconds": 60, "foo": 1}}, "approval.foo"),
    ],
)
def test_v2_unknown_key_in_new_blocks_rejected(patch, field):
    document = _doc()
    document.update(patch)
    assert _field_of(document) == field


def test_v2_x_keys_allowed_in_new_blocks():
    document = _doc()
    document["sandbox"] = {"x-note": "n", "filesystem": {"x-note": "n"}}
    document["approval"] = {"timeout_seconds": 60, "x-note": "n"}
    assert parse_policy(document).sandbox is not None


@pytest.mark.parametrize(
    ("patch", "field"),
    [
        ({"actions": []}, "actions"),
        ({"actions": ""}, "actions"),
        ({"actions": False}, "actions"),
        (
            {"scope": {"allow": [{"hostname": "*.api.example.com"}], "deny": {}}},
            "scope.deny",
        ),
        ({"scope": {"allow": ""}}, "scope.allow"),
        ({"blackout_windows": ""}, "blackout_windows"),
        ({"blackout_windows": {}}, "blackout_windows"),
        (
            {
                "blackout_windows": [
                    {
                        "start": "2026-10-01T01:00:00Z",
                        "end": "2026-10-01T02:00:00Z",
                        "reason": 0,
                    }
                ]
            },
            "blackout_windows[0].reason",
        ),
        ({"approval_required_for": ""}, "approval_required_for"),
        ({"approvers": {}}, "approvers"),
        ({"scope": None}, "scope"),
    ],
)
def test_v2_v1_fields_reject_wrong_types(patch, field):
    document = _doc()
    document.update(patch)
    assert _field_of(document) == field


def test_v2_v1_fields_accept_null():
    for key in ("actions", "blackout_windows", "approval_required_for", "approvers"):
        document = _doc()
        document[key] = None
        assert parse_policy(document).schema_version == 2, key
    document = _doc()
    document["scope"] = {"allow": None, "deny": None}
    assert parse_policy(document).scope.allow == []


def test_v1_keeps_falsy_coercion():
    # SPEC §14.6 a: v1 behaviour is unchanged.
    import yaml

    with open(
        REPO / "tests" / "fixtures" / "valid_policy.yaml", encoding="utf-8"
    ) as fh:
        document = yaml.safe_load(fh)
    document["actions"] = []
    document["blackout_windows"] = ""
    policy = parse_policy(document)
    assert policy.actions_allow == [] and policy.blackout_windows == []


@pytest.mark.parametrize("value", [None, [], "x", 5, b"x"])
def test_parse_policy_rejects_non_mapping(value):
    with pytest.raises(PolicyParseError) as exc:
        parse_policy(value)
    assert exc.value.field == "<top>"


def test_mode_null_rejected():
    document = _doc()
    document["mode"] = None
    assert _field_of(document) == "mode"


@pytest.mark.parametrize(
    ("block", "key"),
    [("syscalls", "profile"), ("resources", "memory_max"), ("resources", "cpu_max")],
)
def test_sandbox_string_fields_reject_null(block, key):
    document = _doc()
    document["sandbox"] = {block: {key: None}}
    assert _field_of(document) == f"sandbox.{block}.{key}"


@pytest.mark.parametrize("value", [True, 256.0, 0, -1, "1", None])
@pytest.mark.parametrize(
    ("patch_path", "field"),
    [
        (("sandbox", "resources", "pids_max"), "sandbox.resources.pids_max"),
        (
            ("sandbox", "credentials", "max_ttl_seconds"),
            "sandbox.credentials.max_ttl_seconds",
        ),
        (("approval", "timeout_seconds"), "approval.timeout_seconds"),
    ],
)
def test_int_fields_reject_bool_float_and_non_positive(value, patch_path, field):
    document = _doc()
    if patch_path[0] == "sandbox":
        document["sandbox"] = {patch_path[1]: {patch_path[2]: value}}
    else:
        document["approval"] = {patch_path[1]: value}
    assert _field_of(document) == field


@pytest.mark.parametrize(
    ("patch", "field"),
    [
        ({"sandbox": None}, "sandbox"),
        ({"approval": None}, "approval"),
        ({"sandbox": {"filesystem": None}}, "sandbox.filesystem"),
        ({"sandbox": {"syscalls": None}}, "sandbox.syscalls"),
        ({"sandbox": {"resources": None}}, "sandbox.resources"),
        ({"sandbox": {"credentials": None}}, "sandbox.credentials"),
        ({"sandbox": {"filesystem": {"read": None}}}, "sandbox.filesystem.read"),
        ({"sandbox": {"syscalls": {"deny": None}}}, "sandbox.syscalls.deny"),
        ({"sandbox": {"imds": "allow"}}, "sandbox.imds"),
        (
            {"approval": {"timeout_seconds": 60, "on_timeout": "allow"}},
            "approval.on_timeout",
        ),
    ],
)
def test_v2_null_blocks_and_values_rejected(patch, field):
    document = _doc()
    document.update(patch)
    assert _field_of(document) == field


def test_parse_policy_warning_points_at_caller():
    import warnings

    import yaml

    from roe_guard.exceptions import UnknownKeyWarning

    with open(
        REPO / "tests" / "fixtures" / "valid_policy.yaml", encoding="utf-8"
    ) as fh:
        document = yaml.safe_load(fh)
    document["unknown_v1_key"] = 1
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        parse_policy(document)
    hits = [w for w in caught if issubclass(w.category, UnknownKeyWarning)]
    assert hits and hits[0].filename == __file__
