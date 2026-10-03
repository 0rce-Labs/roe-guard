"""JSON Schema validation tests for policy v1 and v2 (T19).

The schemas are structural: date ordering, CIDR validity and ISO-8601
parsing stay in the loader (SPEC §14.8).
"""

import json
from pathlib import Path

import yaml
from jsonschema import Draft202012Validator

REPO = Path(__file__).resolve().parent.parent
SCHEMA_V1 = REPO / "schema" / "policy.v1.json"
SCHEMA_V2 = REPO / "schema" / "policy.v2.json"
FIXTURES_V1 = REPO / "tests" / "fixtures"
FIXTURES_V2 = REPO / "tests" / "fixtures" / "v2"


def load_schema(path):
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def pick_schema(document):
    # Missing or exactly 1 selects v1; everything else (2, 3, "2", true, ...) selects v2.
    version = document.get("schema_version", 1)
    if version == 1 and not isinstance(version, bool):
        return SCHEMA_V1
    return SCHEMA_V2


def v2_errors(document):
    return list(Draft202012Validator(load_schema(SCHEMA_V2)).iter_errors(document))


def validate(document):
    schema = load_schema(pick_schema(document))
    Draft202012Validator.check_schema(schema)
    validator = Draft202012Validator(schema)
    return list(validator.iter_errors(document))


def load_yaml(path):
    with open(path, encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def test_both_schemas_are_valid_draft_2020_12():
    for path in (SCHEMA_V1, SCHEMA_V2):
        Draft202012Validator.check_schema(load_schema(path))


def test_v1_valid_fixtures_pass():
    for name in ("valid_policy.yaml", "demo_policy.yaml"):
        assert validate(load_yaml(FIXTURES_V1 / name)) == [], name


def test_v1_missing_required_field_rejected():
    errors = validate(load_yaml(FIXTURES_V1 / "missing_required_field.yaml"))
    assert errors, "missing_required_field.yaml must fail the v1 schema"


# CIDR validity and date formatting are loader-only checks: the v1 schema
# accepts invalid_cidr.yaml and malformed_dates.yaml structurally.
def test_v1_invalid_cidr_passes_schema():
    assert validate(load_yaml(FIXTURES_V1 / "invalid_cidr.yaml")) == []


def test_v1_malformed_dates_pass_schema():
    assert validate(load_yaml(FIXTURES_V1 / "malformed_dates.yaml")) == []


def test_v1_rejects_v2_reserved_top_level_key():
    with open(FIXTURES_V1 / "valid_policy.yaml", encoding="utf-8") as fh:
        document = yaml.safe_load(fh)
    document["egress"] = {}
    assert validate(document), "v2-reserved key at top level must fail the v1 schema"


def test_v1_fixtures_fail_v2_schema():
    for name in ("valid_policy.yaml", "demo_policy.yaml"):
        document = load_yaml(FIXTURES_V1 / name)
        schema = load_schema(SCHEMA_V2)
        Draft202012Validator.check_schema(schema)
        errors = list(Draft202012Validator(schema).iter_errors(document))
        assert errors, f"{name} must fail the v2 schema (versions stay separate)"


def load_manifest():
    with open(FIXTURES_V2 / "manifest.json", encoding="utf-8") as fh:
        return json.load(fh)


def test_manifest_entry_shape():
    loader_only = []
    for name, entry in load_manifest().items():
        expected_keys = {"valid", "block", "loader_only"} | (
            set() if entry["valid"] else {"field"}
        )
        assert set(entry) == expected_keys, name
        assert isinstance(entry["valid"], bool) and isinstance(
            entry["loader_only"], bool
        ), name
        assert not (entry["valid"] and entry["loader_only"]), name
        if entry["loader_only"]:
            loader_only.append(name)
    assert sorted(loader_only) == [
        "invalid_egress_cidr.yaml",
        "invalid_window_order.yaml",
    ]


def test_manifest_entries_match_expected_validity():
    for name, entry in load_manifest().items():
        document = load_yaml(FIXTURES_V2 / name)
        errors = validate(document)
        if entry["valid"] or entry["loader_only"]:
            assert errors == [], f"{name}: expected schema-valid, got {errors}"
        else:
            assert errors, f"{name}: expected schema-invalid"


def test_manifest_covers_every_v2_fixture():
    on_disk = sorted(p.name for p in FIXTURES_V2.glob("*.yaml"))
    assert sorted(load_manifest()) == on_disk


def test_v1_schema_rejects_other_versions():
    document = load_yaml(FIXTURES_V1 / "valid_policy.yaml")
    for version in (2, True, "1"):
        document["schema_version"] = version
        errors = list(
            Draft202012Validator(load_schema(SCHEMA_V1)).iter_errors(document)
        )
        assert errors, f"v1 schema must reject schema_version {version!r}"


def test_v2_keeps_v1_field_types():
    # v1 fields keep their v1 types in v2: null lists and a null actions block are accepted.
    for key in ("actions", "blackout_windows", "approval_required_for", "approvers"):
        document = load_yaml(FIXTURES_V2 / "valid_minimal.yaml")
        document[key] = None
        assert v2_errors(document) == [], key
    nested = [
        {"scope": {"allow": None}},
        {"scope": {"allow": [{"hostname": "*.api.example.com"}], "deny": None}},
        {"actions": {"allow": None}},
        {"actions": {"allow": ["tool.http.get"], "deny": None}},
        {
            "blackout_windows": [
                {
                    "start": "2026-10-01T01:00:00Z",
                    "end": "2026-10-01T02:00:00Z",
                    "reason": None,
                }
            ]
        },
    ]
    for patch in nested:
        document = load_yaml(FIXTURES_V2 / "valid_minimal.yaml")
        document.update(patch)
        assert v2_errors(document) == [], patch


def test_v2_rejects_null_new_blocks():
    cases = {
        "agent": None,
        "sandbox": None,
        "egress": None,
        "approval": None,
    }
    for key, value in cases.items():
        document = load_yaml(FIXTURES_V2 / "valid_minimal.yaml")
        document[key] = value
        assert v2_errors(document), f"{key}: null must fail the v2 schema"
    nested = {
        "sandbox": [
            {"filesystem": None},
            {"syscalls": None},
            {"resources": None},
            {"credentials": None},
        ],
        "egress": [
            {"http": None},
            {"dns": None},
            {"http": {"allow": None}},
            {"http": {"deny": None}},
        ],
    }
    for key, values in nested.items():
        for value in values:
            document = load_yaml(FIXTURES_V2 / "valid_minimal.yaml")
            document[key] = value
            assert v2_errors(document), f"{key}={value!r} must fail the v2 schema"


def test_v2_rejects_empty_methods_and_bad_entries():
    bad_entries = [
        {"host": "api.example.com", "ports": [443], "methods": []},
        {"host": "api.example.com", "ports": [443], "methods": ["get"]},
        {"host": "api.example.com", "ports": []},
        {"host": "api.example.com"},
        {"host": "api.example.com", "cidr": "198.51.100.0/24", "ports": [443]},
        {"ports": [443]},
    ]
    for entry in bad_entries:
        document = load_yaml(FIXTURES_V2 / "valid_minimal.yaml")
        document["egress"] = {"http": {"allow": [entry]}}
        assert v2_errors(document), (
            f"egress.http.allow entry {entry!r} must fail the v2 schema"
        )


def test_v2_rejects_unknown_key_in_every_block():
    blocks = {
        "scope": {"allow": [{"hostname": "*.api.example.com"}], "zz": 1},
        "actions": {"allow": ["tool.http.get"], "zz": 1},
        "agent": {"id": "spiffe://example.org/a", "zz": 1},
        "sandbox": {"zz": 1},
        "egress": {"zz": 1},
        "approval": {"timeout_seconds": 60, "zz": 1},
    }
    for key, value in blocks.items():
        document = load_yaml(FIXTURES_V2 / "valid_minimal.yaml")
        document[key] = value
        assert v2_errors(document), f"unknown key in {key} must fail the v2 schema"
    nested = [
        {"scope": {"allow": [{"hostname": "*.api.example.com", "zz": 1}]}},
        {"sandbox": {"filesystem": {"zz": 1}}},
        {"sandbox": {"syscalls": {"zz": 1}}},
        {"sandbox": {"resources": {"zz": 1}}},
        {"sandbox": {"credentials": {"zz": 1}}},
        {"egress": {"http": {"zz": 1}}},
        {"egress": {"dns": {"zz": 1}}},
        {
            "egress": {
                "http": {
                    "allow": [{"host": "api.example.com", "ports": [443], "zz": 1}]
                }
            }
        },
        {"egress": {"http": {"deny": [{"host": "api.example.com", "zz": 1}]}}},
        {
            "blackout_windows": [
                {
                    "start": "2026-10-01T01:00:00Z",
                    "end": "2026-10-01T02:00:00Z",
                    "zz": 1,
                }
            ]
        },
    ]
    for patch in nested:
        document = load_yaml(FIXTURES_V2 / "valid_minimal.yaml")
        document.update(patch)
        assert v2_errors(document), (
            f"unknown nested key {patch!r} must fail the v2 schema"
        )


def test_v2_accepts_x_keys_in_every_object():
    x = {"x-n": 1}
    document = load_yaml(FIXTURES_V2 / "valid_minimal.yaml")
    document.update(
        {
            "x-root": 1,
            "scope": {
                "allow": [{"hostname": "*.api.example.com", **x}],
                "deny": None,
                **x,
            },
            "actions": {"allow": ["tool.http.get"], **x},
            "blackout_windows": [
                {"start": "2026-10-01T01:00:00Z", "end": "2026-10-01T02:00:00Z", **x}
            ],
            "agent": {"id": "spiffe://example.org/a", **x},
            "sandbox": {
                "filesystem": {**x},
                "syscalls": {**x},
                "resources": {**x},
                "credentials": {**x},
                **x,
            },
            "egress": {
                "http": {
                    "allow": [{"host": "api.example.com", "ports": [443], **x}],
                    "deny": [{"host": "bad.example.com", **x}],
                    **x,
                },
                "dns": {**x},
                **x,
            },
            "approval": {"timeout_seconds": 60, **x},
        }
    )
    assert v2_errors(document) == []
