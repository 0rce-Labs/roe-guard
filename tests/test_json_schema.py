"""JSON Schema validation tests for policy v1 and v2 (roe-guard T19 / 0retty T-082).

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
    version = document.get("schema_version", 1)
    return SCHEMA_V2 if version == 2 else SCHEMA_V1


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


def test_manifest_entries_match_expected_validity():
    manifest_path = FIXTURES_V2 / "manifest.json"
    with open(manifest_path, encoding="utf-8") as fh:
        manifest = json.load(fh)
    for name, entry in manifest.items():
        document = load_yaml(FIXTURES_V2 / name)
        errors = validate(document)
        if entry.get("valid") or entry.get("loader_only"):
            assert errors == [], f"{name}: expected schema-valid, got {errors}"
        else:
            assert errors, f"{name}: expected schema-invalid"


def test_manifest_covers_every_v2_fixture():
    with open(FIXTURES_V2 / "manifest.json", encoding="utf-8") as fh:
        manifest = json.load(fh)
    on_disk = sorted(p.name for p in FIXTURES_V2.glob("*.yaml"))
    assert sorted(manifest) == on_disk
