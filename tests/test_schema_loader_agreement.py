"""Schema/loader agreement over every manifest fixture plus three inline vectors.

The inline vectors cover loader-only checks (SPEC §14.8): no fixture
is added and the manifest stays at 22 entries.
"""

import json
from pathlib import Path

import pytest
import yaml
from jsonschema import Draft202012Validator

from roe_guard import PolicyParseError, load_policy, parse_policy

REPO = Path(__file__).resolve().parent.parent
V2 = REPO / "tests" / "fixtures" / "v2"
SCHEMA_V1 = REPO / "schema" / "policy.v1.json"
SCHEMA_V2 = REPO / "schema" / "policy.v2.json"

with open(V2 / "manifest.json", encoding="utf-8") as _fh:
    MANIFEST = json.load(_fh)


def _schema_for(document):
    path = SCHEMA_V2 if document.get("schema_version") == 2 else SCHEMA_V1
    with open(path, encoding="utf-8") as fh:
        schema = json.load(fh)
    Draft202012Validator.check_schema(schema)
    return schema


def _schema_errors(document):
    return list(Draft202012Validator(_schema_for(document)).iter_errors(document))


def _load_yaml(path):
    with open(path, encoding="utf-8") as fh:
        return yaml.safe_load(fh)


@pytest.mark.parametrize("name", sorted(MANIFEST))
def test_manifest_agreement(name):
    entry = MANIFEST[name]
    document = _load_yaml(V2 / name)
    if entry["valid"]:
        # Loader accepts it.
        assert load_policy(V2 / name).schema_version >= 1
        # Schema also accepts it (loader_only entries are schema-valid too).
        assert _schema_errors(document) == [], name
    else:
        # Loader rejects with the manifest field path.
        with pytest.raises(PolicyParseError) as exc:
            load_policy(V2 / name)
        assert exc.value.field == entry["field"]
        # Schema rejects too, unless the rejection is loader-only.
        if not entry.get("loader_only"):
            assert _schema_errors(document), name
        else:
            assert _schema_errors(document) == [], name


# --- inline vectors (SPEC §14.8; fixture count stays 22) -----------------------

_BASE = {
    "schema_version": 2,
    "engagement_id": "inline-agreement",
    "valid_from": "2026-10-01T00:00:00Z",
    "valid_until": "2026-10-02T00:00:00Z",
    "scope": {"allow": [{"hostname": "*.api.example.com"}]},
    "actions": {"allow": ["tool.http.get"]},
}


def _inline(mutate):
    import copy

    document = copy.deepcopy(_BASE)
    mutate(document)
    return document


def test_inline_actions_null_valid_both():
    document = _inline(lambda d: d.__setitem__("actions", None))
    assert _schema_errors(document) == []
    parse_policy(document)


def test_inline_schema_version_float_loader_only():
    document = _inline(lambda d: d.__setitem__("schema_version", 2.0))
    assert _schema_errors(document) == []
    with pytest.raises(PolicyParseError) as exc:
        parse_policy(document)
    assert exc.value.field == "schema_version"


def test_inline_pids_max_float_loader_only():
    def mutate(d):
        d["sandbox"] = {"resources": {"pids_max": 256.0}}

    document = _inline(mutate)
    assert _schema_errors(document) == []
    with pytest.raises(PolicyParseError) as exc:
        parse_policy(document)
    assert exc.value.field == "sandbox.resources.pids_max"
