"""schema_version guard: fail-closed rejection of unsupported versions."""

import pytest
import yaml

from roe_guard.exceptions import PolicyParseError
from roe_guard.policy import load_policy

BASE = {
    "engagement_id": "sv-test",
    "valid_from": "2026-10-01T00:00:00Z",
    "valid_until": "2026-10-02T00:00:00Z",
    "scope": {"allow": [{"cidr": "10.0.0.0/8"}]},
    "actions": {"allow": ["tool.read"]},
}

NOW = "2026-10-01T12:00:00Z"


def _write(tmp_path, data, name="policy.yaml"):
    p = tmp_path / name
    p.write_text(yaml.safe_dump(data), encoding="utf-8")
    return str(p)


def test_missing_field_defaults_to_one(tmp_path):
    p = _write(tmp_path, dict(BASE))
    assert load_policy(p).schema_version == 1


def test_explicit_one(tmp_path):
    data = dict(BASE, schema_version=1)
    p = _write(tmp_path, data)
    assert load_policy(p).schema_version == 1


def test_fixtures_default_to_one():
    from pathlib import Path

    fixtures = Path(__file__).parent / "fixtures"
    assert load_policy(str(fixtures / "valid_policy.yaml")).schema_version == 1
    assert load_policy(str(fixtures / "demo_policy.yaml")).schema_version == 1


@pytest.mark.parametrize(
    "value",
    [2, 99, 0, -1, "1", True, 1.0, None],
)
def test_invalid_versions_rejected(tmp_path, value):
    data = dict(BASE, schema_version=value)
    p = _write(tmp_path, data)
    with pytest.raises(PolicyParseError) as exc:
        load_policy(p)
    assert exc.value.field == "schema_version"
    if value in (2, 99):
        assert f"unsupported schema_version {value}" in str(exc.value)
        assert "supports up to 1" in str(exc.value)


def test_version_checked_before_required_fields(tmp_path):
    data = {"schema_version": 99}
    p = _write(tmp_path, data)
    with pytest.raises(PolicyParseError) as exc:
        load_policy(p)
    assert exc.value.field == "schema_version"


def test_cli_validate_rejects_unsupported(tmp_path, capsys):
    from roe_guard.cli import main

    data = dict(BASE, schema_version=99)
    p = _write(tmp_path, data)
    assert main(["validate", p]) == 1
    _, err = capsys.readouterr()
    assert "schema_version" in err


def test_cli_check_rejects_unsupported(tmp_path, capsys):
    from roe_guard.cli import main

    data = dict(BASE, schema_version=99)
    p = _write(tmp_path, data)
    args = [
        "check",
        "--target",
        "10.1.2.3",
        "--action",
        "tool.read",
        "--policy",
        p,
        "--now",
        NOW,
    ]
    assert main(args) == 1
    out, err = capsys.readouterr()
    assert "schema_version" in err
    assert "outcome" not in out.lower()


def test_cli_check_allows_base(tmp_path, capsys):
    from roe_guard.cli import main

    p = _write(tmp_path, dict(BASE))
    args = [
        "check",
        "--target",
        "10.1.2.3",
        "--action",
        "tool.read",
        "--policy",
        p,
        "--now",
        NOW,
    ]
    assert main(args) == 0
    capsys.readouterr()


def test_max_schema_version_exported():
    from roe_guard import MAX_SCHEMA_VERSION

    assert MAX_SCHEMA_VERSION == 1
