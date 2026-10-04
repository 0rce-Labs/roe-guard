"""Audit v2 conformance: every case in conformance/audit/cases.json runs."""

import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from roe_guard.audit_v2 import verify_chain

REPO = Path(__file__).resolve().parent.parent
AUDIT_CASES = REPO / "conformance" / "audit" / "cases.json"
JCS_CASES = REPO / "conformance" / "jcs" / "cases.json"
RECORD_SCHEMA = REPO / "schema" / "audit-record.v2.json"
CHECKPOINT_SCHEMA = REPO / "schema" / "audit-checkpoint.v2.json"

with open(AUDIT_CASES, encoding="utf-8") as _fh:
    AUDIT = json.load(_fh)
with open(JCS_CASES, encoding="utf-8") as _fh:
    JCS = json.load(_fh)
with open(RECORD_SCHEMA, encoding="utf-8") as _fh:
    _RECORD_SCHEMA = json.load(_fh)
with open(CHECKPOINT_SCHEMA, encoding="utf-8") as _fh:
    _CHECKPOINT_SCHEMA = json.load(_fh)


def _run_case(case):
    path = Path(case["id"] + ".jsonl")
    path.write_text("".join(line + "\n" for line in case["chain"]), encoding="utf-8")
    kwargs = {}
    if case.get("checkpoints") is not None:
        ckpt = Path(case["id"] + ".checkpoints.jsonl")
        ckpt.write_text(
            "".join(line + "\n" for line in case["checkpoints"]), encoding="utf-8"
        )
        kwargs["checkpoints_path"] = str(ckpt)
    if case.get("public_keys"):
        kwargs["public_keys"] = {
            k: bytes.fromhex(v) for k, v in case["public_keys"].items()
        }
    try:
        return verify_chain(path, **kwargs)
    finally:
        path.unlink(missing_ok=True)
        if "ckpt" in dir():
            Path(kwargs["checkpoints_path"]).unlink(missing_ok=True)


@pytest.mark.parametrize("case", AUDIT["cases"], ids=lambda c: c["id"])
def test_audit_case(case):
    result = _run_case(case)
    expected = case["expected"]
    assert result.valid == expected["valid"], (case["id"], result.reason)
    assert result.reason_code == expected["reason_code"], (
        case["id"],
        result.reason_code,
    )
    if expected["broken_at_index"] is None:
        assert result.broken_at_index is None, case["id"]
    else:
        assert result.broken_at_index == expected["broken_at_index"], case["id"]


def test_all_15_line_and_checkpoint_codes_covered():
    covered = {case["expected"]["reason_code"] for case in AUDIT["cases"]}
    for code in (
        "VERSION_DOWNGRADE",
        "UNKNOWN_FIELD",
        "ENTRY_HASH_MISMATCH",
        "SEQ_MISMATCH",
        "TIMESTAMP_FORMAT",
        "UNKNOWN_VERSION",
        "CHAIN_TRUNCATED",
        "CHECKPOINT_SIGNATURE_INVALID",
        "CHECKPOINT_KEY_UNKNOWN",
        "CHECKPOINT_HEAD_MISMATCH",
        "CHAIN_ID_MISMATCH",
        "PREV_HASH_MISMATCH",
        "MALFORMED",
        "INVALID_JSON",
    ):
        assert code in covered, code


def test_valid_case_lines_match_schemas():
    for case in AUDIT["cases"]:
        if not case["expected"]["valid"]:
            continue
        for line in case["chain"]:
            record = json.loads(line)
            if record.get("v") == 2:
                errors = list(Draft202012Validator(_RECORD_SCHEMA).iter_errors(record))
                assert errors == [], (case["id"], errors)
        for line in case.get("checkpoints") or []:
            checkpoint = json.loads(line)
            errors = list(
                Draft202012Validator(_CHECKPOINT_SCHEMA).iter_errors(checkpoint)
            )
            assert errors == [], (case["id"], errors)


@pytest.mark.parametrize("case", JCS["cases"], ids=lambda c: c["id"])
def test_jcs_case(case):
    if "expected_error" in case:
        from roe_guard.jcs import canonicalize

        value = json.loads(case["input_json"])
        with pytest.raises((TypeError, ValueError)):
            canonicalize(value)
        return
    from roe_guard.jcs import canonicalize

    value = json.loads(case["input_json"])
    assert canonicalize(value).hex() == case["expected_hex"], case["id"]
