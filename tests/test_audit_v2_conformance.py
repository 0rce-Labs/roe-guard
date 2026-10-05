"""Audit v2 conformance: every case in conformance/audit/cases.json runs."""

import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from roe_guard.audit_v2 import AuditReasonCode, verify_chain
from roe_guard.jcs import canonicalize

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


def _run_case(case, tmp_path):
    path = tmp_path / "audit.jsonl"
    path.write_text("".join(line + "\n" for line in case["chain"]), encoding="utf-8")
    kwargs = {}
    if case.get("checkpoints") is not None:
        ckpt = tmp_path / "audit.jsonl.checkpoints.jsonl"
        ckpt.write_text(
            "".join(line + "\n" for line in case["checkpoints"]), encoding="utf-8"
        )
        kwargs["checkpoints_path"] = ckpt
    if case.get("public_keys"):
        kwargs["public_keys"] = {
            k: bytes.fromhex(v) for k, v in case["public_keys"].items()
        }
    return verify_chain(path, **kwargs)


@pytest.mark.parametrize("case", AUDIT["cases"], ids=lambda c: c["id"])
def test_audit_case(case, tmp_path):
    result = _run_case(case, tmp_path)
    expected = case["expected"]
    assert (result.valid, result.reason_code, result.broken_at_index) == (
        expected["valid"],
        expected["reason_code"],
        expected["broken_at_index"],
    ), (case["id"], result.reason)


def test_vector_files_have_known_format():
    assert (AUDIT["format"], AUDIT["suite"]) == (1, "audit-v2")
    assert (JCS["format"], JCS["suite"]) == (1, "jcs")
    ids = [case["id"] for case in AUDIT["cases"] + JCS["cases"]]
    assert len(ids) == len(set(ids))


def test_all_15_line_and_checkpoint_codes_covered():
    covered = {case["expected"]["reason_code"] for case in AUDIT["cases"]}
    wanted = {code.value for code in AuditReasonCode} - {
        "CHECKPOINT_MISSING",
        "SIGNING_BACKEND_UNAVAILABLE",
    }
    assert len(wanted) == 15
    assert wanted <= covered, sorted(wanted - covered)


def test_valid_case_lines_match_schemas():
    for case in AUDIT["cases"]:
        if not case["expected"]["valid"]:
            continue
        for line in case["chain"]:
            if not line.strip():
                continue  # v1 rules skip empty lines
            record = json.loads(line)
            if "v" in record:
                errors = list(Draft202012Validator(_RECORD_SCHEMA).iter_errors(record))
                assert errors == [], (case["id"], errors)
        for line in case.get("checkpoints") or []:
            checkpoint = json.loads(line)
            errors = list(
                Draft202012Validator(_CHECKPOINT_SCHEMA).iter_errors(checkpoint)
            )
            assert errors == [], (case["id"], errors)


_JCS_ERRORS = {
    "UNSUPPORTED_NUMBER": TypeError,
    "INTEGER_OUT_OF_RANGE": ValueError,
    "LONE_SURROGATE": ValueError,
    "NESTING_TOO_DEEP": ValueError,
}


@pytest.mark.parametrize("case", JCS["cases"], ids=lambda c: c["id"])
def test_jcs_case(case):
    value = json.loads(case["input_json"])
    if "expected_error" in case:
        with pytest.raises(_JCS_ERRORS[case["expected_error"]]):
            canonicalize(value)
        return
    assert canonicalize(value).hex() == case["expected_hex"], case["id"]
