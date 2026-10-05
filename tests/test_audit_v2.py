"""Audit v2 tests: writer, locking, mixed chains, checkpoints, tamper codes."""

import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

import roe_guard.exceptions
from roe_guard import (
    AuditLogV2,
    AuditWriterLockedError,
    Decision,
    DecisionType,
    Ed25519Signer,
    EnforcementMode,
    load_policy,
)
from roe_guard.audit import AuditLog
from roe_guard.audit_v2 import verify_chain
from roe_guard.exceptions import AuditIntegrityError
from roe_guard.jcs import canonicalize

REPO = Path(__file__).resolve().parent.parent

TEST_PRIVATE = bytes.fromhex(
    "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
)
TEST_PUBLIC = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
TEST_KEY_ID = "sha256:21fe31dfa154a261626bf854046fd2271b7bed4b6abe45aa58877ef47f9721b9"

NOW = datetime(2026, 10, 1, 10, 0, 0, tzinfo=timezone.utc)

POLICY_SHA = hashlib.sha256(b"policy-bytes").hexdigest()

_ENGAGEMENT = {
    "schema_version": 2,
    "engagement_id": "audit-eng",
    "valid_from": "2026-10-01T00:00:00Z",
    "valid_until": "2026-10-02T00:00:00Z",
    "scope": {"allow": [{"hostname": "*.api.example.com"}]},
    "actions": {"allow": ["tool.http.get"]},
}


def _decision(
    outcome=DecisionType.ALLOW,
    target="api.x.api.example.com",
    action_type="tool.http.get",
    reason="action type 'tool.http.get' allowed",
    reason_code="ACTION_ALLOWED",
    agent_id="spiffe://example.org/agent/a1",
    when=NOW,
):
    return Decision(
        outcome=outcome,
        reason=reason,
        target=target,
        action_type=action_type,
        timestamp=when,
        mode=EnforcementMode.ENFORCE,
        reason_code=reason_code,
        matched_rule="actions.allow",
        agent_id=agent_id,
    )


def _write(path, count=3, signer=None, checkpoint_every=1000):
    with AuditLogV2(
        path, chain_id="test-chain", signer=signer, checkpoint_every=checkpoint_every
    ) as log:
        for i in range(count):
            log.record(
                _decision(target=f"t{i}"),
                engagement_id="audit-eng",
                policy_sha256=POLICY_SHA,
                metadata={"i": i},
            )


# --- writer -------------------------------------------------------------------


def test_record_line_has_sixteen_keys(tmp_path):
    path = tmp_path / "audit.jsonl"
    _write(path, count=1)
    record = json.loads(path.read_text(encoding="utf-8").splitlines()[0])
    assert len(record) == 16
    assert set(record) == {
        "v",
        "seq",
        "chain_id",
        "timestamp",
        "engagement_id",
        "policy_sha256",
        "mode",
        "agent_id",
        "target",
        "action_type",
        "decision",
        "reason",
        "reason_code",
        "metadata",
        "prev_hash",
        "entry_hash",
    }


def test_timestamp_microsecond_format(tmp_path):
    path = tmp_path / "audit.jsonl"
    _write(path, count=1)
    record = json.loads(path.read_text(encoding="utf-8").splitlines()[0])
    assert record["timestamp"] == "2026-10-01T10:00:00.000000Z"


def test_seq_increments(tmp_path):
    path = tmp_path / "audit.jsonl"
    _write(path, count=3)
    records = [
        json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()
    ]
    assert [r["seq"] for r in records] == [0, 1, 2]


def test_prev_hash_chain(tmp_path):
    path = tmp_path / "audit.jsonl"
    _write(path, count=3)
    lines = path.read_text(encoding="utf-8").splitlines()
    records = [json.loads(line) for line in lines]
    assert records[0]["prev_hash"] == "0" * 64
    assert records[1]["prev_hash"] == records[0]["entry_hash"]
    assert records[2]["prev_hash"] == records[1]["entry_hash"]


def test_line_is_jcs_plus_newline(tmp_path):
    path = tmp_path / "audit.jsonl"
    _write(path, count=1)
    raw = path.read_bytes()
    assert raw.endswith(b"\n")
    record = json.loads(raw.decode("utf-8"))
    assert canonicalize(record) + b"\n" == raw


# --- locking ------------------------------------------------------------------


def test_second_writer_locked(tmp_path):
    path = tmp_path / "audit.jsonl"
    _write(path, count=1)
    assert AuditWriterLockedError is roe_guard.exceptions.AuditWriterLockedError
    with (
        AuditLogV2(path, chain_id="test-chain"),
        pytest.raises(AuditWriterLockedError),
        AuditLogV2(path, chain_id="test-chain"),
    ):
        pass


def test_writer_reopens_after_close(tmp_path):
    path = tmp_path / "audit.jsonl"
    _write(path, count=1)
    _write(path, count=1)
    result = verify_chain(path)
    assert result.valid
    assert result.total_entries == 2


def test_corrupt_existing_file_rejected_on_open(tmp_path):
    path = tmp_path / "audit.jsonl"
    _write(path, count=1)
    good = path.read_bytes()
    lines = good.splitlines()
    record = json.loads(lines[0])
    record["reason"] = "tampered"
    lines[0] = canonicalize(record)
    path.write_bytes(b"\n".join(lines) + b"\n")
    size = path.stat().st_size
    with pytest.raises(AuditIntegrityError):  # noqa: SIM117
        with AuditLogV2(path, chain_id="test-chain"):
            pass
    assert path.stat().st_size == size


# --- mixed v1 → v2 chains -------------------------------------------------------


def _v1_record(path, target, action="recon"):
    policy_path = REPO / "tests" / "fixtures" / "valid_policy.yaml"
    from roe_guard.engine import enforce
    from roe_guard.models import Engagement

    engagement = Engagement(policy=load_policy(policy_path))
    decision = enforce(
        engagement,
        target,
        action,
        now=datetime(2026, 8, 10, 12, 0, tzinfo=timezone.utc),
    )
    log = AuditLog(path)
    log.record(decision, engagement_id=engagement.policy.engagement_id)


def test_mixed_chain(tmp_path):
    path = tmp_path / "mixed.jsonl"
    _v1_record(path, "10.20.3.5")
    _v1_record(path, "10.20.3.6")
    with AuditLogV2(path, chain_id="mixed-chain") as log:
        log.record(_decision(), engagement_id="audit-eng", policy_sha256=POLICY_SHA)
        log.record(
            _decision(target="t2"), engagement_id="audit-eng", policy_sha256=POLICY_SHA
        )
    result = verify_chain(path)
    assert result.valid, result.reason
    lines = path.read_text(encoding="utf-8").splitlines()
    records = [json.loads(line) for line in lines]
    assert records[2]["seq"] == 2
    assert records[3]["seq"] == 3
    assert records[2]["prev_hash"] == records[1]["entry_hash"]
    v1_verify = AuditLog(path).verify()
    assert v1_verify.valid


def test_v1_cli_verify_mixed_chain(tmp_path):
    path = tmp_path / "mixed.jsonl"
    _v1_record(path, "10.20.3.5")
    with AuditLogV2(path, chain_id="mixed-chain") as log:
        log.record(_decision(), engagement_id="audit-eng", policy_sha256=POLICY_SHA)
    from roe_guard.cli import main

    assert main(["audit-verify", str(path)]) == 0


def test_v1_record_rejected_after_v2(tmp_path):
    path = tmp_path / "mixed.jsonl"
    _v1_record(path, "10.20.3.5")
    with AuditLogV2(path, chain_id="mixed-chain") as log:
        log.record(_decision(), engagement_id="audit-eng", policy_sha256=POLICY_SHA)
    size = path.stat().st_size
    with pytest.raises(AuditIntegrityError):
        _v1_record(path, "10.20.3.9")
    assert path.stat().st_size == size


# --- checkpoints -----------------------------------------------------------------


def test_checkpoints_every_two(tmp_path):
    path = tmp_path / "audit.jsonl"
    signer = Ed25519Signer(TEST_PRIVATE)
    with AuditLogV2(
        path, chain_id="ckpt-chain", signer=signer, checkpoint_every=2
    ) as log:
        for i in range(5):
            log.record(
                _decision(target=f"t{i}"),
                engagement_id="audit-eng",
                policy_sha256=POLICY_SHA,
            )
    ckpt_path = Path(str(path) + ".checkpoints.jsonl")
    assert ckpt_path.exists()
    checkpoints = [
        json.loads(line) for line in ckpt_path.read_text(encoding="utf-8").splitlines()
    ]
    assert [c["seq"] for c in checkpoints] == [1, 3, 4]
    result = verify_chain(
        path,
        checkpoints_path=ckpt_path,
        public_keys={TEST_KEY_ID: bytes.fromhex(TEST_PUBLIC)},
    )
    assert result.valid, result.reason


def test_checkpoint_key_unknown(tmp_path):
    path = tmp_path / "audit.jsonl"
    signer = Ed25519Signer(TEST_PRIVATE)
    with AuditLogV2(
        path, chain_id="ckpt-chain", signer=signer, checkpoint_every=1
    ) as log:
        log.record(_decision(), engagement_id="audit-eng", policy_sha256=POLICY_SHA)
    result = verify_chain(path, checkpoints_path=log.checkpoints_path)
    assert not result.valid
    assert result.reason_code == "CHECKPOINT_KEY_UNKNOWN"


def test_checkpoint_missing(tmp_path):
    path = tmp_path / "audit.jsonl"
    signer = Ed25519Signer(TEST_PRIVATE)
    with AuditLogV2(
        path, chain_id="ckpt-chain", signer=signer, checkpoint_every=1000
    ) as log:
        log.record(_decision(), engagement_id="audit-eng", policy_sha256=POLICY_SHA)
    ckpt_path = Path(str(path) + ".checkpoints.jsonl")
    if ckpt_path.exists():
        ckpt_path.unlink()
    result = verify_chain(path, checkpoints_path=str(ckpt_path))
    assert not result.valid
    assert result.reason_code == "CHECKPOINT_MISSING"
    assert result.broken_at_index is None


def test_checkpoint_signature_invalid(tmp_path):
    path = tmp_path / "audit.jsonl"
    signer = Ed25519Signer(TEST_PRIVATE)
    with AuditLogV2(
        path, chain_id="ckpt-chain", signer=signer, checkpoint_every=1
    ) as log:
        log.record(_decision(), engagement_id="audit-eng", policy_sha256=POLICY_SHA)
    ckpt_path = Path(str(path) + ".checkpoints.jsonl")
    checkpoints = [json.loads(line) for line in ckpt_path.read_text().splitlines()]
    checkpoints[0]["sig"] = "A" * 86
    ckpt_path.write_bytes(b"".join(canonicalize(c) + b"\n" for c in checkpoints))
    result = verify_chain(
        path,
        checkpoints_path=ckpt_path,
        public_keys={TEST_KEY_ID: bytes.fromhex(TEST_PUBLIC)},
    )
    assert not result.valid
    assert result.reason_code == "CHECKPOINT_SIGNATURE_INVALID"


def test_signing_backend_unavailable(tmp_path, monkeypatch):
    path = tmp_path / "audit.jsonl"
    signer = Ed25519Signer(TEST_PRIVATE)
    with AuditLogV2(
        path, chain_id="ckpt-chain", signer=signer, checkpoint_every=1
    ) as log:
        log.record(_decision(), engagement_id="audit-eng", policy_sha256=POLICY_SHA)
    monkeypatch.setitem(
        sys.modules, "cryptography.hazmat.primitives.asymmetric.ed25519", None
    )
    result = verify_chain(
        path,
        checkpoints_path=log.checkpoints_path,
        public_keys={TEST_KEY_ID: bytes.fromhex(TEST_PUBLIC)},
    )
    # Fail-closed: a missing backend is never "valid".
    assert not result.valid
    assert result.reason_code == "SIGNING_BACKEND_UNAVAILABLE"
    assert result.broken_at_index == 0


def test_close_checkpoints_only_when_new_records(tmp_path):
    path = tmp_path / "audit.jsonl"
    signer = Ed25519Signer(TEST_PRIVATE)
    log = AuditLogV2(path, chain_id="ckpt-chain", signer=signer, checkpoint_every=1000)
    log.__enter__()
    log.record(_decision(), engagement_id="audit-eng", policy_sha256=POLICY_SHA)
    log.close()
    ckpt_path = Path(str(path) + ".checkpoints.jsonl")
    assert ckpt_path.exists()
    first = ckpt_path.read_text(encoding="utf-8")
    # Reopen without writing: closing again must not append a checkpoint.
    log2 = AuditLogV2(path, chain_id="ckpt-chain", signer=signer)
    log2.__enter__()
    log2.close()
    assert ckpt_path.read_text(encoding="utf-8") == first


# --- tampering -------------------------------------------------------------------


def test_extra_field_detected(tmp_path):
    path = tmp_path / "audit.jsonl"
    _write(path, count=2)
    lines = path.read_text(encoding="utf-8").splitlines()
    record = json.loads(lines[0])
    record["extra"] = 1
    record["entry_hash"] = hashlib.sha256(
        canonicalize({k: v for k, v in record.items() if k != "entry_hash"})
    ).hexdigest()
    lines[0] = canonicalize(record).decode("utf-8")
    path.write_text("".join(line + "\n" for line in lines), encoding="utf-8")
    result = verify_chain(path)
    assert not result.valid
    assert result.reason_code == "UNKNOWN_FIELD"


def test_reason_tamper_detected(tmp_path):
    path = tmp_path / "audit.jsonl"
    _write(path, count=2)
    lines = path.read_text(encoding="utf-8").splitlines()
    record = json.loads(lines[1])
    record["reason"] = "tampered reason"
    lines[1] = canonicalize(record).decode("utf-8")
    path.write_text("".join(line + "\n" for line in lines), encoding="utf-8")
    result = verify_chain(path)
    assert not result.valid
    assert result.reason_code == "ENTRY_HASH_MISMATCH"


def test_truncated_tail_detected_with_checkpoint(tmp_path):
    path = tmp_path / "audit.jsonl"
    signer = Ed25519Signer(TEST_PRIVATE)
    with AuditLogV2(
        path, chain_id="ckpt-chain", signer=signer, checkpoint_every=2
    ) as log:
        for i in range(5):
            log.record(
                _decision(target=f"t{i}"),
                engagement_id="audit-eng",
                policy_sha256=POLICY_SHA,
            )
    lines = path.read_text(encoding="utf-8").splitlines()
    path.write_text("".join(line + "\n" for line in lines[:3]), encoding="utf-8")
    result = verify_chain(
        path,
        checkpoints_path=log.checkpoints_path,
        public_keys={TEST_KEY_ID: bytes.fromhex(TEST_PUBLIC)},
    )
    assert not result.valid
    assert result.reason_code == "CHAIN_TRUNCATED"
    assert result.broken_at_index == 3


def test_truncated_tail_without_checkpoint_looks_valid(tmp_path):
    # Known limitation (SPEC §14.7): tail truncation is undetectable without
    # an external anchor. This test pins that boundary.
    path = tmp_path / "audit.jsonl"
    _write(path, count=5)
    lines = path.read_text(encoding="utf-8").splitlines()
    path.write_text("".join(line + "\n" for line in lines[:3]), encoding="utf-8")
    result = verify_chain(path)
    assert result.valid


# --- record() input validation ---------------------------------------------------


def test_invalid_policy_sha_rejected(tmp_path):
    path = tmp_path / "audit.jsonl"
    with pytest.raises(ValueError), AuditLogV2(path, chain_id="test-chain") as log:
        log.record(
            _decision(),
            engagement_id="audit-eng",
            policy_sha256="not-hex",
        )
    assert not path.exists() or path.stat().st_size == 0


def test_non_jcs_metadata_rejected(tmp_path):
    path = tmp_path / "audit.jsonl"
    with pytest.raises((TypeError, ValueError)):  # noqa: SIM117
        with AuditLogV2(path, chain_id="test-chain") as log:
            log.record(
                _decision(),
                engagement_id="audit-eng",
                policy_sha256=POLICY_SHA,
                metadata={"x": 1.5},
            )
    assert not path.exists() or path.stat().st_size == 0


def test_newline_in_policy_sha_rejected(tmp_path):
    path = tmp_path / "audit.jsonl"
    with pytest.raises(ValueError), AuditLogV2(path, chain_id="test-chain") as log:
        log.record(
            _decision(),
            engagement_id="audit-eng",
            policy_sha256=POLICY_SHA + "\n",
        )
    assert not path.exists() or path.stat().st_size == 0


def test_naive_timestamp_rejected(tmp_path):
    path = tmp_path / "audit.jsonl"
    with pytest.raises(ValueError), AuditLogV2(path, chain_id="test-chain") as log:
        log.record(
            _decision(when=datetime(2026, 10, 1, 10, 0, 0)),  # noqa: DTZ001
            engagement_id="audit-eng",
            policy_sha256=POLICY_SHA,
        )


# --- review follow-ups -------------------------------------------------------------


def _rehash(record):
    record["entry_hash"] = hashlib.sha256(
        canonicalize({k: v for k, v in record.items() if k != "entry_hash"})
    ).hexdigest()
    return record


def _rewrite_line(path, index, mutate, rehash=True):
    lines = path.read_text(encoding="utf-8").split("\n")[:-1]
    record = json.loads(lines[index])
    mutate(record)
    if rehash:
        try:
            _rehash(record)
        except (TypeError, ValueError):
            pass  # outside the JCS subset: the verifier stops before the hash
    lines[index] = json.dumps(
        record, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    )
    path.write_text("".join(line + "\n" for line in lines), encoding="utf-8")


def _verify_with_keys(path):
    return verify_chain(
        path,
        checkpoints_path=Path(str(path) + ".checkpoints.jsonl"),
        public_keys={TEST_KEY_ID: bytes.fromhex(TEST_PUBLIC)},
    )


@pytest.mark.parametrize("text", ["line sep", "para sep", "next\x85line"])
def test_raw_unicode_separators_round_trip(tmp_path, text):
    # JCS writes U+2028/U+2029/U+0085 raw; lines split on "\n" only.
    path = tmp_path / "audit.jsonl"
    with AuditLogV2(path, chain_id="test-chain") as log:
        log.record(
            _decision(reason=text),
            engagement_id="audit-eng",
            policy_sha256=POLICY_SHA,
            metadata={"note": text},
        )
    assert verify_chain(path).valid
    with AuditLogV2(path, chain_id="test-chain") as log:
        log.record(_decision(), engagement_id="audit-eng", policy_sha256=POLICY_SHA)
    result = verify_chain(path)
    assert result.valid, result.reason
    assert result.total_entries == 2


@pytest.mark.parametrize(
    ("mutate", "code"),
    [
        (lambda r: r.update(mode="audit"), "MALFORMED"),
        (lambda r: r.update(decision="MAYBE"), "MALFORMED"),
        (lambda r: r.update(metadata=[]), "MALFORMED"),
        (lambda r: r.update(engagement_id=""), "MALFORMED"),
        (lambda r: r.update(agent_id=None), "MALFORMED"),
        (lambda r: r.update(seq="1"), "MALFORMED"),
        (lambda r: r.update(chain_id="bad chain"), "MALFORMED"),
        (lambda r: r.update(policy_sha256=POLICY_SHA + "\n"), "MALFORMED"),
        (lambda r: r.update(metadata={"big": 2**53}), "MALFORMED"),
        (
            lambda r: r.update(timestamp="2026-10-01T10:00:01.000000Z\n"),
            "TIMESTAMP_FORMAT",
        ),
        (lambda r: (r.pop("reason"), r.update(extra=1)), "MALFORMED"),
        (lambda r: r.update(v=3, extra=1), "UNKNOWN_VERSION"),
        (lambda r: r.update(chain_id="other-chain", seq=9), "CHAIN_ID_MISMATCH"),
        (lambda r: r.update(seq=9, prev_hash="c" * 64), "SEQ_MISMATCH"),
    ],
)
def test_v2_line_checks_follow_spec_order(tmp_path, mutate, code):
    path = tmp_path / "audit.jsonl"
    _write(path, count=2)
    _rewrite_line(path, 1, mutate)
    result = verify_chain(path)
    assert (result.valid, result.reason_code, result.broken_at_index) == (
        False,
        code,
        1,
    )


@pytest.mark.parametrize(
    ("old", "new", "code"),
    [
        ('"v":2}', '"v":2.0}', "UNKNOWN_VERSION"),
        ('"metadata":{"i":0}', '"metadata":{"i":1.5}', "MALFORMED"),
        ('"metadata":{"i":0}', '"metadata":{"i":NaN}', "INVALID_JSON"),
        ('"metadata":{"i":0}', '"metadata":{"i":"\\ud800"}', "MALFORMED"),
    ],
)
def test_non_jcs_values_are_results_not_crashes(tmp_path, old, new, code):
    path = tmp_path / "audit.jsonl"
    _write(path, count=1)
    text = path.read_text(encoding="utf-8")
    assert text.count(old) == 1
    path.write_text(text.replace(old, new), encoding="utf-8")
    result = verify_chain(path)
    assert (result.valid, result.reason_code, result.broken_at_index) == (
        False,
        code,
        0,
    )


def test_non_utf8_line_is_invalid_json(tmp_path):
    path = tmp_path / "audit.jsonl"
    _write(path, count=1)
    path.write_bytes(path.read_bytes() + b'{"v":2,"x":"\xff"}\n')
    result = verify_chain(path)
    assert (result.reason_code, result.broken_at_index) == ("INVALID_JSON", 1)


def test_blank_lines_v1_region_skipped_v2_region_rejected(tmp_path):
    path = tmp_path / "mixed.jsonl"
    _v1_record(path, "10.20.3.5")
    with path.open("a", encoding="utf-8") as fh:
        fh.write("\n")
    _v1_record(path, "10.20.3.6")
    with AuditLogV2(path, chain_id="mixed-chain") as log:
        record = log.record(
            _decision(), engagement_id="audit-eng", policy_sha256=POLICY_SHA
        )
    # seq counts records, not physical lines.
    assert record["seq"] == 2
    assert verify_chain(path).valid
    with path.open("a", encoding="utf-8") as fh:
        fh.write("\n")
    result = verify_chain(path)
    assert (result.reason_code, result.broken_at_index) == ("INVALID_JSON", 4)


def _original_v1_verify(path):
    # The pre-T24 AuditLog.verify loop, kept verbatim as the v1 oracle.
    from roe_guard.audit import GENESIS_PREV_HASH, _hash_entry
    from roe_guard.models import AuditEntry

    expected_prev = GENESIS_PREV_HASH
    total = 0
    with Path(path).open("r", encoding="utf-8") as fh:
        for index, raw_line in enumerate(fh):
            stripped = raw_line.strip()
            if not stripped:
                continue
            try:
                payload = json.loads(stripped)
            except json.JSONDecodeError as exc:
                return (False, total, index, f"line {index}: invalid JSON: {exc}")
            try:
                entry = AuditEntry(
                    engagement_id=payload.get("engagement_id", ""),
                    timestamp=datetime.fromisoformat(payload["timestamp"]),
                    target=payload["target"],
                    action_type=payload["action_type"],
                    decision=DecisionType(payload["decision"]),
                    reason=payload.get("reason", ""),
                    prev_hash=payload["prev_hash"],
                    entry_hash=payload["entry_hash"],
                )
            except (KeyError, ValueError) as exc:
                return (False, total, index, f"line {index}: malformed entry: {exc}")
            if entry.prev_hash != expected_prev:
                return (
                    False,
                    total + 1,
                    index,
                    (
                        f"line {index}: prev_hash mismatch "
                        f"(expected {expected_prev[:12]}…, "
                        f"got {entry.prev_hash[:12]}…)"
                    ),
                )
            computed = _hash_entry(entry)
            if computed != entry.entry_hash:
                return (
                    False,
                    total + 1,
                    index,
                    (
                        f"line {index}: entry_hash mismatch "
                        f"(expected {computed[:12]}…, "
                        f"got {entry.entry_hash[:12]}…)"
                    ),
                )
            expected_prev = entry.entry_hash
            total += 1
    return (True, total, None, None)


_V1_TAMPERS = {
    "intact": lambda lines: lines,
    "blank-lines": lambda lines: ["", lines[0], "  ", *lines[1:], ""],
    "bad-json": lambda lines: [lines[0], "{oops", *lines[2:]],
    "missing-key": lambda lines: [
        lines[0],
        json.dumps({k: v for k, v in json.loads(lines[1]).items() if k != "target"}),
        *lines[2:],
    ],
    "bad-decision": lambda lines: [
        lines[0],
        json.dumps({**json.loads(lines[1]), "decision": "MAYBE"}),
        *lines[2:],
    ],
    "bad-timestamp": lambda lines: [
        json.dumps({**json.loads(lines[0]), "timestamp": "yesterday"}),
        *lines[1:],
    ],
    "extra-key": lambda lines: [
        json.dumps({**json.loads(lines[0]), "note": "outside the hash"}),
        *lines[1:],
    ],
    "reason-changed": lambda lines: [
        lines[0],
        json.dumps({**json.loads(lines[1]), "reason": "edited"}),
        *lines[2:],
    ],
    "deleted-line": lambda lines: [lines[0], *lines[2:]],
}


@pytest.mark.parametrize("tamper", sorted(_V1_TAMPERS))
def test_v1_results_identical_to_original_verify(tmp_path, tamper):
    path = tmp_path / "v1.jsonl"
    for target in ("10.20.3.5", "10.20.3.6", "10.20.3.7"):
        _v1_record(path, target)
    lines = path.read_text(encoding="utf-8").splitlines()
    path.write_text(
        "".join(line + "\n" for line in _V1_TAMPERS[tamper](lines)), encoding="utf-8"
    )
    result = AuditLog(path).verify()
    assert (
        result.valid,
        result.total_entries,
        result.broken_at_index,
        result.reason,
    ) == _original_v1_verify(path)


def test_verify_ignores_checkpoints_unless_a_path_is_given(tmp_path):
    path = tmp_path / "audit.jsonl"
    _write(path, count=2, signer=Ed25519Signer(TEST_PRIVATE))
    assert Path(str(path) + ".checkpoints.jsonl").exists()
    assert verify_chain(path).valid
    assert AuditLog(path).verify().valid
    from roe_guard.cli import main

    assert main(["audit-verify", str(path)]) == 0


def test_records_after_last_checkpoint_stay_valid(tmp_path):
    # Known limit, not an error: records after the last checkpoint (e.g. a
    # writer that died before close) verify; their removal is undetectable.
    path = tmp_path / "audit.jsonl"
    _write(path, count=2, signer=Ed25519Signer(TEST_PRIVATE), checkpoint_every=2)
    _write(path, count=1)
    result = _verify_with_keys(path)
    assert result.valid, result.reason
    assert result.total_entries == 3


def _resign(checkpoint):
    signer = Ed25519Signer(TEST_PRIVATE)
    body = {k: v for k, v in checkpoint.items() if k != "sig"}
    checkpoint["sig"] = (
        __import__("base64")
        .urlsafe_b64encode(signer.sign(canonicalize(body)))
        .rstrip(b"=")
        .decode("ascii")
    )
    return checkpoint


def _rewrite_checkpoint(path, index, mutate):
    ckpt_path = Path(str(path) + ".checkpoints.jsonl")
    lines = ckpt_path.read_text(encoding="utf-8").splitlines()
    checkpoint = json.loads(lines[index])
    mutate(checkpoint)
    lines[index] = canonicalize(checkpoint).decode("utf-8")
    ckpt_path.write_text("".join(line + "\n" for line in lines), encoding="utf-8")


def test_every_checkpoint_head_is_checked(tmp_path):
    path = tmp_path / "audit.jsonl"
    _write(path, count=4, signer=Ed25519Signer(TEST_PRIVATE), checkpoint_every=2)

    def mutate(checkpoint):
        checkpoint["head_hash"] = "d" * 64
        _resign(checkpoint)

    _rewrite_checkpoint(path, 0, mutate)
    result = _verify_with_keys(path)
    assert (result.reason_code, result.broken_at_index) == (
        "CHECKPOINT_HEAD_MISMATCH",
        1,
    )


@pytest.mark.parametrize(
    ("field", "value", "at"),
    [
        ("v", 3, 1),
        ("v", True, 1),
        ("seq", -1, None),
        ("head_hash", "B" * 64, 1),
        ("chain_id", "bad chain", 1),
        ("timestamp", "2026-10-01T10:00:00Z", 1),
        ("key_id", TEST_KEY_ID + "\n", 1),
    ],
)
def test_checkpoint_format_is_malformed(tmp_path, field, value, at):
    path = tmp_path / "audit.jsonl"
    _write(path, count=2, signer=Ed25519Signer(TEST_PRIVATE), checkpoint_every=2)

    def mutate(checkpoint):
        checkpoint[field] = value
        _resign(checkpoint)

    _rewrite_checkpoint(path, 0, mutate)
    result = _verify_with_keys(path)
    assert (result.reason_code, result.broken_at_index) == ("CHECKPOINT_MALFORMED", at)


def test_non_canonical_signature_spelling_is_malformed(tmp_path):
    # The last of the 86 characters carries 4 padding bits; flipping one
    # keeps the decoded signature but must not verify as a second spelling.
    path = tmp_path / "audit.jsonl"
    _write(path, count=2, signer=Ed25519Signer(TEST_PRIVATE), checkpoint_every=2)
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"

    def mutate(checkpoint):
        last = alphabet[alphabet.index(checkpoint["sig"][-1]) ^ 1]
        checkpoint["sig"] = checkpoint["sig"][:-1] + last

    _rewrite_checkpoint(path, 0, mutate)
    result = _verify_with_keys(path)
    assert (result.reason_code, result.broken_at_index) == ("CHECKPOINT_MALFORMED", 1)


def test_repeated_checkpoint_for_same_head_is_valid(tmp_path):
    path = tmp_path / "audit.jsonl"
    with AuditLogV2(
        path, chain_id="test-chain", signer=Ed25519Signer(TEST_PRIVATE)
    ) as log:
        log.record(_decision(), engagement_id="audit-eng", policy_sha256=POLICY_SHA)
        log.checkpoint()
        log.checkpoint()
    assert _verify_with_keys(path).valid


def test_writer_rejects_bad_state_and_arguments(tmp_path, monkeypatch):
    path = tmp_path / "audit.jsonl"
    with pytest.raises(ValueError):
        AuditLogV2(path, chain_id="test-chain", checkpoint_every=0)
    with pytest.raises(ValueError):
        AuditLogV2(path, chain_id="bad chain")
    log = AuditLogV2(path, chain_id="test-chain", signer=Ed25519Signer(TEST_PRIVATE))
    with pytest.raises(roe_guard.exceptions.RoeGuardError):
        log.checkpoint()  # no record yet: no seq -1 checkpoint
    log.close()
    log.close()  # idempotent
    with pytest.raises(roe_guard.exceptions.RoeGuardError):
        log.record(_decision(), engagement_id="audit-eng", policy_sha256=POLICY_SHA)
    assert path.stat().st_size == 0

    from roe_guard import audit_v2

    monkeypatch.setattr(audit_v2, "_fcntl", None)
    with pytest.raises(roe_guard.exceptions.RoeGuardError):
        AuditLogV2(path, chain_id="test-chain")


def test_writer_refuses_v2_file_ending_mid_line(tmp_path):
    # A v2 line without its "\n" is already MALFORMED for the verifier.
    path = tmp_path / "audit.jsonl"
    _write(path, count=1)
    path.write_bytes(path.read_bytes().rstrip(b"\n"))
    size = path.stat().st_size
    with pytest.raises(AuditIntegrityError):
        AuditLogV2(path, chain_id="test-chain")
    assert path.stat().st_size == size


def test_writer_refuses_v1_file_ending_mid_line(tmp_path):
    # The v1 rules accept a last line without "\n", but a v2 record appended
    # to it would be glued onto that line; the writer's own guard refuses.
    path = tmp_path / "audit.jsonl"
    _v1_record(path, "10.20.3.5")
    path.write_bytes(path.read_bytes().rstrip(b"\n"))
    assert verify_chain(path).valid
    size = path.stat().st_size
    with pytest.raises(AuditIntegrityError, match="ends mid-line"):
        AuditLogV2(path, chain_id="test-chain")
    assert path.stat().st_size == size


def test_v1_writer_blocked_while_v2_writer_holds_lock(tmp_path):
    path = tmp_path / "audit.jsonl"
    _v1_record(path, "10.20.3.5")
    size = path.stat().st_size
    with (
        AuditLogV2(path, chain_id="mixed-chain"),
        pytest.raises(AuditWriterLockedError),
    ):
        _v1_record(path, "10.20.3.6")
    assert path.stat().st_size == size


def test_v1_writer_rejects_any_v2_line(tmp_path):
    path = tmp_path / "mixed.jsonl"
    _v1_record(path, "10.20.3.5")
    with AuditLogV2(path, chain_id="mixed-chain") as log:
        log.record(_decision(), engagement_id="audit-eng", policy_sha256=POLICY_SHA)
    # Break the v2 line: the v1 writer must still refuse (no downgrade).
    _rewrite_line(path, 1, lambda r: r.update(reason="x"), rehash=False)
    size = path.stat().st_size
    with pytest.raises(AuditIntegrityError):
        _v1_record(path, "10.20.3.9")
    assert path.stat().st_size == size


def test_writer_output_matches_schema(tmp_path):
    from jsonschema import Draft202012Validator

    record_schema = json.loads(
        (REPO / "schema" / "audit-record.v2.json").read_text(encoding="utf-8")
    )
    checkpoint_schema = json.loads(
        (REPO / "schema" / "audit-checkpoint.v2.json").read_text(encoding="utf-8")
    )
    path = tmp_path / "audit.jsonl"
    _write(path, count=3, signer=Ed25519Signer(TEST_PRIVATE), checkpoint_every=2)
    for line in path.read_text(encoding="utf-8").splitlines():
        Draft202012Validator(record_schema).validate(json.loads(line))
    for line in Path(str(path) + ".checkpoints.jsonl").read_text().splitlines():
        Draft202012Validator(checkpoint_schema).validate(json.loads(line))


@pytest.mark.parametrize(
    "rewrite",
    [
        lambda line: json.dumps(dict(reversed(list(json.loads(line).items())))),
        lambda line: line.replace('"seq":', '"seq": '),
        lambda line: line.replace('"t1"', '"\\u0074\\u0031"'),
        lambda line: line + "\r",
    ],
    ids=["key-order", "whitespace", "escape", "crlf"],
)
def test_non_canonical_v2_line_is_malformed(tmp_path, rewrite):
    # SPEC §14.7: a line is JCS(record) + "\n"; same content, other bytes
    # is not accepted.
    path = tmp_path / "audit.jsonl"
    _write(path, count=3)
    lines = path.read_text(encoding="utf-8").split("\n")[:-1]
    lines[1] = rewrite(lines[1])
    path.write_text("".join(line + "\n" for line in lines), encoding="utf-8")
    result = verify_chain(path)
    assert (result.reason_code, result.broken_at_index) == ("MALFORMED", 1)


def test_last_v2_line_without_newline_is_malformed(tmp_path):
    path = tmp_path / "audit.jsonl"
    _write(path, count=2)
    path.write_bytes(path.read_bytes()[:-1])
    result = verify_chain(path)
    assert (result.reason_code, result.broken_at_index) == ("MALFORMED", 1)


def test_non_canonical_checkpoint_line_is_malformed(tmp_path):
    path = tmp_path / "audit.jsonl"
    _write(path, count=2, signer=Ed25519Signer(TEST_PRIVATE), checkpoint_every=2)
    ckpt_path = Path(str(path) + ".checkpoints.jsonl")
    checkpoint = json.loads(ckpt_path.read_text(encoding="utf-8"))
    ckpt_path.write_text(json.dumps(checkpoint, sort_keys=True) + "\n")
    result = _verify_with_keys(path)
    assert (result.reason_code, result.broken_at_index) == ("CHECKPOINT_MALFORMED", 1)


def test_writer_refuses_chain_its_checkpoints_contradict(tmp_path):
    # Records cut behind signed checkpoints: the writer must not reuse
    # the signed seqs and sign a new head over the gap.
    path = tmp_path / "audit.jsonl"
    signer = Ed25519Signer(TEST_PRIVATE)
    _write(path, count=6, signer=signer, checkpoint_every=2)
    lines = path.read_text(encoding="utf-8").split("\n")[:-1]
    path.write_text("".join(line + "\n" for line in lines[:4]), encoding="utf-8")
    size = path.stat().st_size
    with pytest.raises(AuditIntegrityError):
        AuditLogV2(path, chain_id="test-chain", signer=signer)
    assert path.stat().st_size == size


def test_reopen_checkpoints_records_a_crashed_writer_left(tmp_path):
    path = tmp_path / "audit.jsonl"
    signer = Ed25519Signer(TEST_PRIVATE)
    log = AuditLogV2(path, chain_id="test-chain", signer=signer, checkpoint_every=2)
    for i in range(3):
        log.record(
            _decision(target=f"t{i}"),
            engagement_id="audit-eng",
            policy_sha256=POLICY_SHA,
        )
    log._release()  # the process dies: no close(), no final checkpoint
    with AuditLogV2(path, chain_id="test-chain", signer=signer):
        pass
    ckpt_path = Path(str(path) + ".checkpoints.jsonl")
    seqs = [json.loads(line)["seq"] for line in ckpt_path.read_text().splitlines()]
    assert seqs == [1, 2]
    assert _verify_with_keys(path).valid


def test_failed_write_closes_writer_and_leaves_no_buffered_line(tmp_path):
    path = tmp_path / "audit.jsonl"
    log = AuditLogV2(path, chain_id="test-chain")
    log.record(_decision(), engagement_id="audit-eng", policy_sha256=POLICY_SHA)
    size = path.stat().st_size

    class Full:
        def __init__(self, inner):
            self._inner = inner

        def write(self, data):
            raise OSError(28, "No space left on device")

        def __getattr__(self, name):
            return getattr(self._inner, name)

    log._file = Full(log._file)
    with pytest.raises(OSError):
        log.record(_decision(), engagement_id="audit-eng", policy_sha256=POLICY_SHA)
    with pytest.raises(roe_guard.exceptions.RoeGuardError):
        log.record(_decision(), engagement_id="audit-eng", policy_sha256=POLICY_SHA)
    log.close()
    assert path.stat().st_size == size
    assert verify_chain(path).valid


def test_one_writer_shared_by_threads(tmp_path):
    import threading

    path = tmp_path / "audit.jsonl"

    def work(log, n):
        for i in range(50):
            log.record(
                _decision(target=f"t{n}-{i}"),
                engagement_id="audit-eng",
                policy_sha256=POLICY_SHA,
            )

    old = sys.getswitchinterval()
    sys.setswitchinterval(1e-6)
    try:
        with AuditLogV2(path, chain_id="test-chain") as log:
            threads = [threading.Thread(target=work, args=(log, n)) for n in range(4)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join()
    finally:
        sys.setswitchinterval(old)
    result = verify_chain(path)
    assert result.valid, result.reason
    assert result.total_entries == 200


def test_checkpoints_stay_next_to_the_log_after_chdir(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "other").mkdir()
    with AuditLogV2(
        "audit.jsonl",
        chain_id="test-chain",
        signer=Ed25519Signer(TEST_PRIVATE),
        checkpoint_every=1,
    ) as log:
        log.record(_decision(), engagement_id="audit-eng", policy_sha256=POLICY_SHA)
        monkeypatch.chdir(tmp_path / "other")
        log.record(_decision(), engagement_id="audit-eng", policy_sha256=POLICY_SHA)
    assert not (tmp_path / "other" / "audit.jsonl.checkpoints.jsonl").exists()
    assert _verify_with_keys(tmp_path / "audit.jsonl").valid


@pytest.mark.parametrize(
    "decision",
    [
        _decision(agent_id=None),
        _decision(reason_code=None),
        _decision(target=1),
    ],
)
def test_writer_rejects_fields_its_verifier_would_reject(tmp_path, decision):
    path = tmp_path / "audit.jsonl"
    with (
        AuditLogV2(path, chain_id="test-chain") as log,
        pytest.raises(ValueError),
    ):
        log.record(decision, engagement_id="audit-eng", policy_sha256=POLICY_SHA)
    assert path.stat().st_size == 0


@pytest.mark.parametrize("metadata", [[], 0, [("k", 1)]])
def test_writer_rejects_non_mapping_metadata(tmp_path, metadata):
    path = tmp_path / "audit.jsonl"
    with AuditLogV2(path, chain_id="test-chain") as log, pytest.raises(TypeError):
        log.record(
            _decision(),
            engagement_id="audit-eng",
            policy_sha256=POLICY_SHA,
            metadata=metadata,
        )
    assert path.stat().st_size == 0


def test_writer_rejects_metadata_beyond_jcs_depth(tmp_path):
    from roe_guard.jcs import MAX_DEPTH

    deep: object = 0
    for _ in range(MAX_DEPTH):
        deep = [deep]
    path = tmp_path / "audit.jsonl"
    with AuditLogV2(path, chain_id="test-chain") as log, pytest.raises(ValueError):
        log.record(
            _decision(),
            engagement_id="audit-eng",
            policy_sha256=POLICY_SHA,
            metadata={"deep": deep},
        )
    assert path.stat().st_size == 0


def test_empty_checkpoint_file_counts_as_missing(tmp_path):
    path = tmp_path / "audit.jsonl"
    _write(path, count=2, signer=Ed25519Signer(TEST_PRIVATE))
    Path(str(path) + ".checkpoints.jsonl").write_bytes(b"")
    result = _verify_with_keys(path)
    assert (result.reason_code, result.broken_at_index) == ("CHECKPOINT_MISSING", None)
    # The writer treats an empty file as "no checkpoints yet".
    with AuditLogV2(path, chain_id="test-chain", signer=Ed25519Signer(TEST_PRIVATE)):
        pass
    assert _verify_with_keys(path).valid


def test_verify_beside_a_live_writer_is_not_truncation(tmp_path, monkeypatch):
    # A record and its checkpoint land between the verifier's two reads.
    # SPEC §14.7: checkpoints are read first. Reading the chain first would
    # see the new checkpoint without its record (a false CHAIN_TRUNCATED).
    path = tmp_path / "audit.jsonl"
    ckpt_path = Path(str(path) + ".checkpoints.jsonl")
    signer = Ed25519Signer(TEST_PRIVATE)
    log = AuditLogV2(path, chain_id="test-chain", signer=signer, checkpoint_every=1)
    log.record(_decision(), engagement_id="audit-eng", policy_sha256=POLICY_SHA)
    real_read = Path.read_bytes
    reads = []

    def read_then_append(self):
        data = real_read(self)
        if self in (path, ckpt_path):
            reads.append(self)
            if len(reads) == 1:
                log.record(
                    _decision(), engagement_id="audit-eng", policy_sha256=POLICY_SHA
                )
        return data

    monkeypatch.setattr(Path, "read_bytes", read_then_append)
    result = _verify_with_keys(path)
    monkeypatch.undo()
    log.close()
    assert reads == [ckpt_path, path]
    assert result.valid, result.reason


# --- second verification pass follow-ups -------------------------------------


@pytest.mark.parametrize("where", ["lead", "trail"])
@pytest.mark.parametrize(
    "pad", ["\x0b", "\x0c", "\x1c", "\x1f", "\x85", "\xa0", "\u2028", "\u3000"]
)
def test_v2_line_with_non_json_padding_is_invalid_json(tmp_path, pad, where):
    # str.strip() removes these characters but JSON does not allow them as
    # whitespace: the line is not JSON as written (step 1), never a crash.
    path = tmp_path / "audit.jsonl"
    _write(path, count=1)
    line = path.read_bytes().rstrip(b"\n").decode("utf-8")
    padded = pad + line if where == "lead" else line + pad
    path.write_bytes((padded + "\n").encode("utf-8"))
    result = verify_chain(path)
    assert (result.valid, result.reason_code) == (False, "INVALID_JSON")
    with pytest.raises(AuditIntegrityError):
        AuditLogV2(path, chain_id="test-chain")


def test_nan_after_nested_duplicate_key_is_invalid_json(tmp_path):
    # Step 1 (NaN) wins over step 2 (duplicate key), wherever they sit.
    path = tmp_path / "audit.jsonl"
    _write(path, count=1)
    line = path.read_bytes().rstrip(b"\n").decode("utf-8")
    assert '"metadata":{"i":0}' in line
    line = line.replace('"metadata":{"i":0}', '"metadata":{"a":{"k":1,"k":2},"b":NaN}')
    path.write_bytes((line + "\n").encode("utf-8"))
    assert verify_chain(path).reason_code == "INVALID_JSON"


def test_checkpoint_seq_outside_jcs_range_is_malformed(tmp_path):
    path = tmp_path / "audit.jsonl"
    _write(path, count=2, signer=Ed25519Signer(TEST_PRIVATE))
    ckpt = Path(str(path) + ".checkpoints.jsonl")
    checkpoint = json.loads(ckpt.read_bytes().splitlines()[-1])
    checkpoint["seq"] = 2**53
    ckpt.write_text(
        json.dumps(checkpoint, sort_keys=True, separators=(",", ":")) + "\n"
    )
    result = _verify_with_keys(path)
    assert (result.reason_code, result.broken_at_index) == (
        "CHECKPOINT_MALFORMED",
        2**53,
    )
    with pytest.raises(AuditIntegrityError):
        AuditLogV2(path, chain_id="test-chain")


def test_checkpoint_line_without_final_newline_is_malformed(tmp_path):
    path = tmp_path / "audit.jsonl"
    _write(path, count=2, signer=Ed25519Signer(TEST_PRIVATE))
    ckpt = Path(str(path) + ".checkpoints.jsonl")
    ckpt.write_bytes(ckpt.read_bytes().rstrip(b"\n"))
    assert _verify_with_keys(path).reason_code == "CHECKPOINT_MALFORMED"


@pytest.mark.parametrize("depth", [100, 500, 900, 990, 2000, 20000])
@pytest.mark.parametrize("field_name", ["target", "prev_hash", "decision"])
def test_deep_v1_field_never_crashes(tmp_path, depth, field_name):
    path = tmp_path / "audit.jsonl"
    _v1_record(path, "10.20.3.5")
    record = json.loads(path.read_text(encoding="utf-8"))
    text = json.dumps(record, sort_keys=True, separators=(",", ":"))
    old = f'"{field_name}":' + json.dumps(record[field_name])
    assert old in text
    deep = "[" * depth + "]" * depth
    path.write_text(text.replace(old, f'"{field_name}":{deep}') + "\n")
    result = verify_chain(path)
    assert result.valid is False
    # Which code depends on the interpreter's JSON depth limits; never a crash.
    assert result.reason_code in {
        "INVALID_JSON",
        "MALFORMED",
        "PREV_HASH_MISMATCH",
        "ENTRY_HASH_MISMATCH",
    }


@pytest.mark.parametrize("depth", [100, 500, 900, 990, 2000, 20000])
def test_deep_v2_version_never_crashes(tmp_path, depth):
    path = tmp_path / "audit.jsonl"
    _write(path, count=1)
    line = path.read_bytes().rstrip(b"\n").decode("utf-8")
    deep = "[" * depth + "]" * depth
    assert line.count('"v":2') == 1
    path.write_bytes((line.replace('"v":2', '"v":' + deep) + "\n").encode("utf-8"))
    result = verify_chain(path)
    assert result.valid is False
    assert result.reason_code in {"INVALID_JSON", "UNKNOWN_VERSION"}


def test_v1_prev_hash_checked_before_hashing(tmp_path):
    # Original v1 order: a wrong prev_hash is reported even when the line
    # also holds a string JSON cannot encode (lone surrogate).
    path = tmp_path / "audit.jsonl"
    _v1_record(path, "10.20.3.5")
    record = json.loads(path.read_text(encoding="utf-8"))
    record["prev_hash"] = "f" * 64
    text = json.dumps(record, sort_keys=True, separators=(",", ":"))
    assert '"reason":"' in text
    text = text.replace('"reason":"', '"reason":"\\ud800', 1)
    path.write_text(text + "\n")
    result = verify_chain(path)
    assert (result.reason_code, result.total_entries, result.broken_at_index) == (
        "PREV_HASH_MISMATCH",
        1,
        0,
    )
    assert result.reason == (
        "line 0: prev_hash mismatch (expected 000000000000…, got ffffffffffff…)"
    )


def test_v1_list_prev_hash_text_matches_original(tmp_path):
    # The original wrote prev_hash[:12]; for a list that is the list slice.
    path = tmp_path / "audit.jsonl"
    _v1_record(path, "10.20.3.5")
    record = json.loads(path.read_text(encoding="utf-8"))
    record["prev_hash"] = ["a", "b"]
    path.write_text(json.dumps(record, sort_keys=True) + "\n")
    result = verify_chain(path)
    assert result.reason == (
        "line 0: prev_hash mismatch (expected 000000000000…, got ['a', 'b']…)"
    )


def test_failed_checkpoint_append_closes_the_writer(tmp_path, monkeypatch):
    path = tmp_path / "audit.jsonl"
    signer = Ed25519Signer(TEST_PRIVATE)
    log = AuditLogV2(path, chain_id="test-chain", signer=signer, checkpoint_every=1000)
    log.record(_decision(), engagement_id="audit-eng", policy_sha256=POLICY_SHA)
    real_open = Path.open

    class _ShortWriter:
        def __init__(self, fh):
            self._fh = fh

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            self._fh.close()

        def fileno(self):
            return self._fh.fileno()

        def write(self, view):
            self._fh.write(bytes(view[:10]))
            raise OSError(28, "No space left on device")

    def short_open(self, mode="r", *args, **kwargs):
        fh = real_open(self, mode, *args, **kwargs)
        if self.name.endswith(".checkpoints.jsonl"):
            return _ShortWriter(fh)
        return fh

    monkeypatch.setattr(Path, "open", short_open)
    with pytest.raises(OSError):
        log.checkpoint()
    monkeypatch.undo()
    with pytest.raises(roe_guard.exceptions.RoeGuardError):
        log.record(_decision(), engagement_id="audit-eng", policy_sha256=POLICY_SHA)
    # The torn checkpoint is reported on the next open, never appended to.
    with pytest.raises(AuditIntegrityError):
        AuditLogV2(path, chain_id="test-chain", signer=signer)


def test_v1_record_accepts_lines_the_v1_reader_accepts(tmp_path):
    # _reject_v2_tail strips like the original reader (e.g. a trailing \x0c).
    path = tmp_path / "audit.jsonl"
    _v1_record(path, "10.20.3.5")
    path.write_bytes(path.read_bytes().rstrip(b"\n") + b"\x0c\n")
    assert AuditLog(path).verify().valid
    _v1_record(path, "10.20.3.6")
    assert AuditLog(path).verify().valid
