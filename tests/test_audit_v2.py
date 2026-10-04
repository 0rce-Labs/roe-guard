"""Audit v2 tests: writer, locking, mixed chains, checkpoints, tamper codes."""

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from roe_guard import (
    AuditLogV2,
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
    with AuditLogV2(path, chain_id="test-chain"):
        with pytest.raises(Exception) as exc:  # noqa: SIM117
            with AuditLogV2(path, chain_id="test-chain"):
                pass
        assert type(exc.value).__name__ == "AuditWriterLockedError"


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
    result = verify_chain(path, public_keys={TEST_KEY_ID: bytes.fromhex(TEST_PUBLIC)})
    assert result.valid


def test_checkpoint_key_unknown(tmp_path):
    path = tmp_path / "audit.jsonl"
    signer = Ed25519Signer(TEST_PRIVATE)
    with AuditLogV2(
        path, chain_id="ckpt-chain", signer=signer, checkpoint_every=1
    ) as log:
        log.record(_decision(), engagement_id="audit-eng", policy_sha256=POLICY_SHA)
    result = verify_chain(path)
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
    ckpt_path.write_text(
        "".join(json.dumps(c, sort_keys=True) + "\n" for c in checkpoints)
    )
    result = verify_chain(path, public_keys={TEST_KEY_ID: bytes.fromhex(TEST_PUBLIC)})
    assert not result.valid
    assert result.reason_code == "CHECKPOINT_SIGNATURE_INVALID"


def test_signing_backend_unavailable(tmp_path):
    path = tmp_path / "audit.jsonl"
    signer = Ed25519Signer(TEST_PRIVATE)
    with AuditLogV2(
        path, chain_id="ckpt-chain", signer=signer, checkpoint_every=1
    ) as log:
        log.record(_decision(), engagement_id="audit-eng", policy_sha256=POLICY_SHA)
    import cryptography.hazmat.primitives.asymmetric as asym_module

    import roe_guard.audit_v2 as audit_v2_module

    saved = asym_module.ed25519
    monkey = pytest.MonkeyPatch()
    monkey.setattr(asym_module, "ed25519", None)
    try:
        result = audit_v2_module.verify_chain(
            path, public_keys={TEST_KEY_ID: bytes.fromhex(TEST_PUBLIC)}
        )
    finally:
        monkey.undo()
        if saved is not None:
            asym_module.ed25519 = saved
    assert not result.valid
    assert result.reason_code == "SIGNING_BACKEND_UNAVAILABLE"


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
    result = verify_chain(path, public_keys={TEST_KEY_ID: bytes.fromhex(TEST_PUBLIC)})
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
