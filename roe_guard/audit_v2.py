"""Audit record v2: seq, JCS hashing, single writer, signed checkpoints.

Contract: SPEC §14.7. The record carries exactly 16 keys; the hash is
sha256 over the JCS serialization of the record minus ``entry_hash``.
Lines are the JCS serialization of the full record plus ``\\n``.
Verification handles mixed v1→v2 chains; v1 lines keep the v1 rules.
"""

from __future__ import annotations

import base64
import errno
import fcntl
import hashlib
import json
import re
from collections.abc import Callable, Mapping
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import TYPE_CHECKING, Any, Protocol

from roe_guard.exceptions import (
    AuditIntegrityError,
    RoeGuardError,
)

if TYPE_CHECKING:
    from roe_guard.models import AuditVerificationResult
from roe_guard.jcs import canonicalize

CHAIN_ID_RE = re.compile(r"^[A-Za-z0-9._:-]{1,128}$", re.ASCII)
TIMESTAMP_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$", re.ASCII)
POLICY_SHA_RE = re.compile(r"^[0-9a-f]{64}$", re.ASCII)
KEY_ID_RE = re.compile(r"^sha256:[0-9a-f]{64}$", re.ASCII)
SIG_RE = re.compile(r"^[A-Za-z0-9_-]{86}$", re.ASCII)

GENESIS_PREV_HASH = "0" * 64

V2_KEYS = (
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
)

CHECKPOINT_KEYS = ("v", "chain_id", "seq", "head_hash", "timestamp", "key_id", "sig")


def _utc_timestamp(dt: datetime) -> str:
    if dt.tzinfo is None:
        raise ValueError("timestamp must be timezone-aware")
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _entry_hash(record: Mapping[str, Any]) -> str:
    # SPEC §14.7: the hash covers the record minus the entry_hash key.
    payload = {k: v for k, v in record.items() if k != "entry_hash"}
    return hashlib.sha256(canonicalize(payload)).hexdigest()


class AuditReasonCode(str, Enum):
    """Verification failure codes; value == name (SPEC §14.7)."""

    INVALID_JSON = "INVALID_JSON"
    MALFORMED = "MALFORMED"
    UNKNOWN_VERSION = "UNKNOWN_VERSION"
    UNKNOWN_FIELD = "UNKNOWN_FIELD"
    TIMESTAMP_FORMAT = "TIMESTAMP_FORMAT"
    CHAIN_ID_MISMATCH = "CHAIN_ID_MISMATCH"
    SEQ_MISMATCH = "SEQ_MISMATCH"
    PREV_HASH_MISMATCH = "PREV_HASH_MISMATCH"
    ENTRY_HASH_MISMATCH = "ENTRY_HASH_MISMATCH"
    VERSION_DOWNGRADE = "VERSION_DOWNGRADE"
    CHECKPOINT_MISSING = "CHECKPOINT_MISSING"
    CHECKPOINT_MALFORMED = "CHECKPOINT_MALFORMED"
    CHECKPOINT_KEY_UNKNOWN = "CHECKPOINT_KEY_UNKNOWN"
    SIGNING_BACKEND_UNAVAILABLE = "SIGNING_BACKEND_UNAVAILABLE"
    CHECKPOINT_SIGNATURE_INVALID = "CHECKPOINT_SIGNATURE_INVALID"
    CHAIN_TRUNCATED = "CHAIN_TRUNCATED"
    CHECKPOINT_HEAD_MISMATCH = "CHECKPOINT_HEAD_MISMATCH"


class CheckpointSigner(Protocol):
    """A caller-provided signer; roe-guard never stores or derives keys."""

    key_id: str

    def sign(self, message: bytes) -> bytes: ...


def _load_ed25519() -> Any:
    from cryptography.hazmat.primitives.asymmetric import ed25519

    return ed25519


class Ed25519Signer:
    """Ed25519 checkpoint signer over a raw 32-byte private key."""

    def __init__(self, private_key_bytes: bytes) -> None:
        if len(private_key_bytes) != 32:
            raise ValueError("ed25519 private key must be 32 raw bytes")
        try:
            ed25519 = _load_ed25519()
        except ImportError as exc:
            raise RoeGuardError(
                "ed25519 backend unavailable: install roe-guard[signing]"
            ) from exc
        from cryptography.hazmat.primitives.serialization import (
            Encoding,
            PublicFormat,
        )

        self._private = ed25519.Ed25519PrivateKey.from_private_bytes(private_key_bytes)
        public = self._private.public_key().public_bytes(
            encoding=Encoding.Raw,
            format=PublicFormat.Raw,
        )
        self.key_id = "sha256:" + hashlib.sha256(public).hexdigest()
        self._public_bytes = public

    def sign(self, message: bytes) -> bytes:
        signature: bytes = self._private.sign(message)
        return bytes(signature)


class AuditWriterLockedError(RoeGuardError):
    """Raised when another writer holds the audit file lock."""


def _duplicate_keys_hook(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate key: {key}")
        result[key] = value
    return result


def _check_v2_line(
    record: dict[str, Any], expected_chain_id: str, index: int, seq: int, prev_hash: str
) -> tuple[str, int] | None:
    keys = set(record)
    if keys - set(V2_KEYS):
        # Extra keys are an unknown-field problem...
        return ("UNKNOWN_FIELD", index)
    if set(V2_KEYS) - keys:
        # ...while missing keys are malformed (SPEC §14.7 order).
        return ("MALFORMED", index)
    if record["v"] != 2 or isinstance(record["v"], bool):
        return ("UNKNOWN_VERSION", index)
    if (
        not isinstance(record["seq"], int)
        or isinstance(record["seq"], bool)
        or record["seq"] != seq
    ):
        return ("SEQ_MISMATCH", index)
    if not isinstance(record["chain_id"], str) or not CHAIN_ID_RE.fullmatch(
        record["chain_id"]
    ):
        return ("CHAIN_ID_MISMATCH", index)
    if record["chain_id"] != expected_chain_id:
        return ("CHAIN_ID_MISMATCH", index)
    if not isinstance(record["timestamp"], str) or not TIMESTAMP_RE.fullmatch(
        record["timestamp"]
    ):
        return ("TIMESTAMP_FORMAT", index)
    if not isinstance(record["policy_sha256"], str) or not POLICY_SHA_RE.fullmatch(
        record["policy_sha256"]
    ):
        return ("MALFORMED", index)
    if record["prev_hash"] != prev_hash:
        return ("PREV_HASH_MISMATCH", index)
    if record["entry_hash"] != _entry_hash(record):
        return ("ENTRY_HASH_MISMATCH", index)
    return None


def verify_chain(
    path: str | Path,
    *,
    checkpoints_path: str | Path | None = None,
    public_keys: Mapping[str, bytes] | None = None,
    check_checkpoints: bool = True,
) -> AuditVerificationResult:
    """Verify a (possibly mixed v1→v2) audit chain; optionally checkpoints."""
    from roe_guard.models import AuditVerificationResult

    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"audit file not found: {p}")

    lines = p.read_text(encoding="utf-8").splitlines()
    total = len(lines)
    expected_seq = 0
    prev_hash = GENESIS_PREV_HASH
    expected_chain_id: str | None = None
    seen_v2 = False

    for index, line in enumerate(lines):
        if not line.strip():
            return AuditVerificationResult(
                valid=False,
                total_entries=total,
                broken_at_index=index,
                reason=f"empty line at {index}",
                reason_code="INVALID_JSON",
            )
        try:
            record = json.loads(line, object_pairs_hook=_duplicate_keys_hook)
        except json.JSONDecodeError as exc:
            return AuditVerificationResult(
                valid=False,
                total_entries=total,
                broken_at_index=index,
                # v1 text kept byte-identical for the mixed-chain contract.
                reason=f"line {index}: invalid JSON: {exc}",
                reason_code="INVALID_JSON",
            )
        except ValueError as exc:
            # Duplicate keys via the object_pairs_hook are malformed input,
            # not a JSON syntax problem (SPEC §14.7 step 2).
            return AuditVerificationResult(
                valid=False,
                total_entries=total,
                broken_at_index=index,
                reason=f"line {index}: {exc}",
                reason_code="MALFORMED",
            )
        if not isinstance(record, dict):
            return AuditVerificationResult(
                valid=False,
                total_entries=total,
                broken_at_index=index,
                reason=f"line {index} is not an object",
                reason_code="MALFORMED",
            )
        version = record.get("v")
        if version is None:
            # --- v1 line (SPEC §14.7: v1 keeps the v1 rules) -------------
            if seen_v2:
                return AuditVerificationResult(
                    valid=False,
                    total_entries=total,
                    broken_at_index=index,
                    reason="v1 record after a v2 record",
                    reason_code="VERSION_DOWNGRADE",
                )
            problem: tuple[str, int] | tuple[str, int | None] | None = _check_v1_line(
                record, index, prev_hash
            )
            if problem is not None:
                code, at = problem
                # v1 free-text reasons stay byte-identical to
                # AuditLog.verify (the 152-test contract).
                v1_text = {
                    "UNKNOWN_FIELD": f"line {at}: malformed entry: unexpected keys",
                    "MALFORMED": f"line {at}: malformed entry",
                    "PREV_HASH_MISMATCH": f"line {at}: prev_hash mismatch",
                    "ENTRY_HASH_MISMATCH": f"line {at}: entry_hash mismatch",
                }
                return AuditVerificationResult(
                    valid=False,
                    total_entries=total,
                    broken_at_index=at,
                    reason=v1_text.get(code, f"line {at}: {code}"),
                    reason_code=code,
                )
            prev_hash = record["entry_hash"]
            expected_seq += 1
            continue
        # --- v2 line -----------------------------------------------------
        if not seen_v2:
            if "chain_id" in record and isinstance(record["chain_id"], str):
                expected_chain_id = record["chain_id"]
            seen_v2 = True
        problem2 = _check_v2_line(
            record, expected_chain_id or "", index, expected_seq, prev_hash
        )
        if problem2 is not None:
            code2, at2 = problem2
            return AuditVerificationResult(
                valid=False,
                total_entries=total,
                broken_at_index=at2,
                reason=f"line {at2}: {code2}",
                reason_code=code2,
            )
        prev_hash = record["entry_hash"]
        expected_seq += 1

    result = AuditVerificationResult(
        valid=True,
        total_entries=total,
        broken_at_index=None,
        reason=None,
        reason_code=None,
    )

    if not check_checkpoints:
        return result
    ckpt = (
        Path(checkpoints_path)
        if checkpoints_path is not None
        else Path(str(p) + ".checkpoints.jsonl")
    )
    if ckpt.exists():
        problem = _verify_checkpoints(
            ckpt, public_keys, total, prev_hash, expected_chain_id
        )
        if problem is not None:
            code, at = problem
            return AuditVerificationResult(
                valid=False,
                total_entries=total,
                broken_at_index=at,
                reason=f"checkpoint: {code}",
                reason_code=code,
            )
    elif checkpoints_path is not None:
        return AuditVerificationResult(
            valid=False,
            total_entries=total,
            broken_at_index=None,
            reason="checkpoint file not found",
            reason_code="CHECKPOINT_MISSING",
        )
    return result


def _check_v1_line(
    record: dict[str, Any], index: int, expected_prev: str
) -> tuple[str, int] | None:
    """The v1 rules, byte-identical to AuditLog.verify (reason texts too)."""
    v1_keys = {
        "action_type",
        "decision",
        "engagement_id",
        "entry_hash",
        "prev_hash",
        "reason",
        "target",
        "timestamp",
    }
    if set(record) != v1_keys:
        return ("UNKNOWN_FIELD", index)
    try:
        from datetime import datetime as _dt

        _dt.fromisoformat(record["timestamp"])
    except (KeyError, ValueError):
        return ("MALFORMED", index)
    if record["prev_hash"] != expected_prev:
        return ("PREV_HASH_MISMATCH", index)
    if record["entry_hash"] != _v1_entry_hash(record):
        return ("ENTRY_HASH_MISMATCH", index)
    return None


def _v1_entry_hash(record: dict[str, Any]) -> str:
    # v1 rule (byte-identical to AuditLog._hash_entry): the payload holds
    # the 8 v1 keys, timestamp re-serialized via isoformat(), and
    # entry_hash replaced by "".
    payload = {
        "engagement_id": record.get("engagement_id", ""),
        "timestamp": record["timestamp"],
        "target": record["target"],
        "action_type": record["action_type"],
        "decision": record["decision"],
        "reason": record.get("reason", ""),
        "prev_hash": record["prev_hash"],
        "entry_hash": "",
    }
    return hashlib.sha256(
        json.dumps(
            payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode()
    ).hexdigest()


def _verify_checkpoints(
    ckpt_path: Path,
    public_keys: Mapping[str, bytes] | None,
    total_records: int,
    head_hash: str,
    expected_chain_id: str | None,
) -> tuple[str, int | None] | None:
    if not ckpt_path.exists():
        return ("CHECKPOINT_MISSING", None)
    last_seq: int | None = None
    try:
        lines = ckpt_path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return ("CHECKPOINT_MISSING", None)
    for line in lines:
        if not line.strip():
            return ("CHECKPOINT_MALFORMED", last_seq or 0)
        try:
            checkpoint = json.loads(line, object_pairs_hook=_duplicate_keys_hook)
        except ValueError:
            return ("CHECKPOINT_MALFORMED", last_seq or 0)
        if not isinstance(checkpoint, dict) or set(checkpoint) != set(CHECKPOINT_KEYS):
            return ("CHECKPOINT_MALFORMED", last_seq or 0)
        seq = checkpoint["seq"]
        if (
            isinstance(seq, bool)
            or not isinstance(seq, int)
            or (last_seq is not None and seq <= last_seq)
        ):
            return ("CHECKPOINT_MALFORMED", last_seq or 0)
        if not KEY_ID_RE.fullmatch(
            str(checkpoint.get("key_id", ""))
        ) or not SIG_RE.fullmatch(str(checkpoint.get("sig", ""))):
            return ("CHECKPOINT_MALFORMED", seq)
        if not isinstance(
            checkpoint.get("timestamp"), str
        ) or not TIMESTAMP_RE.fullmatch(checkpoint["timestamp"]):
            return ("CHECKPOINT_MALFORMED", seq)
        if (
            expected_chain_id is not None
            and checkpoint["chain_id"] != expected_chain_id
        ):
            return ("CHAIN_ID_MISMATCH", seq)
        key_id = checkpoint["key_id"]
        if public_keys is None or key_id not in public_keys:
            return ("CHECKPOINT_KEY_UNKNOWN", seq)
        sig_message = {k: v for k, v in checkpoint.items() if k != "sig"}
        signature = base64.urlsafe_b64decode(
            checkpoint["sig"] + "=" * (-len(checkpoint["sig"]) % 4)
        )
        try:
            from cryptography.exceptions import InvalidSignature
            from cryptography.hazmat.primitives.asymmetric import ed25519

            if ed25519 is None:
                return ("SIGNING_BACKEND_UNAVAILABLE", seq)
            public = ed25519.Ed25519PublicKey.from_public_bytes(public_keys[key_id])
            public.verify(signature, canonicalize(sig_message))
        except ImportError:
            return ("SIGNING_BACKEND_UNAVAILABLE", seq)
        except InvalidSignature:
            return ("CHECKPOINT_SIGNATURE_INVALID", seq)
        except (ValueError, TypeError):
            return ("CHECKPOINT_MALFORMED", seq)
        if seq >= total_records:
            return ("CHAIN_TRUNCATED", total_records)
        if checkpoint["head_hash"] != head_hash and seq == total_records - 1:
            return ("CHECKPOINT_HEAD_MISMATCH", seq)
        last_seq = seq
    if last_seq is not None and last_seq != total_records - 1:
        return ("CHECKPOINT_HEAD_MISMATCH", last_seq)
    return None


class AuditLogV2:
    """Single-writer JSONL audit log over the v2 record format.

    Opening takes an exclusive non-blocking flock and re-verifies the
    existing content; a corrupt file is never appended to.
    """

    def __init__(
        self,
        path: str | Path,
        *,
        chain_id: str,
        signer: CheckpointSigner | None = None,
        checkpoint_every: int = 1000,
        clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
    ) -> None:
        if not CHAIN_ID_RE.fullmatch(chain_id):
            raise ValueError(f"invalid chain_id: {chain_id!r}")
        self.path = Path(path)
        self.chain_id = chain_id
        self.signer = signer
        self.checkpoint_every = checkpoint_every
        self._clock = clock
        self._seq = 0
        self._head_hash = GENESIS_PREV_HASH
        self._records_since_checkpoint = 0
        self._file = None
        self._fd = None

        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._file = self.path.open("a+", encoding="utf-8")
        self._fd = self._file.fileno()
        try:
            fcntl.flock(self._fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            self._file.close()
            if exc.errno in (errno.EACCES, errno.EAGAIN):
                raise AuditWriterLockedError(
                    f"another writer holds {self.path}"
                ) from exc
            raise
        # Verify existing content before appending anything.
        if self.path.stat().st_size:
            result = verify_chain(self.path, check_checkpoints=False)
            if not result.valid:
                self._release()
                raise AuditIntegrityError(
                    f"existing audit file is invalid: {result.reason}"
                )
            lines = self.path.read_text(encoding="utf-8").splitlines()
            if lines:
                last = json.loads(lines[-1])
                last_chain = last.get("chain_id")
                if last_chain is not None and last_chain != self.chain_id:
                    self._release()
                    raise AuditIntegrityError(
                        f"existing chain_id {last_chain!r} != {self.chain_id!r}"
                    )
                self._seq = (
                    (last.get("seq", -1) + 1) if last.get("v") == 2 else len(lines)
                )
                self._head_hash = last["entry_hash"]

    def __enter__(self) -> "AuditLogV2":  # noqa: PYI034, UP037
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()

    def _release(self) -> None:
        if self._fd is not None:
            try:
                fcntl.flock(self._fd, fcntl.LOCK_UN)
            finally:
                self._fd = None
        if self._file is not None:
            self._file.close()
            self._file = None

    def record(
        self,
        decision: Any,
        *,
        engagement_id: str,
        policy_sha256: str,
        metadata: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        if not POLICY_SHA_RE.fullmatch(policy_sha256):
            raise ValueError(f"invalid policy_sha256: {policy_sha256!r}")
        if not isinstance(engagement_id, str) or not engagement_id:
            raise ValueError("engagement_id must be a non-empty string")
        record: dict[str, Any] = {
            "v": 2,
            "seq": self._seq,
            "chain_id": self.chain_id,
            "timestamp": _utc_timestamp(decision.timestamp),
            "engagement_id": engagement_id,
            "policy_sha256": policy_sha256,
            "mode": decision.mode.value,
            "agent_id": decision.agent_id,
            "target": decision.target,
            "action_type": decision.action_type,
            "decision": decision.outcome.value,
            "reason": decision.reason,
            "reason_code": decision.reason_code,
            "metadata": dict(metadata) if metadata else {},
            "prev_hash": self._head_hash,
        }
        # Canonicalize once: raises for JCS-incompatible metadata.
        canonicalize({k: v for k, v in record.items() if k != "entry_hash"})
        record["entry_hash"] = _entry_hash(record)
        line = canonicalize(record) + b"\n"
        assert self._file is not None
        self._file.write(line.decode("utf-8"))
        self._file.flush()
        self._head_hash = record["entry_hash"]
        self._seq += 1
        self._records_since_checkpoint += 1
        if (
            self.signer is not None
            and self._records_since_checkpoint >= self.checkpoint_every
        ):
            self.checkpoint()
        return record

    def checkpoint(self) -> dict[str, Any]:
        if self.signer is None:
            raise RoeGuardError("checkpoint requires a signer")
        assert self._file is not None and self._fd is not None
        self._file.flush()
        import os

        os.fsync(self._fd)
        checkpoint = {
            "v": 2,
            "chain_id": self.chain_id,
            "seq": self._seq - 1,
            "head_hash": self._head_hash,
            "timestamp": _utc_timestamp(self._clock()),
            "key_id": self.signer.key_id,
        }
        signature = self.signer.sign(canonicalize(checkpoint))
        checkpoint["sig"] = (
            base64.urlsafe_b64encode(signature).rstrip(b"=").decode("ascii")
        )
        ckpt_path = Path(str(self.path) + ".checkpoints.jsonl")
        with ckpt_path.open("a", encoding="utf-8") as fh:
            fh.write(canonicalize(checkpoint).decode("utf-8") + "\n")
            fh.flush()
            os.fsync(fh.fileno())
        self._records_since_checkpoint = 0
        return checkpoint

    def close(self) -> None:
        try:
            if (
                self.signer is not None
                and self._records_since_checkpoint > 0
                and self._file is not None
            ):
                self.checkpoint()
        finally:
            self._release()


__all__ = [
    "AuditLogV2",
    "AuditReasonCode",
    "AuditWriterLockedError",
    "CheckpointSigner",
    "Ed25519Signer",
    "verify_chain",
]
