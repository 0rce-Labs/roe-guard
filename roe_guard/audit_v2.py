"""Audit record v2: seq, JCS hashing, single writer, signed checkpoints.

Contract: SPEC §14.7. The record carries exactly 16 keys; the hash is
sha256 over the JCS serialization of the record minus ``entry_hash``.
Lines are the JCS serialization of the full record plus ``\\n``.
Verification handles mixed v1→v2 chains; v1 lines keep the v1 rules.
"""

from __future__ import annotations

import base64
import errno
import hashlib
import importlib
import json
import os
import re
import threading
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Protocol

from roe_guard.audit import GENESIS_PREV_HASH, _hash_entry
from roe_guard.exceptions import (
    AuditIntegrityError,
    AuditWriterLockedError,
    RoeGuardError,
)
from roe_guard.jcs import canonicalize
from roe_guard.models import (
    AuditEntry,
    AuditVerificationResult,
    Decision,
    DecisionType,
)

_fcntl: Any
try:
    _fcntl = importlib.import_module("fcntl")
except ImportError:  # pragma: no cover - fcntl is POSIX-only
    _fcntl = None

# SPEC §14.7 patterns; always applied with fullmatch and re.ASCII.
CHAIN_ID_RE = re.compile(r"^[A-Za-z0-9._:-]{1,128}$", re.ASCII)
TIMESTAMP_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$", re.ASCII)
POLICY_SHA_RE = re.compile(r"^[0-9a-f]{64}$", re.ASCII)
HASH_RE = re.compile(r"^[0-9a-f]{64}$", re.ASCII)
KEY_ID_RE = re.compile(r"^sha256:[0-9a-f]{64}$", re.ASCII)
SIG_RE = re.compile(r"^[A-Za-z0-9_-]{86}$", re.ASCII)

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

_MODES = ("enforce", "observe")
_DECISIONS = ("ALLOW", "DENY", "REQUIRES_APPROVAL")
_STR_FIELDS = ("agent_id", "target", "action_type", "reason", "reason_code")


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


_RC = AuditReasonCode


# --------------------------------------------------------------------------- #
# Helpers                                                                     #
# --------------------------------------------------------------------------- #


def _is_int(value: object) -> bool:
    # JSON integers only: bool is not an int here.
    return type(value) is int


def _utc_timestamp(dt: object) -> str:
    if not isinstance(dt, datetime) or dt.utcoffset() is None:
        raise ValueError("timestamp must be a timezone-aware datetime")
    text = dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    if not TIMESTAMP_RE.fullmatch(text):
        raise ValueError(f"timestamp outside the SPEC §14.7 format: {text!r}")
    return text


def _entry_hash(record: Mapping[str, Any]) -> str:
    # SPEC §14.7: the hash covers the record minus the entry_hash key.
    payload = {k: v for k, v in record.items() if k != "entry_hash"}
    return hashlib.sha256(canonicalize(payload)).hexdigest()


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


class _StrictJSONError(ValueError):
    """A JSON text the v2 rules refuse: NaN/Infinity are not JSON."""


class _DuplicateKeyError(_StrictJSONError):
    """The same key twice in one object (SPEC §14.7 step 2)."""


def _reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateKeyError(f"duplicate key {key!r}")
        result[key] = value
    return result


def _reject_constant(name: str) -> Any:
    raise _StrictJSONError(f"{name} is not valid JSON")


def _strict_loads(text: str) -> Any:
    """Parse *text* under the v2 rules.

    SPEC §14.7 step 1 (not JSON, NaN/Infinity, too deep for the parser) wins
    over step 2 (duplicate key). A single parse would stop at a duplicate key
    in a nested object before it reached a later NaN, so the text is parsed
    once without and then once with the duplicate check.

    Raises:
        _DuplicateKeyError: step 2.
        ValueError or RecursionError: step 1 (``json.JSONDecodeError`` and
            ``_StrictJSONError`` are ``ValueError`` subclasses).
    """
    json.loads(text, parse_constant=_reject_constant)
    return json.loads(text, object_pairs_hook=_reject_duplicates)


def _is_canonical(raw: bytes, value: Any) -> bool:
    """``raw == JCS(value)``; a value outside the JCS subset is not canonical."""
    try:
        return raw == canonicalize(value)
    except (TypeError, ValueError, RecursionError):
        return False


def _short_repr(value: object, limit: int = 80) -> str:
    """``repr`` for messages; never raises on deeply nested or huge values."""
    try:
        text = repr(value)
    except RecursionError:
        return "<nested too deeply>"
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _v1_head(value: object) -> str:
    """``f"{value[:12]}"`` as the original v1 texts wrote it; never raises.

    The original sliced whatever the line held (a string or a list); for
    other types it raised, so any stable text is acceptable there.
    """
    try:
        return f"{value[:12]}"  # type: ignore[index]
    except (TypeError, KeyError, RecursionError):
        try:
            return str(value)[:12]
        except RecursionError:
            return "<nested>"


def _split_lines(data: bytes) -> list[bytes]:
    # Split on b"\n" only: JCS writes U+0085, U+2028 and U+2029 raw, so
    # str.splitlines() would cut valid records apart.
    lines = data.split(b"\n")
    if lines and lines[-1] == b"":
        lines.pop()
    return lines


def _load_ed25519() -> Any:
    # import_module honours a None entry in sys.modules, so a missing or
    # disabled backend reliably raises ImportError.
    return importlib.import_module("cryptography.hazmat.primitives.asymmetric.ed25519")


# --------------------------------------------------------------------------- #
# Signing                                                                     #
# --------------------------------------------------------------------------- #


class CheckpointSigner(Protocol):
    """A caller-provided signer; roe-guard never stores or derives keys."""

    key_id: str

    def sign(self, message: bytes) -> bytes: ...


class Ed25519Signer:
    """Ed25519 checkpoint signer over a raw 32-byte private key."""

    def __init__(self, private_key_bytes: bytes) -> None:
        if not isinstance(private_key_bytes, bytes) or len(private_key_bytes) != 32:
            raise ValueError("ed25519 private key must be 32 raw bytes")
        unavailable = "ed25519 backend unavailable: install roe-guard[signing]"
        try:
            ed25519 = _load_ed25519()
            serialization = importlib.import_module(
                "cryptography.hazmat.primitives.serialization"
            )
            crypto_errors = importlib.import_module("cryptography.exceptions")
        except ImportError as exc:
            raise RoeGuardError(unavailable) from exc
        try:
            self._private = ed25519.Ed25519PrivateKey.from_private_bytes(
                private_key_bytes
            )
        except crypto_errors.UnsupportedAlgorithm as exc:
            raise RoeGuardError(unavailable) from exc
        public: bytes = self._private.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        self.key_id = "sha256:" + hashlib.sha256(public).hexdigest()

    def sign(self, message: bytes) -> bytes:
        return bytes(self._private.sign(message))


# --------------------------------------------------------------------------- #
# Verification                                                                #
# --------------------------------------------------------------------------- #


@dataclass
class _ChainState:
    """What a chain scan learned; the writer resumes from it."""

    result: AuditVerificationResult
    records: int = 0
    head_hash: str = GENESIS_PREV_HASH
    chain_id: str | None = None
    hashes: list[str] = field(default_factory=list)
    ends_with_newline: bool = True


def _fail(
    index: int | None, total: int, reason: str, code: AuditReasonCode
) -> AuditVerificationResult:
    return AuditVerificationResult(
        valid=False,
        total_entries=total,
        broken_at_index=index,
        reason=reason,
        reason_code=code.value,
    )


def _check_v1_line(
    payload: dict[str, Any], index: int, expected_prev: str, total: int
) -> AuditVerificationResult | None:
    """The v1 rules of the original ``AuditLog.verify``: order and texts.

    The order matters for byte-identical results: build the entry, check
    ``prev_hash``, then hash. Inputs on which the original raised instead of
    returning (a TypeError, a RecursionError on deep nesting, a string JSON
    cannot encode) are reported as MALFORMED.
    """
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
    except (KeyError, ValueError, TypeError, RecursionError) as exc:
        return _fail(
            index, total, f"line {index}: malformed entry: {exc}", _RC.MALFORMED
        )

    if entry.prev_hash != expected_prev:
        return _fail(
            index,
            total + 1,
            f"line {index}: prev_hash mismatch "
            f"(expected {expected_prev[:12]}…, got {_v1_head(entry.prev_hash)}…)",
            _RC.PREV_HASH_MISMATCH,
        )
    try:
        computed = _hash_entry(entry)
    except (TypeError, ValueError, RecursionError) as exc:
        return _fail(
            index, total, f"line {index}: malformed entry: {exc}", _RC.MALFORMED
        )
    if computed != entry.entry_hash:
        return _fail(
            index,
            total + 1,
            f"line {index}: entry_hash mismatch "
            f"(expected {computed[:12]}…, got {_v1_head(entry.entry_hash)}…)",
            _RC.ENTRY_HASH_MISMATCH,
        )
    return None


def _v2_field_problem(record: dict[str, Any]) -> str | None:
    """SPEC §14.7 step 5: types and values (timestamp format is step 6)."""
    seq = record["seq"]
    if not _is_int(seq) or seq < 0:
        return "seq must be an integer >= 0"
    chain_id = record["chain_id"]
    if not isinstance(chain_id, str) or not CHAIN_ID_RE.fullmatch(chain_id):
        return "chain_id does not match the SPEC pattern"
    if not isinstance(record["timestamp"], str):
        return "timestamp must be a string"
    engagement_id = record["engagement_id"]
    if not isinstance(engagement_id, str) or not engagement_id:
        return "engagement_id must be a non-empty string"
    policy_sha = record["policy_sha256"]
    if not isinstance(policy_sha, str) or not POLICY_SHA_RE.fullmatch(policy_sha):
        return "policy_sha256 must be 64 lowercase hex characters"
    if not isinstance(record["mode"], str) or record["mode"] not in _MODES:
        return "mode must be 'enforce' or 'observe'"
    for name in _STR_FIELDS:
        if not isinstance(record[name], str):
            return f"{name} must be a string"
    if not isinstance(record["decision"], str) or record["decision"] not in _DECISIONS:
        return "decision must be ALLOW, DENY or REQUIRES_APPROVAL"
    if not isinstance(record["metadata"], dict):
        return "metadata must be an object"
    for name in ("prev_hash", "entry_hash"):
        value = record[name]
        if not isinstance(value, str) or not HASH_RE.fullmatch(value):
            return f"{name} must be 64 lowercase hex characters"
    try:
        canonicalize({k: v for k, v in record.items() if k != "entry_hash"})
    except (TypeError, ValueError, RecursionError) as exc:
        return f"value outside the JCS subset: {exc}"
    return None


def _scan_chain(path: Path) -> _ChainState:
    """Verify every line of *path* (SPEC §14.7 order); never raises on content."""
    data = path.read_bytes()
    try:
        return _scan_lines(data)
    except RecursionError:
        # Last resort: every step catches its own errors, but a value nested
        # too deeply for the interpreter must still give a result. SPEC
        # §14.7: nesting deeper than 64 is MALFORMED.
        state = _ChainState(
            result=_fail(None, 0, "value nested too deeply", _RC.MALFORMED),
            ends_with_newline=not data or data.endswith(b"\n"),
        )
        return state


def _scan_lines(data: bytes) -> _ChainState:
    state = _ChainState(
        result=AuditVerificationResult(valid=True, total_entries=0),
        ends_with_newline=not data or data.endswith(b"\n"),
    )
    seen_v2 = False
    total = 0

    segments = _split_lines(data)
    for index, raw in enumerate(segments):
        terminated = state.ends_with_newline or index < len(segments) - 1
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            state.result = _fail(
                index, total, f"line {index}: invalid UTF-8: {exc}", _RC.INVALID_JSON
            )
            return state

        if not text.strip():
            if seen_v2:
                state.result = _fail(
                    index, total, f"line {index}: empty line", _RC.INVALID_JSON
                )
                return state
            # v1 rule: blank lines are skipped.
            continue

        # Step 1: JSON. The plain parse keeps the v1 texts byte-identical.
        try:
            payload = json.loads(text.strip())
        except (ValueError, RecursionError) as exc:
            state.result = _fail(
                index, total, f"line {index}: invalid JSON: {exc}", _RC.INVALID_JSON
            )
            return state
        if not isinstance(payload, dict):
            state.result = _fail(
                index,
                total,
                f"line {index}: malformed entry: not a JSON object",
                _RC.MALFORMED,
            )
            return state

        if "v" not in payload:
            # --- v1 line ---------------------------------------------------
            if seen_v2:
                state.result = _fail(
                    index,
                    total,
                    f"line {index}: v1 record after a v2 record",
                    _RC.VERSION_DOWNGRADE,
                )
                return state
            problem = _check_v1_line(payload, index, state.head_hash, total)
            if problem is not None:
                state.result = problem
                return state
            entry_hash = payload["entry_hash"]
        else:
            # --- v2 line ---------------------------------------------------
            seen_v2 = True
            code: AuditReasonCode | None = None
            detail = ""
            try:
                record = _strict_loads(text)
            except _DuplicateKeyError as exc:
                code, detail, record = _RC.MALFORMED, str(exc), {}
            except (ValueError, RecursionError) as exc:
                # Step 1: NaN/Infinity, or bytes that only parsed after the
                # routing parse's str.strip() (e.g. a leading \x0c or U+00A0,
                # which are not JSON whitespace).
                code, detail, record = _RC.INVALID_JSON, str(exc), {}
            if code is None:
                missing = [k for k in V2_KEYS if k not in record]
                extra = sorted(k for k in record if k not in V2_KEYS)
                if missing:
                    code, detail = _RC.MALFORMED, f"missing keys {missing}"
                elif not _is_int(record["v"]) or record["v"] != 2:
                    code, detail = (
                        _RC.UNKNOWN_VERSION,
                        f"v = {_short_repr(record['v'])}",
                    )
                elif extra:
                    code, detail = _RC.UNKNOWN_FIELD, f"unknown keys {extra}"
                elif (field_problem := _v2_field_problem(record)) is not None:
                    code, detail = _RC.MALFORMED, field_problem
                elif not _is_canonical(raw, record) or not terminated:
                    code, detail = _RC.MALFORMED, "line is not JCS(record) + \\n"
                elif not TIMESTAMP_RE.fullmatch(record["timestamp"]):
                    code, detail = _RC.TIMESTAMP_FORMAT, "timestamp format"
                elif (
                    state.chain_id is not None and record["chain_id"] != state.chain_id
                ):
                    code, detail = (
                        _RC.CHAIN_ID_MISMATCH,
                        (f"chain_id {record['chain_id']!r} != {state.chain_id!r}"),
                    )
                elif record["seq"] != state.records:
                    code, detail = (
                        _RC.SEQ_MISMATCH,
                        (f"seq {record['seq']} != {state.records}"),
                    )
                elif record["prev_hash"] != state.head_hash:
                    code, detail = _RC.PREV_HASH_MISMATCH, "prev_hash mismatch"
                elif record["entry_hash"] != _entry_hash(record):
                    code, detail = _RC.ENTRY_HASH_MISMATCH, "entry_hash mismatch"
            if code is not None:
                state.result = _fail(index, total, f"line {index}: {detail}", code)
                return state
            if state.chain_id is None:
                state.chain_id = record["chain_id"]
            entry_hash = record["entry_hash"]

        state.head_hash = entry_hash
        state.hashes.append(entry_hash)
        state.records += 1
        total += 1

    state.result = AuditVerificationResult(valid=True, total_entries=total)
    return state


def _read_checkpoints(ckpt_path: Path) -> bytes | None:
    """The checkpoint file's bytes, or None when it is missing."""
    try:
        return ckpt_path.read_bytes()
    except (FileNotFoundError, IsADirectoryError, NotADirectoryError):
        return None


def _verify_checkpoints(
    data: bytes | None,
    public_keys: Mapping[str, bytes] | None,
    state: _ChainState,
    *,
    expected_chain_id: str | None = None,
    check_signatures: bool = True,
) -> tuple[AuditReasonCode, int | None] | None:
    """SPEC §14.7 checkpoint order; returns (code, broken_at_index) or None.

    *data* is the checkpoint file read before the chain, so a live writer
    (record and fsync first, checkpoint second) never looks truncated.
    The writer runs it with ``check_signatures=False`` on open: format,
    chain_id, truncation and heads need no key.
    """
    segments = _split_lines(data) if data is not None else []
    if not segments:
        # A given path with no checkpoint line protects nothing, the same
        # as a deleted file.
        return (_RC.CHECKPOINT_MISSING, None)
    assert data is not None
    expected_chain_id = state.chain_id or expected_chain_id
    last_seq: int | None = None

    for index, raw in enumerate(segments):
        terminated = data.endswith(b"\n") or index < len(segments) - 1
        try:
            checkpoint = _strict_loads(raw.decode("utf-8"))
        except (ValueError, RecursionError):  # UnicodeDecodeError included
            return (_RC.CHECKPOINT_MALFORMED, None)
        if not isinstance(checkpoint, dict):
            return (_RC.CHECKPOINT_MALFORMED, None)
        seq: Any = checkpoint.get("seq")
        at: int | None = seq if _is_int(seq) and seq >= 0 else None
        if (
            set(checkpoint) != set(CHECKPOINT_KEYS)
            or not _is_int(checkpoint["v"])
            or checkpoint["v"] != 2
            or at is None
            or (last_seq is not None and seq < last_seq)
            or not isinstance(checkpoint["chain_id"], str)
            or not CHAIN_ID_RE.fullmatch(checkpoint["chain_id"])
            or not isinstance(checkpoint["head_hash"], str)
            or not HASH_RE.fullmatch(checkpoint["head_hash"])
            or not isinstance(checkpoint["timestamp"], str)
            or not TIMESTAMP_RE.fullmatch(checkpoint["timestamp"])
            or not isinstance(checkpoint["key_id"], str)
            or not KEY_ID_RE.fullmatch(checkpoint["key_id"])
            or not isinstance(checkpoint["sig"], str)
            or not SIG_RE.fullmatch(checkpoint["sig"])
            or not _is_canonical(raw, checkpoint)
            or not terminated
        ):
            return (_RC.CHECKPOINT_MALFORMED, at)
        signature = base64.urlsafe_b64decode(checkpoint["sig"] + "==")
        if _b64url(signature) != checkpoint["sig"]:
            # Non-zero padding bits: one signature, one spelling.
            return (_RC.CHECKPOINT_MALFORMED, at)

        if expected_chain_id is None:
            # A chain without v2 lines: checkpoints agree with each other.
            expected_chain_id = checkpoint["chain_id"]
        if checkpoint["chain_id"] != expected_chain_id:
            return (_RC.CHAIN_ID_MISMATCH, at)

        if check_signatures:
            problem = _check_signature(checkpoint, signature, public_keys)
            if problem is not None:
                return (problem, at)

        if seq >= state.records:
            return (_RC.CHAIN_TRUNCATED, state.records)
        if checkpoint["head_hash"] != state.hashes[seq]:
            return (_RC.CHECKPOINT_HEAD_MISMATCH, at)
        last_seq = seq
    return None


def _check_signature(
    checkpoint: dict[str, Any],
    signature: bytes,
    public_keys: Mapping[str, bytes] | None,
) -> AuditReasonCode | None:
    """Checkpoint steps 4-6: key id, ed25519 backend, signature."""
    key_id = checkpoint["key_id"]
    if public_keys is None or key_id not in public_keys:
        return _RC.CHECKPOINT_KEY_UNKNOWN
    try:
        ed25519 = _load_ed25519()
        crypto_errors = importlib.import_module("cryptography.exceptions")
    except ImportError:
        return _RC.SIGNING_BACKEND_UNAVAILABLE
    try:
        public = ed25519.Ed25519PublicKey.from_public_bytes(public_keys[key_id])
    except crypto_errors.UnsupportedAlgorithm:
        return _RC.SIGNING_BACKEND_UNAVAILABLE
    except ValueError:
        return _RC.CHECKPOINT_SIGNATURE_INVALID
    message = canonicalize({k: v for k, v in checkpoint.items() if k != "sig"})
    try:
        public.verify(signature, message)
    except crypto_errors.InvalidSignature:
        return _RC.CHECKPOINT_SIGNATURE_INVALID
    return None


def verify_chain(
    path: str | Path,
    *,
    checkpoints_path: str | Path | None = None,
    public_keys: Mapping[str, bytes] | None = None,
) -> AuditVerificationResult:
    """Verify a (possibly mixed v1→v2) audit chain and, optionally, checkpoints.

    Lines are checked in the SPEC §14.7 order. v1 lines keep the v1 rules
    and texts of the original ``AuditLog.verify``; a v1 line after a v2
    line is ``VERSION_DOWNGRADE``. Checkpoints are verified only when
    *checkpoints_path* is given; *public_keys* maps ``key_id`` to the raw
    32-byte ed25519 public key.

    ``total_entries`` counts the records verified before the failing line
    (v1 hash mismatches keep the v1 value, which counts the failing line);
    checkpoint failures carry the full record count.

    Raises:
        FileNotFoundError: *path* does not exist (never "valid").
        ValueError: a *public_keys* value is not 32 bytes.
    """
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"audit file not found: {p}")
    if public_keys is not None:
        for key_id, raw in public_keys.items():
            if not isinstance(raw, bytes) or len(raw) != 32:
                raise ValueError(f"public key for {key_id!r} must be 32 raw bytes")

    # Checkpoints first: every checkpoint read then names a record that is
    # already in the audit file, even while the writer is appending.
    ckpt_data = None
    if checkpoints_path is not None:
        ckpt_data = _read_checkpoints(Path(checkpoints_path))
    state = _scan_chain(p)
    if not state.result.valid or checkpoints_path is None:
        return state.result

    problem = _verify_checkpoints(ckpt_data, public_keys, state)
    if problem is None:
        return state.result
    code, at = problem
    return _fail(at, state.records, f"checkpoint: {code.value}", code)


# --------------------------------------------------------------------------- #
# Writer                                                                      #
# --------------------------------------------------------------------------- #


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _plain(value: Any) -> Any:
    # Enum members become their values so the record holds plain JSON types.
    return value.value if isinstance(value, Enum) else value


class AuditLogV2:
    """Single-writer JSONL audit log over the v2 record format.

    Opening takes an exclusive non-blocking flock and re-verifies the
    existing content (and, without keys, the existing checkpoints); a
    corrupt file is never appended to. One instance may be shared by
    threads; a failed write closes the writer.
    """

    def __init__(
        self,
        path: str | Path,
        *,
        chain_id: str,
        signer: CheckpointSigner | None = None,
        checkpoint_every: int = 1000,
        clock: Callable[[], datetime] = _utc_now,
    ) -> None:
        if not isinstance(chain_id, str) or not CHAIN_ID_RE.fullmatch(chain_id):
            raise ValueError(f"invalid chain_id: {chain_id!r}")
        if not _is_int(checkpoint_every) or checkpoint_every < 1:
            raise ValueError("checkpoint_every must be an integer >= 1")
        if signer is not None:
            _check_key_id(signer.key_id)
        if _fcntl is None:
            raise RoeGuardError("audit writer needs fcntl.flock; refusing to open")

        # Absolute paths: a later chdir must not split the checkpoint file.
        self.path = Path(path).absolute()
        self.checkpoints_path = Path(str(self.path) + ".checkpoints.jsonl")
        self.chain_id = chain_id
        self.signer = signer
        self.checkpoint_every = checkpoint_every
        self._clock = clock
        self._lock = threading.Lock()

        self.path.parent.mkdir(parents=True, exist_ok=True)
        # Unbuffered: a failed write leaves nothing behind to flush later.
        self._file: Any = self.path.open("ab", buffering=0)
        try:
            _fcntl.flock(self._file.fileno(), _fcntl.LOCK_EX | _fcntl.LOCK_NB)
        except OSError as exc:
            self._file.close()
            self._file = None
            if exc.errno in (errno.EACCES, errno.EAGAIN):
                raise AuditWriterLockedError(
                    f"another writer holds {self.path}"
                ) from exc
            raise
        try:
            state = self._check_existing()
        except BaseException:
            self._release()
            raise
        self._seq = state.records
        self._head_hash = state.head_hash

    def _check_existing(self) -> _ChainState:
        state = _scan_chain(self.path)
        if not state.result.valid:
            raise AuditIntegrityError(
                f"existing audit file is invalid: {state.result.reason}"
            )
        if state.chain_id is not None and state.chain_id != self.chain_id:
            raise AuditIntegrityError(
                f"existing chain_id {state.chain_id!r} != {self.chain_id!r}"
            )
        if not state.ends_with_newline:
            raise AuditIntegrityError("existing audit file ends mid-line")
        covered = -1
        ckpt_data = _read_checkpoints(self.checkpoints_path)
        if ckpt_data:
            problem = _verify_checkpoints(
                ckpt_data,
                None,
                state,
                expected_chain_id=self.chain_id,
                check_signatures=False,
            )
            if problem is not None:
                raise AuditIntegrityError(
                    f"existing checkpoints do not match the chain: {problem[0].value}"
                )
            covered = json.loads(_split_lines(ckpt_data)[-1])["seq"]
        # Records a crashed writer left without a checkpoint count too.
        self._records_since_checkpoint = state.records - 1 - covered
        return state

    def __enter__(self) -> AuditLogV2:  # noqa: PYI034 - typing.Self is 3.11+
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()

    def _require_open(self) -> Any:
        if self._file is None:
            raise RoeGuardError("audit writer is closed")
        return self._file

    def _release(self) -> None:
        handle, self._file = self._file, None
        if handle is None:
            return
        try:
            _fcntl.flock(handle.fileno(), _fcntl.LOCK_UN)
        finally:
            handle.close()

    def record(
        self,
        decision: Decision,
        *,
        engagement_id: str,
        policy_sha256: str,
        metadata: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Append one decision; invalid input raises and writes nothing.

        When the periodic checkpoint fails, the record is already written
        and the checkpoint error propagates.
        """
        with self._lock:
            handle = self._require_open()
            if not isinstance(policy_sha256, str) or not POLICY_SHA_RE.fullmatch(
                policy_sha256
            ):
                raise ValueError(f"invalid policy_sha256: {policy_sha256!r}")
            if not isinstance(engagement_id, str) or not engagement_id:
                raise ValueError("engagement_id must be a non-empty string")
            if metadata is not None and not isinstance(metadata, Mapping):
                raise TypeError("metadata must be a mapping")
            record: dict[str, Any] = {
                "v": 2,
                "seq": self._seq,
                "chain_id": self.chain_id,
                "timestamp": _utc_timestamp(decision.timestamp),
                "engagement_id": engagement_id,
                "policy_sha256": policy_sha256,
                "mode": _plain(decision.mode),
                "agent_id": _plain(decision.agent_id),
                "target": _plain(decision.target),
                "action_type": _plain(decision.action_type),
                "decision": _plain(decision.outcome),
                "reason": _plain(decision.reason),
                "reason_code": _plain(decision.reason_code),
                "metadata": dict(metadata) if metadata is not None else {},
                "prev_hash": self._head_hash,
            }
            problem = _v2_field_problem({**record, "entry_hash": "0" * 64})
            if problem is not None:
                raise ValueError(f"record rejected: {problem}")
            record["entry_hash"] = _entry_hash(record)
            self._write_all(handle, canonicalize(record) + b"\n")
            self._head_hash = record["entry_hash"]
            self._seq += 1
            self._records_since_checkpoint += 1
            if (
                self.signer is not None
                and self._records_since_checkpoint >= self.checkpoint_every
            ):
                self._checkpoint()
            return record

    def _write_all(self, handle: Any, data: bytes) -> None:
        try:
            view = memoryview(data)
            while view:
                view = view[handle.write(view) :]
        except BaseException:
            # A partial line may be on disk; never append after it.
            self._release()
            raise

    def checkpoint(self) -> dict[str, Any]:
        """fsync the log, then append a signed checkpoint for the head record."""
        with self._lock:
            return self._checkpoint()

    def _checkpoint(self) -> dict[str, Any]:
        handle = self._require_open()
        if self.signer is None:
            raise RoeGuardError("checkpoint requires a signer")
        if self._seq == 0:
            raise RoeGuardError("checkpoint requires at least one record")
        _check_key_id(self.signer.key_id)
        os.fsync(handle.fileno())
        checkpoint: dict[str, Any] = {
            "v": 2,
            "chain_id": self.chain_id,
            "seq": self._seq - 1,
            "head_hash": self._head_hash,
            "timestamp": _utc_timestamp(self._clock()),
            "key_id": self.signer.key_id,
        }
        signature = self.signer.sign(canonicalize(checkpoint))
        if not isinstance(signature, bytes) or len(signature) != 64:
            raise ValueError("signer must return a 64-byte ed25519 signature")
        checkpoint["sig"] = _b64url(signature)
        line = canonicalize(checkpoint) + b"\n"
        try:
            with self.checkpoints_path.open("ab", buffering=0) as fh:
                view = memoryview(line)
                while view:
                    view = view[fh.write(view) :]
                os.fsync(fh.fileno())
        except BaseException:
            # A partial checkpoint line may be on disk; never append after it
            # (the next open reports it instead).
            self._release()
            raise
        self._records_since_checkpoint = 0
        return checkpoint

    def close(self) -> None:
        """Checkpoint uncovered records (when a signer is set), then unlock."""
        with self._lock:
            if self._file is None:
                return
            try:
                if self.signer is not None and self._records_since_checkpoint > 0:
                    self._checkpoint()
            finally:
                self._release()


def _check_key_id(key_id: object) -> None:
    if not isinstance(key_id, str) or not KEY_ID_RE.fullmatch(key_id):
        raise ValueError(f"signer key_id outside the SPEC §14.7 format: {key_id!r}")


__all__ = [
    "AuditLogV2",
    "AuditReasonCode",
    "AuditWriterLockedError",
    "CheckpointSigner",
    "Ed25519Signer",
    "verify_chain",
]
