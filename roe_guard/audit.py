"""
roe_guard.audit

Append-only JSONL audit log with SHA-256 hash chaining.

Each line contains a self-describing record (timestamp, target,
action, decision, reason) plus two hashes:

    - ``prev_hash``  — SHA-256 of the previous line's canonical JSON,
                       or a genesis constant (``"0" * 64``) for the first entry.
    - ``entry_hash`` — SHA-256 of *this* line's canonical JSON (including
                       ``prev_hash``).

Any after-the-fact modification, deletion, or insertion can be detected
by :meth:`AuditLog.verify` (spec §3, §7).

Implemented in T5.
"""

from __future__ import annotations

import errno
import hashlib
import json
from pathlib import Path
from typing import Any, TextIO

from roe_guard.exceptions import AuditIntegrityError, AuditWriterLockedError
from roe_guard.models import (
    AuditEntry,
    AuditVerificationResult,
    Decision,
)

GENESIS_PREV_HASH = "0" * 64
_HASH_FIELDS = ("prev_hash", "entry_hash")


def _canonical_payload(entry: AuditEntry) -> dict[str, Any]:
    """Return a JSON-serialisable, sorted dict of the entry's payload.

    ``prev_hash`` and ``entry_hash`` are included so the chain links
    cannot be tampered with after the fact.
    """
    return {
        "engagement_id": entry.engagement_id,
        "timestamp": entry.timestamp.isoformat(),
        "target": entry.target,
        "action_type": entry.action_type,
        "decision": entry.decision.value,
        "reason": entry.reason,
        "prev_hash": entry.prev_hash,
        "entry_hash": entry.entry_hash,
    }


def _hash_entry(entry: AuditEntry) -> str:
    """Compute SHA-256 of the entry's canonical JSON (sorted keys)."""
    payload = _canonical_payload(entry)
    # NOTE: we recompute entry_hash from a payload that does NOT yet
    # include the new entry_hash. To avoid circularity, build the payload
    # with entry_hash set to an empty string for hashing.
    payload["entry_hash"] = ""  # exclude from hash
    canonical = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _decision_to_entry(
    decision: Decision,
    prev_hash: str,
    entry_hash: str,
    engagement_id: str = "",
) -> AuditEntry:
    """Build an :class:`AuditEntry` from a :class:`Decision` + chain state."""
    return AuditEntry(
        engagement_id=engagement_id,
        timestamp=decision.timestamp,
        target=decision.target,
        action_type=decision.action_type,
        decision=decision.outcome,
        reason=decision.reason,
        prev_hash=prev_hash,
        entry_hash=entry_hash,
    )


def _lock_for_append(fh: TextIO) -> None:
    """Hold the writer lock for one append; a live ``AuditLogV2`` wins."""
    try:
        import fcntl
    except ImportError:  # pragma: no cover - non-POSIX: no lock, as before
        return
    try:
        fcntl.flock(fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError as exc:
        if exc.errno in (errno.EACCES, errno.EAGAIN):
            raise AuditWriterLockedError(f"another writer holds {fh.name}") from exc
        raise


class _OversizedInt:
    """An integer literal longer than the interpreter converts.

    It is far outside the JCS range (|n| <= 2^53-1), so its value is never
    needed: it is not an ``int`` for the v2 type checks (``v`` -> step 3,
    ``seq`` -> step 5), ``canonicalize`` rejects it (step 5), and it prints
    without converting.
    """

    __slots__ = ("digits",)

    def __init__(self, token: str) -> None:
        self.digits = len(token.lstrip("-"))

    def __repr__(self) -> str:
        return f"<integer with {self.digits} digits>"


def _parse_int(token: str) -> int | _OversizedInt:
    """A JSON integer literal, never a parse error and never slow.

    ``int(str)`` refuses literals longer than the interpreter's digit limit
    (4300 by default, 640 at the lowest), which would turn an out-of-range
    integer (SPEC §14.7 step 5) into a parse error (step 1). Converting them
    anyway is quadratic in the number of digits (the reason for the limit,
    CVE-2020-10735), so they become ``_OversizedInt`` instead. Within the
    limit the value is exactly ``int(token)``, as in the original v1 reader.
    """
    try:
        return int(token)
    except ValueError:
        return _OversizedInt(token)


class AuditLog:
    """Append-only JSONL audit log with SHA-256 hash chaining.

    Attributes:
        path: Filesystem path to the JSONL audit file.
    """

    def __init__(self, path: str | Path) -> None:
        """Open (or create) an audit log at *path*.

        Args:
            path: Filesystem path for the JSONL audit log.
        """
        self.path = Path(path)
        # Touch the file (parents created) so subsequent ``record`` calls
        # can always open in append mode.
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.touch(exist_ok=True)

    # ------------------------------------------------------------------ #
    # Append                                                             #
    # ------------------------------------------------------------------ #

    def _last_entry_hash(self) -> str:
        """Return the ``entry_hash`` of the last line, or genesis."""
        prev = GENESIS_PREV_HASH
        with self.path.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                payload = json.loads(line, parse_int=_parse_int)
                prev = payload["entry_hash"]
        return prev

    def _reject_v2_tail(self) -> None:
        """Refuse to append v1 records to a chain that contains v2 records.

        SPEC §14.7: a v1 line after a v2 line is a version downgrade, so
        the v1 writer never produces one.
        """
        with self.path.open("r", encoding="utf-8") as fh:
            for line in fh:
                if not line.strip():
                    continue
                # Strip like the original v1 reader: a v1 chain it accepts
                # (e.g. a line ending in \x0c) must not crash here.
                payload = json.loads(line.strip(), parse_int=_parse_int)
                if isinstance(payload, dict) and "v" in payload:
                    raise AuditIntegrityError(
                        "chain contains v2 records; use AuditLogV2"
                    )

    def record(
        self,
        decision: Decision,
        engagement_id: str = "",
    ) -> AuditEntry:
        """Append a :class:`Decision` to the audit chain.

        Computes ``entry_hash`` from the previous line's hash plus the
        current record's canonical JSON, then writes a single JSONL
        line in append mode (never overwriting existing data).

        Args:
            decision: The :class:`~roe_guard.models.Decision` to record.
            engagement_id: Optional engagement identifier for cross-
                reference with the originating policy.

        Returns:
            The :class:`~roe_guard.models.AuditEntry` that was written.

        Raises:
            AuditIntegrityError: The chain already contains v2 records.
            AuditWriterLockedError: An ``AuditLogV2`` writer holds the file.
        """
        with self.path.open("a", encoding="utf-8") as fh:
            _lock_for_append(fh)
            self._reject_v2_tail()
            return self._append(fh, decision, engagement_id)

    def _append(self, fh: TextIO, decision: Decision, engagement_id: str) -> AuditEntry:
        prev_hash = self._last_entry_hash()
        # First compute the hash with an empty entry_hash slot, then
        # build the entry with that hash filled in.  The shell MUST
        # carry the same engagement_id as the final entry, otherwise
        # the recomputed hash diverges from the stored one.
        shell = _decision_to_entry(decision, prev_hash, "", engagement_id=engagement_id)
        entry_hash = _hash_entry(shell)
        entry = _decision_to_entry(decision, prev_hash, entry_hash, engagement_id)
        # Sanity: the hash we computed for the shell must equal entry_hash.
        # (It will, because _canonical_payload is deterministic and both
        # objects have identical field values except entry_hash which is
        # hashed as "" anyway.)
        fh.write(
            json.dumps(
                _canonical_payload(entry),
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
            )
            + "\n"
        )
        return entry

    # ------------------------------------------------------------------ #
    # Verify                                                             #
    # ------------------------------------------------------------------ #

    def verify(self) -> AuditVerificationResult:
        """Verify the integrity of the entire hash chain.

        Reads every line, recomputes each entry's hash from its
        self-describing payload, and confirms that ``prev_hash`` links
        are consistent with the prior line's ``entry_hash``. Mixed
        v1→v2 chains are verified by :func:`roe_guard.audit_v2.verify_chain`
        (checkpoints are not checked here).

        Returns:
            :class:`~roe_guard.models.AuditVerificationResult` with:
                - ``valid``            — ``True`` iff the chain is intact.
                - ``total_entries``    — number of lines inspected.
                - ``broken_at_index``  — index of first broken entry, or ``None``.
                - ``reason``           — explanation, or ``None``.
        """
        # The single verifier lives in audit_v2 and handles mixed v1→v2
        # chains; v1 lines keep the rules and texts of this method.
        from roe_guard.audit_v2 import verify_chain

        return verify_chain(self.path)


__all__ = ["GENESIS_PREV_HASH", "AuditLog"]
