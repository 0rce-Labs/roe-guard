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

import hashlib
import json
from datetime import datetime
from pathlib import Path
from typing import Any

from roe_guard.exceptions import AuditIntegrityError
from roe_guard.models import (
    AuditEntry,
    AuditVerificationResult,
    Decision,
    DecisionType,
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
                payload = json.loads(line)
                prev = payload["entry_hash"]
        return prev

    def _reject_v2_tail(self) -> None:
        """Refuse to append v1 records to a chain that contains v2 records."""
        from roe_guard.audit_v2 import verify_chain

        result = verify_chain(self.path)
        if result.valid and result.total_entries:
            with self.path.open("r", encoding="utf-8") as fh:
                lines = [line for line in fh if line.strip()]
            if lines and json.loads(lines[-1]).get("v") == 2:
                raise AuditIntegrityError("chain contains v2 records; use AuditLogV2")

    def record(
        self,
        decision: Decision,
        engagement_id: str = "",
    ) -> AuditEntry:
        self._reject_v2_tail()

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
        """
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
        with self.path.open("a", encoding="utf-8") as fh:
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
        are consistent with the prior line's ``entry_hash``.

        Returns:
            :class:`~roe_guard.models.AuditVerificationResult` with:
                - ``valid``            — ``True`` iff the chain is intact.
                - ``total_entries``    — number of lines inspected.
                - ``broken_at_index``  — index of first broken entry, or ``None``.
                - ``reason``           — explanation, or ``None``.
        """
        # The single verifier lives in audit_v2 and handles mixed v1→v2
        # chains (card: AuditLog.verify() is a thin wrapper).
        from roe_guard.audit_v2 import verify_chain

        return verify_chain(self.path)

        expected_prev = GENESIS_PREV_HASH
        total = 0

        with self.path.open("r", encoding="utf-8") as fh:
            for index, raw_line in enumerate(fh):
                stripped = raw_line.strip()
                if not stripped:
                    continue
                try:
                    payload = json.loads(stripped)
                except json.JSONDecodeError as exc:
                    return AuditVerificationResult(
                        valid=False,
                        total_entries=total,
                        broken_at_index=index,
                        reason=f"line {index}: invalid JSON: {exc}",
                    )

                # Reconstruct AuditEntry from the line. Strip the hashes
                # so we can recompute one of them deterministically.
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
                    return AuditVerificationResult(
                        valid=False,
                        total_entries=total,
                        broken_at_index=index,
                        reason=f"line {index}: malformed entry: {exc}",
                    )

                # 1) prev_hash must equal previous line's entry_hash.
                if entry.prev_hash != expected_prev:
                    return AuditVerificationResult(
                        valid=False,
                        total_entries=total + 1,
                        broken_at_index=index,
                        reason=(
                            f"line {index}: prev_hash mismatch "
                            f"(expected {expected_prev[:12]}…, "
                            f"got {entry.prev_hash[:12]}…)"
                        ),
                    )

                # 2) entry_hash must match what we compute from payload.
                computed = _hash_entry(entry)
                if computed != entry.entry_hash:
                    return AuditVerificationResult(
                        valid=False,
                        total_entries=total + 1,
                        broken_at_index=index,
                        reason=(
                            f"line {index}: entry_hash mismatch "
                            f"(expected {computed[:12]}…, "
                            f"got {entry.entry_hash[:12]}…)"
                        ),
                    )

                expected_prev = entry.entry_hash
                total += 1

        return AuditVerificationResult(
            valid=True,
            total_entries=total,
            broken_at_index=None,
            reason=None,
        )


__all__ = ["GENESIS_PREV_HASH", "AuditLog"]
