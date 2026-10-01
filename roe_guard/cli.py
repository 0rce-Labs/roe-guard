"""
roe_guard.cli

Command-line interface for roe-guard.

Subcommands (spec §6):
    validate       Validate a policy YAML file.
    check          Evaluate a single (target, action) against a policy.
    audit-verify   Verify the integrity of an audit hash-chain.

Exit codes (per spec §6 + the task ticket):
    validate       0 = valid,    1 = invalid
    check          0 = ALLOW,    1 = DENY,    2 = REQUIRES_APPROVAL
    audit-verify   0 = valid,    1 = broken

The CLI is a thin "wire" — every subcommand delegates to functions
already implemented in T2-T6.  No business logic lives here.

Implemented in T7.
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path

from roe_guard import __version__
from roe_guard.audit import AuditLog
from roe_guard.engine import enforce
from roe_guard.exceptions import PolicyParseError
from roe_guard.models import DecisionType, Engagement
from roe_guard.policy import load_policy

# Exit codes for `check` — keep in sync with decision outcomes.
_EXIT_BY_OUTCOME: dict[DecisionType, int] = {
    DecisionType.ALLOW: 0,
    DecisionType.DENY: 1,
    DecisionType.REQUIRES_APPROVAL: 2,
}


# ---------------------------------------------------------------------------
# Subcommand implementations
# ---------------------------------------------------------------------------


def _cmd_validate(args: argparse.Namespace) -> int:
    """`roe-guard validate <policy.yaml>`."""
    path = Path(args.policy)
    try:
        policy = load_policy(path)
    except PolicyParseError as exc:
        print(f"✗ Invalid policy at {path}: {exc}", file=sys.stderr)
        return 1
    print(
        f"✓ Valid policy: {policy.engagement_id} "
        f"({policy.valid_from.isoformat()} → {policy.valid_until.isoformat()})"
    )
    return 0


def _cmd_check(args: argparse.Namespace) -> int:
    """`roe-guard check --target ... --action ... --policy ... [--now ...]`."""
    try:
        policy = load_policy(Path(args.policy))
    except PolicyParseError as exc:
        print(f"✗ Invalid policy: {exc}", file=sys.stderr)
        return 1

    now: datetime | None = None
    if args.now is not None:
        try:
            normalised = (
                args.now.replace("Z", "+00:00") if args.now.endswith("Z") else args.now
            )
            now = datetime.fromisoformat(normalised)
            if now.tzinfo is None:
                now = now.replace(tzinfo=timezone.utc)
        except ValueError:
            print(f"✗ Invalid --now timestamp: {args.now!r}", file=sys.stderr)
            return 1

    engagement = Engagement(policy=policy)
    decision = enforce(engagement, args.target, args.action_type, now=now)
    print(f"target:     {decision.target}")
    print(f"action:     {decision.action_type}")
    print(f"outcome:    {decision.outcome.value}")
    print(f"reason:     {decision.reason}")
    print(f"timestamp:  {decision.timestamp.isoformat()}")
    return _EXIT_BY_OUTCOME[decision.outcome]


def _cmd_audit_verify(args: argparse.Namespace) -> int:
    """`roe-guard audit-verify <audit.jsonl>`."""
    path = Path(args.audit_log)
    if not path.exists():
        print(f"✗ Audit log not found: {path}", file=sys.stderr)
        return 1
    log = AuditLog(path)
    result = log.verify()
    if result.valid:
        print(f"✓ Audit chain valid ({result.total_entries} entries)")
        return 0
    print(
        f"✗ Chain broken at entry {result.broken_at_index}: {result.reason}",
        file=sys.stderr,
    )
    return 1


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------


def _build_parser() -> argparse.ArgumentParser:
    """Construct the top-level argument parser."""
    parser = argparse.ArgumentParser(
        prog="roe-guard",
        description=(
            "roe-guard — Rules of Engagement policy enforcement.\n\n"
            "Define what targets, time-windows, and action types are allowed; "
            "every out-of-scope action is denied and logged."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "-V",
        "--version",
        action="version",
        version=f"roe-guard {__version__}",
    )

    subparsers = parser.add_subparsers(
        dest="command",
        metavar="<command>",
        required=False,
    )

    # validate
    p_validate = subparsers.add_parser(
        "validate",
        help="Validate a policy YAML file.",
        description="Load and validate a policy YAML, exit 0 if valid.",
    )
    p_validate.add_argument(
        "policy",
        help="Path to the policy YAML file.",
    )
    p_validate.set_defaults(func=_cmd_validate)

    # check
    p_check = subparsers.add_parser(
        "check",
        help="Evaluate a single target/action against a policy.",
        description=(
            "Evaluate a (target, action_type) pair against a policy file. "
            "Exit code: 0=ALLOW, 1=DENY, 2=REQUIRES_APPROVAL."
        ),
    )
    p_check.add_argument(
        "--target",
        required=True,
        help="Target identifier (IP, hostname, or glob).",
    )
    p_check.add_argument(
        "--action",
        required=True,
        dest="action_type",
        help="Action type (e.g. recon, exploit, persistence-test).",
    )
    p_check.add_argument(
        "--policy",
        required=True,
        help="Path to the policy YAML file.",
    )
    p_check.add_argument(
        "--now",
        default=None,
        help=(
            "Override evaluation time (ISO-8601). "
            "Useful for testing and demos. Default: now (UTC)."
        ),
    )
    p_check.set_defaults(func=_cmd_check)

    # audit-verify
    p_audit = subparsers.add_parser(
        "audit-verify",
        help="Verify the integrity of an audit hash-chain.",
        description=(
            "Verify the SHA-256 hash chain in an audit log. "
            "Exit 0 if intact, 1 if tampered."
        ),
    )
    p_audit.add_argument(
        "audit_log",
        help="Path to the JSONL audit log.",
    )
    p_audit.set_defaults(func=_cmd_audit_verify)

    return parser


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    """CLI entry point.

    Args:
        argv: Optional argument list (defaults to ``sys.argv[1:]``).

    Returns:
        Process exit code (subcommand-specific).
    """
    parser = _build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "command", None):
        parser.print_help()
        return 0
    func: Callable[[argparse.Namespace], int] = args.func
    return func(args)


if __name__ == "__main__":
    sys.exit(main())
