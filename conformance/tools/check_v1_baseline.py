#!/usr/bin/env python3
"""Verify the v1 golden cases against a roe-guard checkout using the v1 API only.

Usage:
    python conformance/tools/check_v1_baseline.py [--roe-guard-path DIR]

``--roe-guard-path`` is inserted at ``sys.path[0]`` so the checks can run
against a pristine baseline checkout (see the T23 card, step 11).

The tool writes each case policy to a temporary ``.yaml`` file (JSON is a
valid YAML subset), loads it with the v1 entry points only, and compares
verdict and free-text reason. A parse failure expects POLICY_INVALID.
"""

import argparse
import json
import sys
import tempfile
from pathlib import Path

CASES = Path(__file__).resolve().parent.parent / "cases" / "v1-golden.json"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--roe-guard-path", help="checkout whose roe_guard/ to test")
    args = parser.parse_args()

    if args.roe_guard_path:
        sys.path.insert(0, str(Path(args.roe_guard_path).resolve()))

    # Late import so --roe-guard-path takes effect.
    from roe_guard import __file__ as roe_guard_file
    from roe_guard.engine import enforce
    from roe_guard.exceptions import PolicyParseError
    from roe_guard.models import Engagement
    from roe_guard.policy import load_policy

    with open(CASES, encoding="utf-8") as fh:
        document = json.load(fh)

    failures = []
    count = 0
    for case in document["cases"]:
        count += 1
        expected = case["expected"]
        with tempfile.NamedTemporaryFile(
            "w", suffix=".yaml", delete=False, encoding="utf-8"
        ) as fh:
            json.dump(case["policy"], fh)
            path = fh.name
        try:
            decision = enforce(
                Engagement(policy=load_policy(path)),
                case["input"]["target"],
                case["input"]["action_type"],
                now=_parse_now(case["input"]["now"]),
            )
            verdict, reason = decision.outcome.value, decision.reason
        except PolicyParseError as exc:
            verdict = "DENY"
            # Card: POLICY_INVALID cases carry no free-text reason; the
            # parse error message is not comparable across versions.
            reason = "POLICY_INVALID" if expected.get("reason") is None else str(exc)
        finally:
            Path(path).unlink(missing_ok=True)

        want_reason = expected.get("reason")
        if verdict != expected["verdict"] or (
            want_reason is not None and reason != want_reason
        ):
            failures.append(
                f"  {case['id']}: expected {expected['verdict']}/{expected.get('reason')!r}, got {verdict}/{reason!r}"
            )

    if failures:
        print(f"FAILED {len(failures)}/{count} cases:")
        print("\n".join(failures))
        return 1
    print(f"OK {count} cases (roe_guard from {roe_guard_file})")
    return 0


def _parse_now(value: str):
    from datetime import datetime

    return datetime.fromisoformat(value.replace("Z", "+00:00"))


if __name__ == "__main__":
    sys.exit(main())
