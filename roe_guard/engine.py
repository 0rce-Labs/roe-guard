"""
roe_guard.engine

Decision engine — evaluates (target, action_type) against an engagement
policy using the **fail-closed priority order** defined in spec §5.

This is the security-critical core of roe-guard.  The 8-step priority
order is intentional and MUST NOT be reordered (e.g. ``scope.deny``
overrides ``scope.allow`` — a target in both lists is denied).

Implemented in T4.
"""

from __future__ import annotations

import fnmatch
import ipaddress
from datetime import datetime, timezone
from typing import Any

from roe_guard.exceptions import PolicyExpiredError
from roe_guard.models import (
    AgentIdentity,
    Decision,
    DecisionType,
    Engagement,
    HttpAllowRule,
    HttpDenyRule,
    Policy,
    ReasonCode,
    ScopeEntry,
)
from roe_guard.policy import _LABEL_RE, _NUMERIC_LABEL_RE

# ---------------------------------------------------------------------------
# Target matching
# ---------------------------------------------------------------------------


def _target_matches(target: str, entry: ScopeEntry) -> bool:
    """Return True if *target* matches a single :class:`ScopeEntry`.

    Matching rules:
        - If the entry has a CIDR and the target is a valid IP address,
          membership is tested via :class:`ipaddress.ip_network`.
        - If the entry has a hostname, wildcard matching is done via
          :func:`fnmatch.fnmatch` (case-insensitive).
        - If the entry has neither, returns False.

    The target format is auto-detected: ``ipaddress.ip_address(target)``
    is attempted first; ``ValueError`` falls back to hostname matching.
    """
    if entry.cidr is not None:
        try:
            ip = ipaddress.ip_address(target)
        except ValueError:
            return False
        try:
            network = ipaddress.ip_network(entry.cidr, strict=False)
        except ValueError:
            # Invalid CIDR (should have been caught at load time).
            return False
        return ip in network

    if entry.hostname is not None:
        # fnmatch is case-insensitive via fnmatchcase + lowered strings.
        return fnmatch.fnmatchcase(target.lower(), entry.hostname.lower())

    return False


def _matches_any(target: str, entries: list[ScopeEntry]) -> bool:
    """Return True if *target* matches **any** entry in the list."""
    return any(_target_matches(target, e) for e in entries)


def _first_match(target: str, entries: list[ScopeEntry]) -> int | None:
    """Return the index of the first entry matching *target*, else None."""
    for idx, entry in enumerate(entries):
        if _target_matches(target, entry):
            return idx
    return None


def _decide(
    policy: Policy,
    target: str,
    action_type: str,
    now: datetime,
    outcome: DecisionType,
    reason: str,
    code: ReasonCode,
    rule: str,
    agent: AgentIdentity | None = None,
) -> Decision:
    """Single Decision constructor: fills mode, reason_code and matched_rule.

    The v1 ``reason`` texts pass through byte-for-byte unchanged.
    """
    return Decision(
        outcome=outcome,
        reason=reason,
        target=target,
        action_type=action_type,
        timestamp=now,
        mode=policy.mode,
        reason_code=code.value,
        matched_rule=rule,
        agent_id=agent.id if agent is not None and isinstance(agent.id, str) else "",
    )


def _check_agent(
    policy: Policy, agent: AgentIdentity | None
) -> tuple[ReasonCode, str, str] | None:
    """Ladder step 0; runs only when the policy has an agent block.

    Returns ``(code, reason, matched_rule)`` on failure and ``None`` on
    pass. Matching is ``fnmatch.fnmatchcase`` — case-sensitive, ``*`` also
    covers ``/``.
    """
    spec = policy.agent
    if spec is None:  # no agent block: step 0 does not apply
        return None
    if agent is None or not isinstance(agent.id, str) or agent.id == "":
        return (ReasonCode.AGENT_ID_MISSING, "agent identity missing", "agent.id")
    if not fnmatch.fnmatchcase(agent.id, spec.id):
        return (
            ReasonCode.AGENT_ID_MISMATCH,
            "agent identity does not match policy",
            "agent.id",
        )
    if spec.runtime and (agent.runtime is None or agent.runtime not in spec.runtime):
        return (
            ReasonCode.AGENT_RUNTIME_NOT_ALLOWED,
            "agent runtime not allowed",
            "agent.runtime",
        )
    return None


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def enforce(
    engagement: Engagement,
    target: str,
    action_type: str,
    now: datetime | None = None,
    metadata: dict[str, Any] | None = None,
    *,
    agent: AgentIdentity | None = None,
) -> Decision:
    """Evaluate *one* action against the engagement policy (spec §5).

    The priority order is intentional and MUST NOT be reordered. Step 0
    runs only when the policy has an ``agent`` block; steps 1-8 are the v1
    ladder, unchanged:

        0. agent missing / id not matching / runtime not allowed → DENY
           (AGENT_ID_MISSING, AGENT_ID_MISMATCH, AGENT_RUNTIME_NOT_ALLOWED)
        1. now < valid_from  OR  now >= valid_until  → DENY (expired)
        2. now in any blackout_window                   → DENY
        3. target in scope.deny                         → DENY (deny > allow)
        4. target NOT in scope.allow                    → DENY
        5. action_type in actions.deny                  → DENY
        6. action_type in approval_required_for         → REQUIRES_APPROVAL
        7. action_type in actions.allow                 → ALLOW
        8. none of the above                            → DENY (fail-closed)

    Args:
        engagement:  The active :class:`~roe_guard.models.Engagement`.
        target:      Target identifier (IP, hostname, or glob).
        action_type: The action type to evaluate.
        now:         Override the evaluation time (UTC). Defaults to
            ``datetime.now(timezone.utc)``. Used for testability.
        metadata:    Optional extra context for audit logging (T5).
        agent:       Keyword-only caller identity. When the policy has an
            ``agent`` block, a call without an identity (CLI ``check``,
            ``guarded`` without ``agent=``) is always DENY with
            ``AGENT_ID_MISSING`` (fail-closed). When the policy has no
            ``agent`` block, step 0 is skipped and the identity is only
            recorded in ``Decision.agent_id`` (``""`` when absent).

    Returns:
        A :class:`~roe_guard.models.Decision` with the resolved outcome,
        a human-readable reason, and ``timestamp == now``.

    Raises:
        roe_guard.exceptions.PolicyExpiredError: If the policy is expired
            AND the caller wants the explicit exception form (kept for
            backward compatibility — T7 CLI may use it).  The primary
            decision path returns ``Decision(outcome=DENY, ...)`` instead.
    """
    policy = engagement.policy
    if now is None:
        now = datetime.now(timezone.utc)

    # --- (0) Agent identity (only when the policy has an agent block) ----
    if policy.agent is not None:
        failure = _check_agent(policy, agent)
        if failure is not None:
            code, reason, rule = failure
            return _decide(
                policy,
                target,
                action_type,
                now,
                DecisionType.DENY,
                reason,
                code,
                rule,
                agent,
            )

    # --- (a) Time-window check -------------------------------------------
    if not (policy.valid_from <= now < policy.valid_until):
        return _decide(
            policy,
            target,
            action_type,
            now,
            DecisionType.DENY,
            "policy expired or not yet active",
            ReasonCode.POLICY_NOT_ACTIVE,
            "valid_from/valid_until",
            agent,
        )

    # --- (b) Blackout-window check --------------------------------------
    for bw_index, bw in enumerate(policy.blackout_windows):
        if bw.start <= now < bw.end:
            reason = "inside blackout window"
            if bw.reason:
                reason = f"{reason}: {bw.reason}"
            return _decide(
                policy,
                target,
                action_type,
                now,
                DecisionType.DENY,
                reason,
                ReasonCode.BLACKOUT_WINDOW,
                f"blackout_windows[{bw_index}]",
                agent,
            )

    # --- (c) Explicit deny overrides allow ------------------------------
    deny_index = _first_match(target, policy.scope.deny)
    if deny_index is not None:
        return _decide(
            policy,
            target,
            action_type,
            now,
            DecisionType.DENY,
            "target explicitly denied in scope",
            ReasonCode.TARGET_DENIED,
            f"scope.deny[{deny_index}]",
            agent,
        )

    # --- (d) Target must be in scope.allow ------------------------------
    if not _matches_any(target, policy.scope.allow):
        return _decide(
            policy,
            target,
            action_type,
            now,
            DecisionType.DENY,
            "target not in allowed scope",
            ReasonCode.TARGET_NOT_IN_SCOPE,
            "scope.allow",
            agent,
        )

    # --- (e) actions.deny check -----------------------------------------
    if action_type in policy.actions_deny:
        return _decide(
            policy,
            target,
            action_type,
            now,
            DecisionType.DENY,
            f"action type {action_type!r} explicitly denied",
            ReasonCode.ACTION_DENIED,
            "actions.deny",
            agent,
        )

    # --- (f) approval_required_for check (NOT ALLOW) --------------------
    if action_type in policy.approval_required_for:
        return _decide(
            policy,
            target,
            action_type,
            now,
            DecisionType.REQUIRES_APPROVAL,
            f"action type {action_type!r} requires human approval",
            ReasonCode.APPROVAL_REQUIRED,
            "approval_required_for",
            agent,
        )

    # --- (g) actions.allow check ----------------------------------------
    if action_type in policy.actions_allow:
        return _decide(
            policy,
            target,
            action_type,
            now,
            DecisionType.ALLOW,
            f"action type {action_type!r} allowed",
            ReasonCode.ACTION_ALLOWED,
            "actions.allow",
            agent,
        )

    # --- (h) Fail-closed default ----------------------------------------
    return _decide(
        policy,
        target,
        action_type,
        now,
        DecisionType.DENY,
        "action type not explicitly allowed",
        ReasonCode.ACTION_NOT_ALLOWED,
        "",
        agent,
    )


_IMDS_IPV4 = (
    "169.254.0.0/16",
    "168.63.129.16/32",
    "100.100.100.200/32",
)
_IMDS_V6 = ("fe80::/10", "fd00:ec2::254/128")
_IMDS_NAMES = {"metadata.google.internal"}


def _egress_target_invalid(
    policy: Policy, target: str, action_type: str, now: datetime
) -> Decision:
    return _decide(
        policy,
        target,
        action_type,
        now,
        DecisionType.DENY,
        "egress target invalid",
        ReasonCode.EGRESS_TARGET_INVALID,
        "",
    )


def _normalize_name(host: str) -> str:
    lowered = host.lower()
    lowered = lowered.removesuffix(".")
    return lowered


def _validate_egress_target(
    policy: Policy,
    host: str,
    port: int,
    method: str | None,
    target: str,
    action_type: str,
    now: datetime,
) -> tuple[str, bool, int, str | None, str | None] | Decision:
    """E3: validate host/port/method.

    Returns ``(normalized_host, is_ip, port, method, ip_literal)`` on
    success or a DENY ``Decision`` (``EGRESS_TARGET_INVALID``).
    """
    if not isinstance(host, str) or not host:
        return _egress_target_invalid(policy, target, action_type, now)
    ip_literal = None
    is_ip = False
    try:
        ip_literal = ipaddress.ip_address(host)
        is_ip = True
    except ValueError:
        if host != host.strip() or " " in host or "\n" in host or "\r" in host:
            return _egress_target_invalid(policy, target, action_type, now)
        if "[" in host or "]" in host:
            return _egress_target_invalid(policy, target, action_type, now)
        norm = _normalize_name(host)
        if not (1 <= len(norm) <= 253):
            return _egress_target_invalid(policy, target, action_type, now)
        labels = norm.split(".")
        if len(labels) < 2:
            return _egress_target_invalid(policy, target, action_type, now)
        for label in labels:
            if not _LABEL_RE.fullmatch(label):
                return _egress_target_invalid(policy, target, action_type, now)
        if _NUMERIC_LABEL_RE.fullmatch(labels[-1]):
            return _egress_target_invalid(policy, target, action_type, now)
    if isinstance(port, bool) or not isinstance(port, int) or not (1 <= port <= 65535):
        return _egress_target_invalid(policy, target, action_type, now)
    if method is not None and (not isinstance(method, str) or not method):
        return _egress_target_invalid(policy, target, action_type, now)
    return (
        _normalize_name(host) if not is_ip else host,
        is_ip,
        port,
        method,
        str(ip_literal) if ip_literal is not None else None,
    )


def _is_imds_target(host: str, is_ip: bool, ip_literal: str | None) -> bool:
    if is_ip and ip_literal is not None:
        addr = ipaddress.ip_address(ip_literal)
        if addr.version == 4:
            return any(addr in ipaddress.ip_network(net) for net in _IMDS_IPV4)
        # IPv4-mapped IPv6 addresses fall back to their embedded IPv4 address.
        if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
            v4 = addr.ipv4_mapped
            return any(v4 in ipaddress.ip_network(net) for net in _IMDS_IPV4)
        return any(addr in ipaddress.ip_network(net) for net in _IMDS_V6)
    return _normalize_name(host) in _IMDS_NAMES


def _rule_matches_host(
    rule: HttpAllowRule | HttpDenyRule,
    norm_host: str,
    is_ip: bool,
    ip_literal: str | None,
) -> bool:
    if rule.cidr is not None:
        return (
            is_ip
            and ip_literal is not None
            and ipaddress.ip_address(ip_literal)
            in ipaddress.ip_network(rule.cidr, strict=False)
        )
    return (not is_ip) and fnmatch.fnmatchcase(norm_host, (rule.host or "").lower())


def enforce_egress(
    engagement: Engagement,
    host: str,
    port: int,
    method: str | None = None,
    *,
    now: datetime | None = None,
    agent: AgentIdentity | None = None,
) -> Decision:
    """Evaluate one egress attempt against the policy (SPEC §14.5).

    ``scope`` and ``actions`` never apply to egress. The order is fixed
    and first match wins; the IMDS/link-local deny (E4) runs before any
    allow rule and cannot be overridden by policy.
    """
    policy = engagement.policy
    if now is None:
        now = datetime.now(timezone.utc)
    action_type = f"egress:{method}" if method is not None else "egress"
    try:
        _ip_check = ipaddress.ip_address(host)
        wire_target = f"[{host}]:{port}" if _ip_check.version == 6 else f"{host}:{port}"
    except ValueError:
        wire_target = f"{host}:{port}"

    # --- (E0) Agent identity — _check_agent returns None when the policy
    # has no agent block, so it is safe to call directly.
    if policy.agent is not None:
        failure = _check_agent(policy, agent)
        if failure is not None:
            fail_code, fail_reason, fail_rule = failure
            return _decide(
                policy,
                wire_target,
                action_type,
                now,
                DecisionType.DENY,
                fail_reason,
                fail_code,
                fail_rule,
                agent,
            )

    # --- (E1) Time window -------------------------------------------------
    if not (policy.valid_from <= now < policy.valid_until):
        return _decide(
            policy,
            wire_target,
            action_type,
            now,
            DecisionType.DENY,
            "policy expired or not yet active",
            ReasonCode.POLICY_NOT_ACTIVE,
            "valid_from/valid_until",
            agent,
        )

    # --- (E2) Blackout -----------------------------------------------------
    for bw_index, bw in enumerate(policy.blackout_windows):
        if bw.start <= now < bw.end:
            reason = "inside blackout window"
            if bw.reason:
                reason = f"{reason}: {bw.reason}"
            return _decide(
                policy,
                wire_target,
                action_type,
                now,
                DecisionType.DENY,
                reason,
                ReasonCode.BLACKOUT_WINDOW,
                f"blackout_windows[{bw_index}]",
                agent,
            )

    # --- (E3) Validation ---------------------------------------------------
    checked = _validate_egress_target(
        policy, host, port, method, wire_target, action_type, now
    )
    if isinstance(checked, Decision):
        return _decide(
            policy,
            wire_target,
            action_type,
            now,
            DecisionType.DENY,
            "egress target invalid",
            ReasonCode.EGRESS_TARGET_INVALID,
            "",
            agent,
        )
    norm_host, is_ip, port_checked, method_checked, ip_literal = checked

    # --- (E4) IMDS / link-local hard-stop ----------------------------------
    if _is_imds_target(norm_host, is_ip, ip_literal):
        return _decide(
            policy,
            wire_target,
            action_type,
            now,
            DecisionType.DENY,
            "egress to instance metadata or link-local address denied",
            ReasonCode.EGRESS_IMDS_DENIED,
            "",
            agent,
        )

    # --- (E5) egress block configured? --------------------------------------
    egress = policy.egress
    if egress is None:
        return _decide(
            policy,
            wire_target,
            action_type,
            now,
            DecisionType.DENY,
            "egress not configured in policy",
            ReasonCode.EGRESS_NOT_CONFIGURED,
            "egress",
            agent,
        )

    http = egress.http
    allow_rules: tuple[HttpAllowRule, ...] = http.allow if http is not None else ()
    deny_rules: tuple[HttpDenyRule, ...] = http.deny if http is not None else ()

    # --- (E6) explicit deny ---------------------------------------------------
    for idx, rule in enumerate(deny_rules):
        if _rule_matches_host(rule, norm_host, is_ip, ip_literal):
            return _decide(
                policy,
                wire_target,
                action_type,
                now,
                DecisionType.DENY,
                "egress host explicitly denied",
                ReasonCode.EGRESS_HOST_DENIED,
                f"egress.http.deny[{idx}]",
                agent,
            )

    # --- (E7) host not allowed -------------------------------------------------
    host_matches: list[tuple[int, HttpAllowRule]] = [
        (idx, rule)
        for idx, rule in enumerate(allow_rules)
        if _rule_matches_host(rule, norm_host, is_ip, ip_literal)
    ]
    if not host_matches:
        return _decide(
            policy,
            wire_target,
            action_type,
            now,
            DecisionType.DENY,
            "egress host not allowed",
            ReasonCode.EGRESS_HOST_NOT_ALLOWED,
            "egress.http.allow",
            agent,
        )

    # --- (E8) port not allowed on any host-matching entry -----------------------
    port_matches: list[tuple[int, HttpAllowRule]] = [
        (idx, rule) for idx, rule in host_matches if port_checked in rule.ports
    ]
    if not port_matches:
        first_idx, _first_rule = host_matches[0]
        return _decide(
            policy,
            wire_target,
            action_type,
            now,
            DecisionType.DENY,
            "egress port not allowed",
            ReasonCode.EGRESS_PORT_NOT_ALLOWED,
            f"egress.http.allow[{first_idx}]",
            agent,
        )

    # --- (E9) method not allowed when every host+port match restricts methods ----
    with_methods: list[tuple[int, HttpAllowRule]] = [
        (idx, rule) for idx, rule in port_matches if rule.methods
    ]
    if with_methods:
        allowed_somewhere = any(
            method_checked is not None and method_checked in rule.methods
            for _idx, rule in with_methods
        )
        if method_checked is None or not allowed_somewhere:
            first_idx, _rule = with_methods[0]
            return _decide(
                policy,
                wire_target,
                action_type,
                now,
                DecisionType.DENY,
                "egress method not allowed",
                ReasonCode.EGRESS_METHOD_NOT_ALLOWED,
                f"egress.http.allow[{first_idx}]",
                agent,
            )

    # --- (E10) allowed -----------------------------------------------------------
    for allow_idx, allow_rule in port_matches:
        if not allow_rule.methods or (
            method_checked is not None and method_checked in allow_rule.methods
        ):
            return _decide(
                policy,
                wire_target,
                action_type,
                now,
                DecisionType.ALLOW,
                "egress allowed",
                ReasonCode.EGRESS_ALLOWED,
                f"egress.http.allow[{allow_idx}]",
                agent,
            )
    # Unreachable: E9 already handled the all-restricted case.
    return _decide(
        policy,
        host,
        action_type,
        now,
        DecisionType.DENY,
        "egress method not allowed",
        ReasonCode.EGRESS_METHOD_NOT_ALLOWED,
        "egress.http.allow",
        agent,
    )


def raise_if_expired(engagement: Engagement, now: datetime | None = None) -> None:
    """Raise :class:`PolicyExpiredError` if the engagement is outside its window.

    Convenience helper — most callers should use :func:`enforce` which
    returns a DENY ``Decision`` instead of raising.
    """
    if now is None:
        now = datetime.now(timezone.utc)
    if not (engagement.policy.valid_from <= now < engagement.policy.valid_until):
        raise PolicyExpiredError(engagement_id=engagement.policy.engagement_id)


__all__ = ["enforce", "enforce_egress", "raise_if_expired"]
