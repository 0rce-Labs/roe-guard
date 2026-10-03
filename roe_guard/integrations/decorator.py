"""
roe_guard.integrations.decorator

``@guarded`` decorator — transparently protect an existing function with
a policy check (spec §6).

Usage::

    @guarded(engagement, action_type="exploit", target_arg="host")
    def run_exploit(host: str):
        ...

Behaviour:
    - The decorator resolves the *target* from the wrapped function's
      call by binding the actual call arguments via
      :func:`inspect.signature` and reading the parameter named
      ``target_arg`` (positional or keyword).
    - :func:`roe_guard.engine.enforce` decides:
        - ALLOW               → wrap and call normally, return result
        - DENY                → raise :class:`OutOfScopeError`
        - REQUIRES_APPROVAL   → raise :class:`ApprovalRequiredError`
    - :func:`functools.wraps` preserves the wrapped function's metadata.

Implemented in T6.  No audit logging is performed inside the decorator
itself (audit binding is a T7 concern).
"""

from __future__ import annotations

import inspect
from collections.abc import Callable
from functools import wraps
from typing import Any

from roe_guard.engine import enforce
from roe_guard.exceptions import ApprovalRequiredError, OutOfScopeError
from roe_guard.models import AgentIdentity, Decision, DecisionType, Engagement


def _resolve_target(
    sig: inspect.Signature,
    args: tuple[Any, ...],
    kwargs: dict[str, Any],
    target_arg: str,
) -> str:
    """Resolve the target string from the wrapped function's call args.

    The target must be a string (IP, hostname, etc.).  If the parameter
    is missing, a clear :class:`TypeError` is raised.
    """
    try:
        bound = sig.bind_partial(*args, **kwargs)
    except TypeError as exc:
        raise TypeError(
            f"@guarded could not bind arguments to determine target: {exc}"
        ) from exc
    if target_arg not in bound.arguments:
        raise TypeError(
            f"@guarded target_arg={target_arg!r} not found in wrapped "
            f"function arguments (have: {sorted(bound.arguments)})"
        )
    target = bound.arguments[target_arg]
    if not isinstance(target, str):
        raise TypeError(
            f"@guarded target must be a string, got {type(target).__name__}"
        )
    return target


def guarded(
    engagement: Engagement,
    action_type: str,
    target_arg: str = "target",
    *,
    agent: AgentIdentity | None = None,
) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """Decorator factory: enforce scope on every call of the wrapped function.

    Args:
        engagement:  The active :class:`~roe_guard.models.Engagement`.
        action_type: The action type this function represents.
        target_arg:  Name of the wrapped function's parameter (positional
            or keyword) that carries the target string.

    Returns:
        A decorator that checks scope before invoking the wrapped function
        and returns its result unchanged on ALLOW.

    Raises (at call time, not at decoration time):
        roe_guard.exceptions.OutOfScopeError:
            If the policy denies the action.
        roe_guard.exceptions.ApprovalRequiredError:
            If the policy says REQUIRES_APPROVAL.
    """

    def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
        sig = inspect.signature(func)

        @wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            target = _resolve_target(sig, args, kwargs, target_arg)
            decision: Decision = enforce(engagement, target, action_type, agent=agent)
            outcome = decision.outcome

            if outcome is DecisionType.DENY:
                raise OutOfScopeError(
                    f"Denied: target={target!r} action={action_type!r} "
                    f"reason={decision.reason}"
                )
            if outcome is DecisionType.REQUIRES_APPROVAL:
                raise ApprovalRequiredError(target=target, action_type=action_type)
            # ALLOW — fall through to the wrapped function.
            return func(*args, **kwargs)

        return wrapper

    return decorator


__all__ = ["guarded"]
