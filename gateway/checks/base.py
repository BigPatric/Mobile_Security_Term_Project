"""
gateway/checks/base.py — the common contract every policy check implements
==========================================================================
A *check* is one step in a tool's policy chain. The PolicyEngine runs the chain
for a tool in the order the config lists it; the first check that returns a
block stops the call before it reaches the core.

    screen(ctx)                -> None (pass) | block dict (stop)
    observe(tool, args, result)   learn state from results flowing back

Checks never filter by tool name themselves: WHICH checks apply to WHICH tool is
decided by the policy config, not hard-coded in the check. That is what makes the
gateway a general mechanism rather than a PDU-release special case.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Dict, Optional

InternalInvoke = Callable[[str, Dict[str, Any]], Dict[str, Any]]


@dataclass
class CallContext:
    tool: str
    args: Dict[str, Any]        # exactly as the agent sent them (opaque tokens)
    real_args: Dict[str, Any]   # detokenized — real identifiers, what the core will see
    # Gateway-internal, trusted call to the core (bypasses the chain; its result is
    # still fed to every check's observe()). None when no core is reachable.
    internal_invoke: Optional[InternalInvoke] = None


def is_authorized(args: Dict[str, Any]) -> bool:
    """An operator-authorization claim on the call. NOTE: this is a *claim* in the
    arguments, not a verified capability — DOS-02 forges exactly this. Only the L3
    `exempt_authorized` opt-in uses it (off in the shipped policy); L2 verifies the
    signed capability instead (gateway/capability.py)."""
    return bool(args.get("operator_authorization") or args.get("authorized"))


def get_path(obj: Any, path: str) -> Any:
    """Dotted lookup into nested dicts: get_path(r, "subscriber.supi")."""
    cur = obj
    for part in path.split("."):
        if not isinstance(cur, dict):
            return None
        cur = cur.get(part)
    return cur


def matches(result: Any, cond: Optional[Dict[str, Any]]) -> bool:
    """True iff every key in `cond` equals the same key in the result."""
    if not cond:
        return True
    if not isinstance(result, dict):
        return False
    return all(result.get(k) == v for k, v in cond.items())


class Check:
    kind: str = "check"
    layer: str = "L?"

    def screen(self, ctx: CallContext) -> Optional[Dict[str, Any]]:
        return None

    def observe(self, tool: str, args: Dict[str, Any], result: Dict[str, Any]) -> None:
        return None

    def describe(self) -> str:
        return self.kind

    def block(self, ctx: CallContext, reason: str, violation: str, **extra: Any) -> Dict[str, Any]:
        out = {"status": "blocked", "layer": self.layer, "check": self.kind,
               "tool": ctx.tool, "reason": reason, "violation": violation}
        out.update(extra)
        return out
