"""
gateway/checks/core_precheck.py — L3 ground-truth precondition check
====================================================================
Before a high-risk call is forwarded, the GATEWAY ITSELF asks the core whether
the precondition actually holds — it does not trust what the agent claims or
what the agent happened to query earlier.

    core_precheck:
      via: query_subscriber_session          # read-only tool the gateway calls
      args: {supi_token: $supi_token}        # $x = value from the call's real args
      expect:
        status: ok
        exists: {in: subscriber.pdu_sessions, where: {id: $pdu_session_id}}

The precheck result is fed to every check's observe() (so the FSM learns the
true state too). The agent never sees it.
"""

from __future__ import annotations

from typing import Any, Dict, Optional

from .base import Check, CallContext, get_path


def _resolve(val: Any, real_args: Dict[str, Any]) -> Any:
    if isinstance(val, str) and val.startswith("$"):
        return real_args.get(val[1:])
    return val


class CorePrecheck(Check):
    kind = "core_precheck"
    layer = "L3"

    def __init__(self, via: str, args: Dict[str, Any], expect: Dict[str, Any]):
        self.via = via
        self.args_map = dict(args or {})
        self.expect = dict(expect or {})

    def describe(self) -> str:
        return f"core_precheck(via {self.via})"

    def screen(self, ctx: CallContext) -> Optional[Dict[str, Any]]:
        if ctx.internal_invoke is None:
            return self.block(ctx, "core precheck unavailable: gateway has no core connection",
                              violation="core-precheck-unavailable")
        q_args = {k: _resolve(v, ctx.real_args) for k, v in self.args_map.items()}
        res = ctx.internal_invoke(self.via, q_args)
        res = res if isinstance(res, dict) else {}

        want_status = self.expect.get("status")
        if want_status is not None and res.get("status") != want_status:
            return self.block(ctx,
                f"core precheck failed: {self.via} returned status={res.get('status')!r} "
                f"({res.get('error') or 'no detail'}); precondition for {ctx.tool} not met",
                violation="core-precheck-failed", precheck_via=self.via)

        exists = self.expect.get("exists")
        if exists:
            items = get_path(res, exists["in"]) or []
            where = {k: _resolve(v, ctx.real_args) for k, v in (exists.get("where") or {}).items()}
            found = any(isinstance(it, dict) and all(str(it.get(k)) == str(v) for k, v in where.items())
                        for it in items)
            if not found:
                return self.block(ctx,
                    f"core precheck failed: the core reports no {exists['in']} entry matching "
                    f"{where}; {ctx.tool} would act on a non-existent context",
                    violation="core-precheck-failed", precheck_via=self.via)
        return None
