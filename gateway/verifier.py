"""
gateway/verifier.py — Layer 3: Procedure-Aware Verifier (TS 23.502 FSM + rate)
==============================================================================
L1 makes identifiers opaque; L2 stops *untrusted-driven* high-risk calls. Neither
knows anything about 3GPP procedure *state*. L3 does: it models the PDU-session
life-cycle (TS 23.502 §4.3) as a small finite-state machine at the tool-call
boundary, and rejects control-plane operations that are illegal *as procedures* —
even when they come from a TRUSTED, operator-authorized source.

This is the layer that closes the gap L2 leaves open:

  * L2 asks "did untrusted content drive this?"  → an *authorized* bulk release
    passes L2 (operator_authorization present).
  * L3 asks "is this a legal procedure right now?" → the same bulk / out-of-order
    release is still blocked. Authorization is NOT a bypass for L3; that is the
    whole point, and it is what the ablation study shows L1/L2 cannot catch.

Two independent checks on the high-risk sink `trigger_pdu_session_release`:

  (a) FSM / ordering — a PDU session that this gateway has already seen released
      cannot be released again (out-of-state: RELEASED --release--> ✗). Optional
      strict mode additionally requires the session to have been observed ACTIVE
      (via query_subscriber_session) before it may be released.

  (b) Rate / volume — no more than `max_releases` releases may be *attempted*
      within a sliding `window_sec`. A hijacked loop tearing down every session
      trips this regardless of provenance or authorization (control-plane DoS).

The gateway feeds the FSM by OBSERVING results it already passes through:
`query_subscriber_session` marks sessions ACTIVE; a confirmed
`trigger_pdu_session_release` marks them RELEASED. No extra core calls.

Aligns with the proposal (slide 6: "state machines for PDU session
establishment/modification/release; block out-of-state sequences and abnormal
call rates").

Implementation note: since the policy pipeline (gateway/policy.py) this class is
a convenience FACADE over the generic checks — FsmCheck on the PDU-session
procedure spec (gateway/procedures.py) followed by a RateCheck. The config-driven
PolicyEngine builds the same checks from config.yaml; this class keeps the
original standalone API (screen_call / observe_result / state / explain).
"""

from __future__ import annotations

import time
from typing import Any, Callable, Dict, Optional

from .checks import CallContext, Check, FsmCheck, ProcedureStore, RateBucket, RateCheck
from .procedures import pdu_session_procedure

_RELEASE_TOOL = "trigger_pdu_session_release"


class ProcedureVerifier(Check):
    kind = "verifier"
    layer = "L3"
    HIGH_RISK_SINKS = {_RELEASE_TOOL}

    def __init__(self,
                 max_releases: int = 3,
                 window_sec: float = 60.0,
                 require_established: bool = False,
                 exempt_authorized: bool = False,
                 now_fn: Callable[[], float] = time.monotonic) -> None:
        """
        max_releases / window_sec : sliding-window rate limit on release attempts.
        require_established        : strict FSM — only release a session already
                                     observed ACTIVE (blocks release of unknown
                                     context). Default off to keep benign
                                     single-release false positives at zero.
        exempt_authorized          : if True, operator_authorization bypasses L3
                                     too. Default False — L3 binds everyone, which
                                     is what distinguishes it from L2.
        """
        self.max_releases = max_releases
        self.window_sec = window_sec
        self.require_established = require_established
        self.exempt_authorized = exempt_authorized
        self.store = ProcedureStore("pdu_session", pdu_session_procedure(require_established))
        self.fsm = FsmCheck(self.store, "release", tool=_RELEASE_TOOL,
                            exempt_authorized=exempt_authorized)
        self.rate = RateCheck(RateBucket("pdu_release", max_releases, window_sec, now_fn),
                              exempt_authorized=exempt_authorized)

    def describe(self) -> str:
        return f"verifier({self.fsm.describe()} + {self.rate.describe()})"

    # -- Check interface (used inside the policy pipeline) -----------------
    def screen(self, ctx: CallContext) -> Optional[Dict[str, Any]]:
        if ctx.tool not in self.HIGH_RISK_SINKS:
            return None
        return self.fsm.screen(ctx) or self.rate.screen(ctx)

    def observe(self, tool: str, args: Dict[str, Any], result: Dict[str, Any]) -> None:
        if not isinstance(result, dict):
            return
        self.store.observe(tool, result)
        self.fsm.observe(tool, args, result)

    # -- original standalone API ------------------------------------------
    def screen_call(self, tool_name: str, real_args: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        return self.screen(CallContext(tool_name, real_args, real_args))

    def observe_result(self, tool_name: str, result: Dict[str, Any]) -> None:
        """Without the call's args, key a confirmed release by its result fields."""
        r = result if isinstance(result, dict) else {}
        self.observe(tool_name, {"supi": r.get("supi"), "pdu_session_id": r.get("pdu_session_id")}, r)

    def state(self) -> Dict[str, Any]:
        return {"fsm": self.store.snapshot(),
                "releases_in_window": self.rate.bucket.count(),
                "max_releases": self.max_releases, "window_sec": self.window_sec}

    def explain(self) -> str:
        snap = self.store.snapshot()
        n = self.rate.bucket.count()
        if not snap and not n:
            return "L3: no PDU-session procedure state observed yet"
        active = sorted(k for k, v in snap.items() if v == "ACTIVE")
        released = sorted(k for k, v in snap.items() if v == "RELEASED")
        return (f"L3 procedure state — ACTIVE: {active or '[]'}; RELEASED: {released or '[]'}; "
                f"{n}/{self.max_releases} releases in last {self.window_sec:g}s")
