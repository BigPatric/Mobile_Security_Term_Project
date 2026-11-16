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
"""

from __future__ import annotations

import logging
import time
from typing import Any, Callable, Deque, Dict, List, Optional, Tuple
from collections import deque

logger = logging.getLogger(__name__)

# Per-session key = (real SUPI, PDU session id). Values are FSM states.
_ACTIVE = "ACTIVE"
_RELEASED = "RELEASED"

SessionKey = Tuple[str, Any]


class ProcedureVerifier:
    HIGH_RISK_SINKS = {"trigger_pdu_session_release"}

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
        self._now = now_fn
        self.fsm: Dict[SessionKey, str] = {}
        self.release_times: Deque[float] = deque()
        self.events: List[Dict[str, Any]] = []

    # ------------------------------------------------------------------ #
    # IN path: before a high-risk tool runs, verify the procedure is legal.
    # Runs on the DETOKENIZED (real) args, after L1/L2.
    # ------------------------------------------------------------------ #
    def screen_call(self, tool_name: str, real_args: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        if tool_name not in self.HIGH_RISK_SINKS:
            return None
        if self.exempt_authorized and self._authorized(real_args):
            return None

        key = self._key(real_args)

        # (a) FSM / ordering check -------------------------------------
        state = self.fsm.get(key)
        if state == _RELEASED:
            return self._blocked(tool_name, key,
                f"out-of-state: PDU session {key[1]} of {key[0]} is already RELEASED; "
                f"a second release is illegal under TS 23.502 §4.3.4",
                violation="fsm-out-of-state", fsm_state=state)
        if self.require_established and state != _ACTIVE:
            return self._blocked(tool_name, key,
                f"out-of-state: no ACTIVE context observed for PDU session {key[1]} of "
                f"{key[0]}; release requires an established session (TS 23.502 §4.3.4)",
                violation="fsm-no-context", fsm_state=state or "UNKNOWN")

        # (b) Rate / volume check --------------------------------------
        now = self._now()
        self._prune(now)
        if len(self.release_times) >= self.max_releases:
            return self._blocked(tool_name, key,
                f"rate limit: {len(self.release_times)} release(s) already in the last "
                f"{self.window_sec:g}s (max {self.max_releases}); refusing bulk PDU-session "
                f"teardown (control-plane DoS), regardless of authorization",
                violation="rate-limit",
                window=self.window_sec, count=len(self.release_times))

        # Allowed — record the attempt for the rate window.
        self.release_times.append(now)
        return None

    # ------------------------------------------------------------------ #
    # OUT path: learn procedure state from results already flowing through.
    # Runs on the RAW result (pre-tokenize), so SUPIs/ids are real.
    # ------------------------------------------------------------------ #
    def observe_result(self, tool_name: str, result: Dict[str, Any]) -> None:
        if not isinstance(result, dict):
            return
        if tool_name == "query_subscriber_session" and result.get("status") == "ok":
            sub = result.get("subscriber", {}) or {}
            supi = sub.get("supi")
            for ps in sub.get("pdu_sessions", []) or []:
                k = (supi, ps.get("id"))
                # don't resurrect a session we already know is released
                if self.fsm.get(k) != _RELEASED:
                    self.fsm[k] = _ACTIVE
        elif tool_name in self.HIGH_RISK_SINKS and result.get("status") == "ok" \
                and result.get("verified") is True:
            k = (result.get("supi"), result.get("pdu_session_id"))
            self.fsm[k] = _RELEASED
            logger.info("[GW:L3] FSM: %s PSI %s -> RELEASED", k[0], k[1])

    # ------------------------------------------------------------------ #
    @staticmethod
    def _authorized(args: Dict[str, Any]) -> bool:
        return bool(args.get("operator_authorization") or args.get("authorized"))

    @staticmethod
    def _key(args: Dict[str, Any]) -> SessionKey:
        supi = args.get("supi_token") or args.get("supi") or args.get("imsi")
        return (supi, args.get("pdu_session_id"))

    def _prune(self, now: float) -> None:
        cutoff = now - self.window_sec
        while self.release_times and self.release_times[0] < cutoff:
            self.release_times.popleft()

    def _blocked(self, tool_name: str, key: SessionKey, reason: str,
                 violation: str = "", **extra: Any) -> Dict[str, Any]:
        block = {"status": "blocked", "layer": "L3", "tool": tool_name,
                 "reason": reason, "violation": violation,
                 "supi": key[0], "pdu_session_id": key[1]}
        block.update(extra)
        self.events.append({"tool": tool_name, "violation": violation, "key": key})
        return block

    # ------------------------------------------------------------------ #
    def state(self) -> Dict[str, Any]:
        return {"fsm": {f"{k[0]}#{k[1]}": v for k, v in self.fsm.items()},
                "releases_in_window": len(self.release_times),
                "max_releases": self.max_releases, "window_sec": self.window_sec}

    def explain(self) -> str:
        if not self.fsm and not self.release_times:
            return "L3: no PDU-session procedure state observed yet"
        active = sorted(f"{k[0]}#{k[1]}" for k, v in self.fsm.items() if v == _ACTIVE)
        released = sorted(f"{k[0]}#{k[1]}" for k, v in self.fsm.items() if v == _RELEASED)
        return (f"L3 procedure state — ACTIVE: {active or '[]'}; RELEASED: {released or '[]'}; "
                f"{len(self.release_times)}/{self.max_releases} releases in last {self.window_sec:g}s")
