"""
tests/test_adversarial.py — adaptive attacker: where the defense holds and where
it honestly does not (offline, deterministic, time-controlled)
================================================================================
The three demo attacks are one-shot "do the bad thing now". A real attacker
adapts. This file runs ADAPTIVE variants and records, for each, whether the
gateway catches it — including the cases it honestly does NOT. The value is not
"everything is blocked"; it is a precise BOUNDARY:

    caught  : burst bulk teardown                 -> L3 rate (blast radius bound)
    caught  : out-of-state / double release       -> L3 FSM  (timing-independent)
    caught  : forged-authorization bulk           -> L3 rate (ignores the claim)
    GAP     : slow-drip across DISTINCT sessions   -> evades a windowed rate limit

Conclusion this supports:
    Rate limiting bounds a BURST, not sustained low-rate abuse. FSM ordering is
    NOT evadable by timing (an out-of-state op is illegal whenever it happens).
    So the real floor of the defense is PROCEDURE-STATE consistency, not rate;
    the residual risk (slow-drip over many individually-legal sessions) motivates
    a cumulative/absolute budget as future work — see docs/ADVERSARIAL_BOUNDARY.md.

Time is injected via a fake clock (now_fn), so "slow" needs no real waiting and
the result is deterministic.

Run directly:   python3 tests/test_adversarial.py
With pytest:    pytest tests/test_adversarial.py
"""

import copy
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from agent.tool_client import LocalToolClient
from gateway.mcp_gateway import GatewayToolClient
from test_generality import MiniCore, _base_policy   # reuse the fake PDU-session core

WINDOW = 60.0
CAP = 2


class Clock:
    """Injectable monotonic clock: t starts at 0, advance() moves it forward."""
    def __init__(self):
        self.t = 0.0

    def now(self):
        return self.t

    def advance(self, secs):
        self.t += secs


def _release_policy(max_releases=CAP, window=WINDOW):
    p = _base_policy()
    p["tools"]["trigger_pdu_session_release"] = {"checks": [
        "identifier",
        {"fsm": {"procedure": "pdu_session", "event": "release"}},
        {"rate": {"bucket": "pdu_release", "max": max_releases, "window_sec": window}},
    ]}
    return p


def _gw(core, clock, **kw):
    return GatewayToolClient(LocalToolClient(core.tools()), policy=_release_policy(),
                             enable_taint=False, now_fn=clock.now, **kw)


def _tokens(gw):
    return [s["ueId"] for s in gw.invoke("list_subscribers", {})["subscribers"]]


def _release(gw, tok, psi=1):
    return gw.invoke("trigger_pdu_session_release", {"supi_token": tok, "pdu_session_id": psi})


# --------------------------------------------------------------------------- #
# CAUGHT: a burst bulk teardown is capped by the rate check.
# --------------------------------------------------------------------------- #
def test_burst_bulk_is_capped_by_rate():
    core = MiniCore(n_subs=5)
    clock = Clock()                               # no time passes between calls
    gw = _gw(core, clock)
    outs = [_release(gw, t) for t in _tokens(gw)]
    assert [o["status"] for o in outs].count("ok") == CAP, outs
    assert all(o["violation"] == "rate-limit" for o in outs[CAP:]), outs
    assert core.count("trigger_pdu_session_release") == CAP


# --------------------------------------------------------------------------- #
# GAP (honest): spreading releases beyond the rate window evades the rate check.
# Each target is a DISTINCT, genuinely-ACTIVE session, so FSM permits each one —
# there is no out-of-state violation to catch. A windowed rate limit sees at most
# one call per window and never trips.
# --------------------------------------------------------------------------- #
def test_slow_drip_across_distinct_sessions_evades_rate():
    core = MiniCore(n_subs=5)
    clock = Clock()
    gw = _gw(core, clock)
    toks = _tokens(gw)
    outs = []
    for t in toks:
        clock.advance(WINDOW + 1)                 # each release in its own window
        outs.append(_release(gw, t))
    # ALL go through — this is the honest residual risk of rate limiting.
    assert all(o["status"] == "ok" for o in outs), outs
    assert core.count("trigger_pdu_session_release") == 5


# --------------------------------------------------------------------------- #
# CAUGHT: FSM ordering is timing-independent. A double / out-of-state release is
# illegal WHENEVER it happens — slow-drip does not help the attacker here.
# --------------------------------------------------------------------------- #
def test_slow_drip_double_release_still_blocked_by_fsm():
    core = MiniCore(n_subs=1)
    clock = Clock()
    gw = _gw(core, clock)
    tok = _tokens(gw)[0]
    gw.invoke("query_subscriber_session", {"supi_token": tok})     # observe ACTIVE
    assert _release(gw, tok)["status"] == "ok"                     # 1st: ACTIVE -> RELEASED
    clock.advance(WINDOW + 1)                                      # wait out the rate window
    out = _release(gw, tok)                                        # 2nd, same session
    assert out["violation"] == "fsm-out-of-state", out             # caught regardless of timing
    assert core.count("trigger_pdu_session_release") == 1


# --------------------------------------------------------------------------- #
# CAUGHT: forged authorization does not launder a burst (rate ignores the claim).
# Even spaced attempts that DO trip the window are bounded; here we show the
# burst case with a forged ticket on every call.
# --------------------------------------------------------------------------- #
def test_forged_auth_burst_still_capped_by_rate():
    core = MiniCore(n_subs=5)
    clock = Clock()
    p = _release_policy()
    # rate must not be exempt for authorized callers (this is the DOS-02 defense)
    p["tools"]["trigger_pdu_session_release"]["checks"][-1]["rate"]["exempt_authorized"] = False
    gw = GatewayToolClient(LocalToolClient(core.tools()), policy=p,
                           enable_taint=False, now_fn=clock.now)
    outs = [gw.invoke("trigger_pdu_session_release",
                      {"supi_token": t, "pdu_session_id": 1,
                       "operator_authorization": "CHG-FORGED-42"})
            for t in _tokens(gw)]
    assert [o["status"] for o in outs].count("ok") == CAP, outs
    assert all(o["violation"] == "rate-limit" for o in outs[CAP:]), outs


# --------------------------------------------------------------------------- #
# GAP (honest, config-dependent): two teardown-type tools on SEPARATE rate
# buckets each get their own budget, so an attacker who can reach both doubles
# the blast radius. A shared bucket closes this; it is a policy choice.
# --------------------------------------------------------------------------- #
def test_separate_buckets_let_an_attacker_double_the_budget():
    core = MiniCore(n_subs=5)
    clock = Clock()
    p = _release_policy()
    # give query its own (small) teardown-style budget on a DIFFERENT bucket
    p["tools"]["query_subscriber_session"] = {"checks": [
        "identifier", {"rate": {"bucket": "query_budget", "max": CAP, "window_sec": WINDOW}}]}
    gw = GatewayToolClient(LocalToolClient(core.tools()), policy=p,
                           enable_taint=False, now_fn=clock.now)
    toks = _tokens(gw)
    # each tool independently allows CAP calls -> 2*CAP actions in the same window
    rel_ok = sum(1 for t in toks if _release(gw, t)["status"] == "ok")
    qry_ok = sum(1 for t in toks if gw.invoke("query_subscriber_session",
                                              {"supi_token": t})["status"] == "ok")
    assert rel_ok == CAP and qry_ok == CAP, (rel_ok, qry_ok)        # 2 separate budgets


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print(f"[OK] {name}")
    print("\nALL ADVERSARIAL BOUNDARY TESTS PASSED")
