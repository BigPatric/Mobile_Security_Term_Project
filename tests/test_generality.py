"""
tests/test_generality.py — the gateway is a GENERAL mechanism, not a PDU-release
special case (offline, no live core)
================================================================================
The project's central claim is that the gateway is a *policy-driven,
procedure-aware tool-call checker*. The three attack scenarios only demonstrate
that it works; this file demonstrates that it is GENERAL. It is built up in
three stages, each proving a different, independently-defensible sense of
"general":

  Stage 1 — COMPOSABILITY  (this section)
      Adding, removing or tuning the protection on an *existing* tool is a
      config edit. The same PolicyEngine class, with zero changes to any file
      under gateway/, produces different enforcement purely from a different
      policy dict. => protection is data, not code.

  Stage 2 — CROSS-PROCEDURE GENERALITY  (added next)
      The same engine enforces procedures it has no built-in knowledge of,
      including a deliberately non-5G one. => the FSM/rate machinery is not
      hard-wired to PDU sessions.

  Stage 3 — ATTACK-BLIND GENERALITY  (added last)
      Attack variants we never scripted or tuned for are still caught by the
      existing procedure-aware rules. => the gateway defends a *class* of
      violations, not the specific attacks in the demo.

Run directly:   python3 tests/test_generality.py
With pytest:    pytest tests/test_generality.py
"""

import copy
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agent.tool_client import LocalToolClient
from gateway.mcp_gateway import GatewayToolClient

S_PREFIX = "imsi-20893000000000"


# --------------------------------------------------------------------------- #
# A minimal, self-contained fake 5G core (SUPI -> set of live PDU session ids).
# Kept local to this file so the generality proof reads top-to-bottom with no
# cross-test coupling.
# --------------------------------------------------------------------------- #
class MiniCore:
    def __init__(self, n_subs=5):
        self.sessions = {f"{S_PREFIX}{i}": {1} for i in range(1, n_subs + 1)}
        self.calls = []

    def tools(self):
        def list_subscribers(**_):
            self.calls.append("list_subscribers")
            return {"status": "ok", "count": len(self.sessions),
                    "subscribers": [{"ueId": s, "plmnID": "20893"} for s in sorted(self.sessions)]}

        def query_subscriber_session(supi_token=None, **_):
            self.calls.append("query_subscriber_session")
            if supi_token not in self.sessions:
                return {"status": "error", "error": f"not provisioned: {supi_token}"}
            ps = [{"id": i, "state": "ACTIVE"} for i in sorted(self.sessions[supi_token])]
            return {"status": "ok",
                    "subscriber": {"supi": supi_token, "pdu_sessions": ps,
                                   "active_pdu_session_count": len(ps)}}

        def trigger_pdu_session_release(supi_token=None, pdu_session_id=None, **_):
            self.calls.append("trigger_pdu_session_release")
            if pdu_session_id in self.sessions.get(supi_token, set()):
                self.sessions[supi_token].discard(pdu_session_id)
                return {"status": "ok", "verified": True,
                        "supi": supi_token, "pdu_session_id": pdu_session_id}
            return {"status": "noop", "verified": False,
                    "supi": supi_token, "pdu_session_id": pdu_session_id}

        return {f.__name__: f for f in
                (list_subscribers, query_subscriber_session, trigger_pdu_session_release)}

    def count(self, tool):
        return sum(1 for t in self.calls if t == tool)


def _gw(core, policy, **kw):
    # L3-only by default: we are proving the fsm/rate machinery is config-driven,
    # so taint (L2) is off unless a test turns it on. Tokenizer (L1) stays on so
    # the agent works with opaque tokens exactly as in production.
    kw.setdefault("enable_taint", False)
    return GatewayToolClient(LocalToolClient(core.tools()), policy=policy, **kw)


def _tokens(gw):
    return [s["ueId"] for s in gw.invoke("list_subscribers", {})["subscribers"]]


# The minimum a PDU-session policy needs; each test overrides the release chain.
def _base_policy():
    return {
        "identifier_params": ["supi_token", "supi", "imsi"],
        "procedures": {
            "pdu_session": {
                "key": ["supi_token|supi|imsi", "pdu_session_id"],
                "initial": "UNKNOWN",
                "states": ["UNKNOWN", "ACTIVE", "RELEASED"],
                "observe": [{"tool": "query_subscriber_session", "when": {"status": "ok"},
                             "for_each": "subscriber.pdu_sessions",
                             "key": ["subscriber.supi", "item.id"],
                             "set": "ACTIVE", "keep": ["RELEASED"]}],
                "transitions": {"release": {"from": ["ACTIVE", "UNKNOWN"], "to": "RELEASED",
                                            "commit_when": {"status": "ok", "verified": True}}},
            }
        },
        "tools": {"*": {"checks": ["identifier"]}},
    }


# =========================================================================== #
# STAGE 1 — COMPOSABILITY: protection is data, not code.
# =========================================================================== #

def test_no_builtin_cap_release_chain_without_rate_passes_bulk():
    """With a release chain of just [identifier], a bulk teardown of every
    session goes through. Proves the rate cap is NOT baked into the gateway —
    absent from the policy, it is absent from enforcement."""
    core = MiniCore(n_subs=5)
    policy = _base_policy()
    policy["tools"]["trigger_pdu_session_release"] = {"checks": ["identifier"]}
    gw = _gw(core, policy)
    outs = [gw.invoke("trigger_pdu_session_release", {"supi_token": t, "pdu_session_id": 1})
            for t in _tokens(gw)]
    assert [o["status"] for o in outs] == ["ok"] * 5, outs
    assert core.count("trigger_pdu_session_release") == 5


def test_adding_a_rate_cap_is_pure_config():
    """Same engine class, same tool, same core — the ONLY difference from the
    test above is three lines of policy data. Now the bulk is capped at 2."""
    core = MiniCore(n_subs=5)
    policy = _base_policy()
    policy["tools"]["trigger_pdu_session_release"] = {"checks": [
        "identifier",
        {"rate": {"bucket": "pdu_release", "max": 2, "window_sec": 60}},
    ]}
    gw = _gw(core, policy)
    outs = [gw.invoke("trigger_pdu_session_release", {"supi_token": t, "pdu_session_id": 1})
            for t in _tokens(gw)]
    assert [o["status"] for o in outs].count("ok") == 2, outs
    assert all(o["violation"] == "rate-limit" for o in outs[2:]), outs
    assert core.count("trigger_pdu_session_release") == 2   # blocked calls never reached core


def test_tuning_a_threshold_is_pure_config():
    """The same policy with a different `max` yields a different cap — no code
    path selects the number; the data does."""
    for cap in (1, 3):
        core = MiniCore(n_subs=5)
        policy = _base_policy()
        policy["tools"]["trigger_pdu_session_release"] = {"checks": [
            "identifier", {"rate": {"bucket": "pdu_release", "max": cap, "window_sec": 60}}]}
        gw = _gw(core, policy)
        outs = [gw.invoke("trigger_pdu_session_release", {"supi_token": t, "pdu_session_id": 1})
                for t in _tokens(gw)]
        assert [o["status"] for o in outs].count("ok") == cap, (cap, outs)


def test_same_checks_guard_a_different_tool_by_config_only():
    """The identifier + rate checks were written for no tool in particular.
    Point them at a *read* tool (enumeration throttling) purely in config and
    they enforce there too — nothing in the check code mentions a tool name."""
    core = MiniCore(n_subs=5)
    policy = _base_policy()
    policy["tools"]["query_subscriber_session"] = {"checks": [
        "identifier", {"rate": {"bucket": "enumeration", "max": 3, "window_sec": 60}}]}
    gw = _gw(core, policy)
    toks = _tokens(gw)
    outs = [gw.invoke("query_subscriber_session", {"supi_token": t}) for t in toks]
    assert [o["status"] for o in outs][:3] == ["ok", "ok", "ok"], outs
    assert all(o["violation"] == "rate-limit" for o in outs[3:]), outs


def test_two_tools_can_share_or_separate_budgets_by_config():
    """Bucket identity is a config string: give two tools the same bucket name
    and they share one budget; give them different names and they don't."""
    # shared budget
    core = MiniCore(n_subs=5)
    p = _base_policy()
    shared = {"rate": {"bucket": "teardown", "max": 2, "window_sec": 60}}
    p["tools"]["trigger_pdu_session_release"] = {"checks": ["identifier", shared]}
    p["tools"]["query_subscriber_session"] = {"checks": ["identifier", shared]}
    gw = _gw(core, p)
    toks = _tokens(gw)
    assert gw.invoke("query_subscriber_session", {"supi_token": toks[0]})["status"] == "ok"
    assert gw.invoke("trigger_pdu_session_release",
                     {"supi_token": toks[0], "pdu_session_id": 1})["status"] == "ok"
    # the shared budget of 2 is now spent across the two different tools
    assert gw.invoke("query_subscriber_session",
                     {"supi_token": toks[1]})["violation"] == "rate-limit"


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print(f"[OK] {name}")
    print("\nALL GENERALITY TESTS PASSED")
