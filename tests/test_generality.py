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


# =========================================================================== #
# STAGE 2 — CROSS-PROCEDURE GENERALITY: the fsm/rate machinery has no built-in
# knowledge of PDU sessions. The same PolicyEngine enforces any procedure that
# is *declared as data*, including one with nothing to do with 5G.
# =========================================================================== #

# --- 2a. A deliberately NON-5G procedure: a door lock --------------------- #
# If the gateway can enforce this with the same code that enforces PDU release,
# then nothing in that code is PDU-specific. This is the decisive anti-
# "hard-coded" proof.
class DoorPanel:
    def __init__(self, doors=("front", "back", "side", "garage")):
        self.state = {d: "LOCKED" for d in doors}
        self.calls = []

    def tools(self):
        def read_doors(**_):
            self.calls.append("read_doors")
            return {"status": "ok",
                    "doors": [{"id": d, "state": s} for d, s in sorted(self.state.items())]}

        def unlock_door(door_id=None, **_):
            self.calls.append("unlock_door")
            self.state[door_id] = "UNLOCKED"
            return {"status": "ok", "door_id": door_id}

        def lock_door(door_id=None, **_):
            self.calls.append("lock_door")
            self.state[door_id] = "LOCKED"
            return {"status": "ok", "door_id": door_id}

        return {f.__name__: f for f in (read_doors, unlock_door, lock_door)}

    def count(self, tool):
        return sum(1 for t in self.calls if t == tool)


def _door_policy():
    return {
        "procedures": {
            "door_lock": {
                "key": ["door_id"],
                "initial": "UNKNOWN",
                "states": ["UNKNOWN", "LOCKED", "UNLOCKED"],
                "observe": [{"tool": "read_doors", "when": {"status": "ok"},
                             "for_each": "doors", "key": ["item.id"],
                             "set": "LOCKED", "keep": ["UNLOCKED"]}],
                "transitions": {
                    "unlock": {"from": ["LOCKED"], "to": "UNLOCKED", "commit_when": {"status": "ok"}},
                    "lock": {"from": ["UNLOCKED"], "to": "LOCKED", "commit_when": {"status": "ok"}},
                },
            }
        },
        "tools": {
            "*": {"checks": []},
            "unlock_door": {"checks": [
                {"fsm": {"procedure": "door_lock", "event": "unlock"}},
                {"rate": {"bucket": "door_unlock", "max": 2, "window_sec": 60}}]},
            "lock_door": {"checks": [{"fsm": {"procedure": "door_lock", "event": "lock"}}]},
        },
    }


def _door_gw(panel):
    # No identifiers here at all -> L1 tokenizer and L2 taint are meaningless and
    # off. Only the L3 procedure machinery runs, on a domain it has never seen.
    return GatewayToolClient(LocalToolClient(panel.tools()), policy=_door_policy(),
                             enable_tokenizer=False, enable_taint=False)


def test_foreign_procedure_fsm_enforced_by_same_engine():
    """unlock is legal only from LOCKED. The gateway refuses it before any
    context is known, learns LOCKED by observing read_doors, then allows exactly
    one unlock and refuses the out-of-state repeat — all via door_lock declared
    as data, with the identical FsmCheck that guards PDU release."""
    panel = DoorPanel()
    gw = _door_gw(panel)

    # no context observed yet -> UNKNOWN, unlock requires LOCKED
    out = gw.invoke("unlock_door", {"door_id": "front"})
    assert out["status"] == "blocked" and out["violation"] == "fsm-no-context", out
    assert panel.count("unlock_door") == 0

    gw.invoke("read_doors", {})                       # observe -> every door LOCKED
    out = gw.invoke("unlock_door", {"door_id": "front"})
    assert out["status"] == "ok", out                 # LOCKED -> UNLOCKED committed

    out = gw.invoke("unlock_door", {"door_id": "front"})
    assert out["violation"] == "fsm-out-of-state", out  # UNLOCKED, cannot unlock again
    assert panel.count("unlock_door") == 1


def test_foreign_procedure_rate_cap_by_same_engine():
    """The same RateCheck that bounds a PDU-release blast radius bounds a bulk
    door-unlock. Nothing about rate limiting is 5G-specific."""
    panel = DoorPanel(doors=("d1", "d2", "d3", "d4", "d5"))
    gw = _door_gw(panel)
    gw.invoke("read_doors", {})                       # all LOCKED
    outs = [gw.invoke("unlock_door", {"door_id": d}) for d in ("d1", "d2", "d3", "d4", "d5")]
    assert [o["status"] for o in outs].count("ok") == 2, outs
    assert all(o["violation"] == "rate-limit" for o in outs[2:]), outs
    assert panel.count("unlock_door") == 2


def test_foreign_procedure_full_cycle_lock_unlock():
    """Both transitions of the foreign procedure compose: unlock then lock then
    unlock again, each gated by its own FsmCheck event."""
    panel = DoorPanel(doors=("gate",))
    gw = _door_gw(panel)
    gw.invoke("read_doors", {})
    assert gw.invoke("unlock_door", {"door_id": "gate"})["status"] == "ok"
    assert gw.invoke("lock_door", {"door_id": "gate"})["status"] == "ok"
    assert gw.invoke("unlock_door", {"door_id": "gate"})["status"] == "ok"
    # locking an already-locked (just unlocked->locked) ... now UNLOCKED again:
    assert gw.invoke("unlock_door", {"door_id": "gate"})["violation"] == "fsm-out-of-state"


# --- 2b. A SECOND, on-theme 3GPP procedure: UE registration --------------- #
# Distinct from the PDU-session life-cycle (different states, different tool),
# so "procedure-aware" is shown on more than one real 5G procedure — the answer
# to "one procedure just looks like a rate limit" (advisor B1).
class RegCore:
    def __init__(self, n=4):
        self.registered = {f"{S_PREFIX}{i}": True for i in range(1, n + 1)}
        self.calls = []

    def tools(self):
        def list_subscribers(**_):
            return {"status": "ok",
                    "subscribers": [{"ueId": s} for s in sorted(self.registered)]}

        def query_registration(supi_token=None, **_):
            self.calls.append("query_registration")
            reg = self.registered.get(supi_token)
            if reg is None:
                return {"status": "error", "error": "unknown"}
            return {"status": "ok", "subscriber": {
                "supi": supi_token, "registration": "REGISTERED" if reg else "DEREGISTERED"}}

        def trigger_ue_deregistration(supi_token=None, **_):
            self.calls.append("trigger_ue_deregistration")
            if self.registered.get(supi_token):
                self.registered[supi_token] = False
                return {"status": "ok", "verified": True, "supi": supi_token}
            return {"status": "noop", "verified": False, "supi": supi_token}

        return {f.__name__: f for f in
                (list_subscribers, query_registration, trigger_ue_deregistration)}

    def count(self, tool):
        return sum(1 for t in self.calls if t == tool)


def _reg_policy():
    return {
        "identifier_params": ["supi_token", "supi", "imsi"],
        "procedures": {
            "ue_registration": {
                "key": ["supi_token|supi|imsi"],
                "initial": "UNKNOWN",
                "states": ["UNKNOWN", "REGISTERED", "DEREGISTERED"],
                "observe": [{"tool": "query_registration", "when": {"status": "ok"},
                             "key": ["subscriber.supi"], "set": "REGISTERED",
                             "keep": ["DEREGISTERED"]}],
                "transitions": {"deregister": {"from": ["REGISTERED"], "to": "DEREGISTERED",
                                               "commit_when": {"status": "ok", "verified": True}}},
            }
        },
        "tools": {
            "*": {"checks": ["identifier"]},
            "trigger_ue_deregistration": {"checks": [
                "identifier",
                {"fsm": {"procedure": "ue_registration", "event": "deregister"}},
                {"rate": {"bucket": "dereg", "max": 2, "window_sec": 60}}]},
        },
    }


def test_second_5g_procedure_registration_lifecycle():
    """A different real 3GPP procedure (TS 23.502 registration), different
    states (REGISTERED/DEREGISTERED) and a different tool — same engine, same
    check types, declared entirely in config."""
    core = RegCore()
    gw = GatewayToolClient(LocalToolClient(core.tools()), policy=_reg_policy(),
                           enable_taint=False)
    tok = gw.invoke("list_subscribers", {})["subscribers"][0]["ueId"]

    # deregister before the gateway has observed the UE registered
    out = gw.invoke("trigger_ue_deregistration", {"supi_token": tok})
    assert out["status"] == "blocked" and out["violation"] == "fsm-no-context", out

    gw.invoke("query_registration", {"supi_token": tok})        # observe -> REGISTERED
    assert gw.invoke("trigger_ue_deregistration", {"supi_token": tok})["status"] == "ok"
    # double deregistration is out-of-state, exactly like a double PDU release
    out = gw.invoke("trigger_ue_deregistration", {"supi_token": tok})
    assert out["violation"] == "fsm-out-of-state", out
    assert core.count("trigger_ue_deregistration") == 1


def test_second_5g_procedure_rate_cap():
    """Bulk deregistration (a different DoS on a different procedure) is bounded
    by the same RateCheck."""
    core = RegCore(n=5)
    gw = GatewayToolClient(LocalToolClient(core.tools()), policy=_reg_policy(),
                           enable_taint=False)
    toks = [s["ueId"] for s in gw.invoke("list_subscribers", {})["subscribers"]]
    for t in toks:
        gw.invoke("query_registration", {"supi_token": t})      # observe all REGISTERED
    outs = [gw.invoke("trigger_ue_deregistration", {"supi_token": t}) for t in toks]
    assert [o["status"] for o in outs].count("ok") == 2, outs
    assert all(o["violation"] == "rate-limit" for o in outs[2:]), outs


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print(f"[OK] {name}")
    print("\nALL GENERALITY TESTS PASSED")
