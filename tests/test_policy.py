"""
tests/test_policy.py — config-driven policy pipeline (offline, no live core)
============================================================================
Shows the gateway is a GENERAL mechanism: chains, procedures and new tools are
declared as data; the same engine enforces them.

Run directly:   python3 tests/test_policy.py
With pytest:    pytest tests/test_policy.py
"""

import copy
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agent.tool_client import LocalToolClient
from gateway.mcp_gateway import GatewayToolClient
from gateway.policy import DEFAULT_POLICY, PolicyEngine
from gateway.procedures import pdu_session_procedure

SUPI_RE = re.compile(r"imsi-\d{15}")
S1 = "imsi-208930000000001"


class FakeCore:
    """Minimal stateful core: SUPI -> set of live PDU session ids."""

    def __init__(self, sessions=None):
        self.sessions = {k: set(v) for k, v in (sessions or {S1: {1}}).items()}
        self.calls = []

    def tools(self):
        def list_subscribers(**_):
            self.calls.append(("list_subscribers", {}))
            return {"status": "ok", "count": len(self.sessions),
                    "subscribers": [{"ueId": s, "plmnID": "20893"} for s in sorted(self.sessions)]}

        def query_subscriber_session(supi_token=None, **_):
            self.calls.append(("query_subscriber_session", {"supi_token": supi_token}))
            if supi_token not in self.sessions:
                return {"status": "error", "error": f"Subscriber '{supi_token}' not provisioned"}
            ps = [{"id": i, "state": "ACTIVE"} for i in sorted(self.sessions[supi_token])]
            return {"status": "ok", "subscriber": {"supi": supi_token, "pdu_sessions": ps,
                                                   "active_pdu_session_count": len(ps)}}

        def trigger_pdu_session_release(supi_token=None, pdu_session_id=None, **_):
            self.calls.append(("trigger_pdu_session_release", {"supi_token": supi_token}))
            if pdu_session_id in self.sessions.get(supi_token, set()):
                self.sessions[supi_token].discard(pdu_session_id)
                return {"status": "ok", "verified": True, "supi": supi_token, "pdu_session_id": pdu_session_id}
            return {"status": "noop", "verified": False, "supi": supi_token, "pdu_session_id": pdu_session_id}

        def modify_session_qos(supi_token=None, pdu_session_id=None, **_):
            self.calls.append(("modify_session_qos", {"supi_token": supi_token}))
            return {"status": "ok", "supi": supi_token, "pdu_session_id": pdu_session_id}

        return {f.__name__: f for f in (list_subscribers, query_subscriber_session,
                                        trigger_pdu_session_release, modify_session_qos)}

    def count(self, tool):
        return sum(1 for t, _ in self.calls if t == tool)


def _gw(core, policy=None, **kw):
    return GatewayToolClient(LocalToolClient(core.tools()), policy=policy, **kw)


def _token(gw):
    return gw.invoke("list_subscribers", {})["subscribers"][0]["ueId"]


PRECHECK = {"core_precheck": {
    "via": "query_subscriber_session",
    "args": {"supi_token": "$supi_token"},
    "expect": {"status": "ok",
               "exists": {"in": "subscriber.pdu_sessions", "where": {"id": "$pdu_session_id"}}}}}


def _policy_with_precheck(max_releases=2):
    p = copy.deepcopy(DEFAULT_POLICY)
    p["tools"]["trigger_pdu_session_release"]["checks"] = [
        "identifier", {"provenance": {}},
        {"fsm": {"procedure": "pdu_session", "event": "release"}},
        {"rate": {"bucket": "pdu_release", "max": max_releases, "window_sec": 60}},
        PRECHECK]
    return p


# --- generality: a NEW procedure + tool, declared only in config ------------ #
def test_new_procedure_declared_in_config_only():
    """A QoS-modification procedure the code has never heard of: legal only on
    an ACTIVE session. No Python written for it — just policy data."""
    p = copy.deepcopy(DEFAULT_POLICY)
    proc = pdu_session_procedure()
    proc["transitions"]["modify"] = {"from": ["ACTIVE"], "to": "ACTIVE",
                                     "commit_when": {"status": "ok"}}
    p["procedures"]["pdu_session"] = proc
    p["tools"]["modify_session_qos"] = {"checks": [
        "identifier", {"fsm": {"procedure": "pdu_session", "event": "modify"}}]}
    core = FakeCore()
    gw = _gw(core, policy=p)
    tok = _token(gw)
    out = gw.invoke("modify_session_qos", {"supi_token": tok, "pdu_session_id": 1})
    assert out["status"] == "blocked" and out["violation"] == "fsm-no-context", out
    gw.invoke("query_subscriber_session", {"supi_token": tok})           # observe -> ACTIVE
    out = gw.invoke("modify_session_qos", {"supi_token": tok, "pdu_session_id": 1})
    assert out["status"] == "ok", out
    assert core.count("modify_session_qos") == 1


def test_bad_policy_rejected_at_build_time():
    for mutate, msg in [
        (lambda p: p["tools"].__setitem__("x", {"checks": ["no_such_check"]}), "unknown check"),
        (lambda p: p["tools"].__setitem__("x", {"checks": [{"fsm": {"procedure": "nope", "event": "e"}}]}),
         "unknown procedure"),
        (lambda p: p["tools"].__setitem__("x", {"checks": [{"fsm": {"procedure": "pdu_session", "event": "nope"}}]}),
         "no transition"),
        (lambda p: p["procedures"]["pdu_session"]["transitions"]["release"].__setitem__("to", "GONE"),
         "undeclared state"),
    ]:
        p = copy.deepcopy(DEFAULT_POLICY)
        mutate(p)
        try:
            PolicyEngine(p)
        except ValueError as e:
            assert msg in str(e), (msg, e)
        else:
            raise AssertionError(f"policy with {msg} was accepted")


def test_layer_toggle_drops_checks():
    e = PolicyEngine(_policy_with_precheck(), layers={"tokenizer": True, "taint": False, "verifier": False})
    assert e.describe()["trigger_pdu_session_release"] == ["identifier"]
    e = PolicyEngine(_policy_with_precheck(), layers={"tokenizer": False, "taint": True, "verifier": True})
    assert e.describe()["trigger_pdu_session_release"][0] == "provenance"


# --- core_precheck: ground truth from the core ------------------------------ #
def test_core_precheck_blocks_nonexistent_session():
    core = FakeCore()
    gw = _gw(core, policy=_policy_with_precheck())
    tok = _token(gw)
    out = gw.invoke("trigger_pdu_session_release", {"supi_token": tok, "pdu_session_id": 7})
    assert out["status"] == "blocked" and out["violation"] == "core-precheck-failed", out
    assert core.count("trigger_pdu_session_release") == 0          # the release never ran
    assert core.count("query_subscriber_session") == 1             # the gateway asked the core


def test_core_precheck_passes_existing_session_and_feeds_fsm():
    core = FakeCore()
    gw = _gw(core, policy=_policy_with_precheck())
    tok = _token(gw)
    out = gw.invoke("trigger_pdu_session_release", {"supi_token": tok, "pdu_session_id": 1})
    assert out["status"] == "ok", out
    # gateway memory now says RELEASED -> a second release is out-of-state,
    # caught by the FSM before any further core query
    q_before = core.count("query_subscriber_session")
    out = gw.invoke("trigger_pdu_session_release", {"supi_token": tok, "pdu_session_id": 1})
    assert out["violation"] == "fsm-out-of-state", out
    assert core.count("query_subscriber_session") == q_before


def test_rate_runs_before_precheck_so_bulk_does_not_hammer_core():
    core = FakeCore({f"imsi-20893000000000{i}": {1} for i in range(1, 7)})
    gw = _gw(core, policy=_policy_with_precheck(max_releases=2))
    toks = [s["ueId"] for s in gw.invoke("list_subscribers", {})["subscribers"]]
    outs = [gw.invoke("trigger_pdu_session_release", {"supi_token": t, "pdu_session_id": 1}) for t in toks]
    assert [o["status"] for o in outs].count("ok") == 2
    assert all(o["violation"] == "rate-limit" for o in outs[2:])
    assert core.count("query_subscriber_session") == 2             # prechecks only for the 2 allowed


# --- blocks never leak identifiers ------------------------------------------ #
def test_block_response_is_redacted():
    core = FakeCore()
    gw = _gw(core, policy=_policy_with_precheck())
    tok = _token(gw)
    gw.invoke("trigger_pdu_session_release", {"supi_token": tok, "pdu_session_id": 1})
    out = gw.invoke("trigger_pdu_session_release", {"supi_token": tok, "pdu_session_id": 1})  # L3 block
    assert out["status"] == "blocked"
    assert not SUPI_RE.findall(json.dumps(out)), out               # real SUPI never shown
    assert tok in json.dumps(out)                                  # the known token is


def test_redact_does_not_mint_tokens_for_unknown_supis():
    gw = _gw(FakeCore())
    before = gw.tokenizer.mapping_count()
    red = gw.tokenizer.redact({"reason": "value imsi-208930000000099 from log"})
    assert "imsi-[REDACTED]" in red["reason"]
    assert gw.tokenizer.mapping_count() == before


# --- explainability + other tools ------------------------------------------- #
def test_decision_trace_recorded():
    core = FakeCore()
    gw = _gw(core, policy=_policy_with_precheck())
    tok = _token(gw)
    gw.invoke("trigger_pdu_session_release", {"supi_token": tok, "pdu_session_id": 9})
    d = gw.decisions[-1]
    assert d["decision"] == "block" and d["check"] == "core_precheck", d
    assert [t["outcome"] for t in d["trace"]] == ["pass", "pass", "pass", "pass", "block"], d["trace"]
    assert d["gateway_overhead_ms"] >= 0


def test_enumeration_rate_limit():
    p = copy.deepcopy(DEFAULT_POLICY)
    p["tools"]["list_subscribers"] = {"checks": ["identifier",
                                                 {"rate": {"bucket": "enumeration", "max": 2, "window_sec": 60}}]}
    gw = _gw(FakeCore(), policy=p)
    outs = [gw.invoke("list_subscribers", {})["status"] for _ in range(3)]
    assert outs == ["ok", "ok", "blocked"], outs


def test_deny_allowlist():
    p = {"tools": {"*": {"checks": ["deny"]}, "list_subscribers": {"checks": []}}}
    gw = _gw(FakeCore(), policy=p, enable_tokenizer=False)
    assert gw.invoke("list_subscribers", {})["status"] == "ok"
    out = gw.invoke("modify_session_qos", {"supi_token": S1, "pdu_session_id": 1})
    assert out["status"] == "blocked" and out["violation"] == "not-allowed", out


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print(f"[OK] {name}")
    print("\nALL POLICY TESTS PASSED")
