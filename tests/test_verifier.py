"""
tests/test_verifier.py — Layer 3 Procedure-Aware Verifier (offline, no live core)
=================================================================================
L3 enforces 3GPP PDU-session procedure state and rate, at the tool-call boundary,
on EVERY source — including operator-authorized ones. These tests show L3 catches
exactly what L1/L2 cannot:

  * double / out-of-state release   (FSM)
  * bulk release / control-plane DoS (rate limit)
  * authorized bulk release          (L2 would pass it; L3 still blocks)

Run directly:   python3 tests/test_verifier.py
With pytest:    pytest tests/test_verifier.py
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agent.tool_client import LocalToolClient
from gateway.mcp_gateway import GatewayToolClient
from gateway.verifier import ProcedureVerifier


def _build(verifier: ProcedureVerifier, n_sessions: int = 1, enable_verifier: bool = True):
    """Gateway with ONLY L3 active (L1/L2 off) so we isolate procedure logic.
    `seen` records what actually reached the core."""
    seen = {"release": []}
    subs = [{"ueId": f"imsi-20893000000000{i}", "plmnID": "20893"} for i in range(1, n_sessions + 1)]

    def fake_list(**_):
        return {"status": "ok", "count": len(subs), "subscribers": subs}

    def fake_query(supi_token=None, **_):
        return {"status": "ok", "subscriber": {
            "supi": supi_token, "registration_state": "REGISTERED",
            "pdu_sessions": [{"id": 1, "smContextRef": "ref-1"}],
            "active_pdu_session_count": 1}}

    def fake_release(**kw):
        seen["release"].append(kw)
        return {"status": "ok", "verified": True,
                "supi": kw.get("supi_token"), "pdu_session_id": kw.get("pdu_session_id")}

    inner = LocalToolClient({"list_subscribers": fake_list,
                             "query_subscriber_session": fake_query,
                             "trigger_pdu_session_release": fake_release})
    gw = GatewayToolClient(inner, enable_tokenizer=False, enable_taint=False,
                           enable_verifier=enable_verifier, verifier=verifier)
    return gw, seen


def test_single_release_allowed():
    gw, seen = _build(ProcedureVerifier(max_releases=3))
    gw.invoke("query_subscriber_session", {"supi_token": "imsi-208930000000001"})
    out = gw.invoke("trigger_pdu_session_release",
                    {"supi_token": "imsi-208930000000001", "pdu_session_id": 1})
    assert out["status"] == "ok", out            # a legal single release passes
    assert len(seen["release"]) == 1


def test_double_release_blocked_out_of_state():
    gw, seen = _build(ProcedureVerifier(max_releases=9))   # high rate cap: isolate FSM
    args = {"supi_token": "imsi-208930000000001", "pdu_session_id": 1}
    assert gw.invoke("trigger_pdu_session_release", dict(args))["status"] == "ok"
    out = gw.invoke("trigger_pdu_session_release", dict(args))   # release it AGAIN
    assert out["status"] == "blocked" and out["layer"] == "L3", out
    assert out["violation"] == "fsm-out-of-state", out
    assert len(seen["release"]) == 1             # 2nd release never reached the core


def test_rate_limit_blocks_bulk_release():
    gw, seen = _build(ProcedureVerifier(max_releases=2, window_sec=60.0), n_sessions=5)
    blocked = 0
    for i in range(1, 6):
        out = gw.invoke("trigger_pdu_session_release",
                        {"supi_token": f"imsi-20893000000000{i}", "pdu_session_id": 1})
        if out["status"] == "blocked":
            blocked += 1
            assert out["violation"] == "rate-limit", out
    assert len(seen["release"]) == 2             # only the first 2 got through
    assert blocked == 3


def test_rate_window_slides():
    t = {"now": 1000.0}
    gw, seen = _build(ProcedureVerifier(max_releases=1, window_sec=10.0, now_fn=lambda: t["now"]),
                      n_sessions=3)
    assert gw.invoke("trigger_pdu_session_release",
                     {"supi_token": "imsi-208930000000001", "pdu_session_id": 1})["status"] == "ok"
    # immediately again -> over cap within window
    assert gw.invoke("trigger_pdu_session_release",
                     {"supi_token": "imsi-208930000000002", "pdu_session_id": 1})["status"] == "blocked"
    t["now"] += 11.0                             # window elapses
    assert gw.invoke("trigger_pdu_session_release",
                     {"supi_token": "imsi-208930000000003", "pdu_session_id": 1})["status"] == "ok"
    assert len(seen["release"]) == 2


def test_authorized_bulk_still_blocked_by_l3():
    """The crux: L2 lets an authorized release through; L3 does NOT."""
    gw, seen = _build(ProcedureVerifier(max_releases=2, exempt_authorized=False), n_sessions=5)
    results = [gw.invoke("trigger_pdu_session_release",
                         {"supi_token": f"imsi-20893000000000{i}", "pdu_session_id": 1,
                          "operator_authorization": "signed-by-noc"})
               for i in range(1, 6)]
    assert any(r["status"] == "blocked" and r["layer"] == "L3" for r in results), results
    assert len(seen["release"]) == 2             # authorization is not an L3 bypass


def test_exempt_authorized_opt_in():
    """With exempt_authorized=True, L3 defers to authorization (opt-in)."""
    gw, seen = _build(ProcedureVerifier(max_releases=1, exempt_authorized=True), n_sessions=3)
    for i in range(1, 4):
        out = gw.invoke("trigger_pdu_session_release",
                        {"supi_token": f"imsi-20893000000000{i}", "pdu_session_id": 1,
                         "operator_authorization": "signed-by-noc"})
        assert out["status"] == "ok", out
    assert len(seen["release"]) == 3


def test_strict_requires_established_context():
    gw, seen = _build(ProcedureVerifier(require_established=True))
    # release WITHOUT a preceding query (no ACTIVE context observed) -> blocked
    out = gw.invoke("trigger_pdu_session_release",
                    {"supi_token": "imsi-208930000000001", "pdu_session_id": 1})
    assert out["status"] == "blocked" and out["violation"] == "fsm-no-context", out
    assert seen["release"] == []


def test_ablation_verifier_off_lets_bulk_through():
    gw, seen = _build(verifier=None, n_sessions=5, enable_verifier=False)   # L3 disabled
    for i in range(1, 6):
        gw.invoke("trigger_pdu_session_release",
                  {"supi_token": f"imsi-20893000000000{i}", "pdu_session_id": 1})
    assert len(seen["release"]) == 5                 # without L3 the bulk DoS succeeds


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print(f"[OK] {name}")
    print("\nALL VERIFIER (L3) TESTS PASSED")
