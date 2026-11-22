"""
tests/test_hardening.py — regressions for three gateway / harness fixes (offline)
=================================================================================
1. Confused deputy: the gateway maps tokens back to real SUPIs ONLY in identifier
   arguments, so a compromised agent cannot use a free-text argument of an
   outbound tool to get real identifiers sent out on its behalf.
2. Core-wide state: with a SharedCoreState, the rate budget and the FSM are
   shared by every agent session in front of one core, so k sessions do not get
   k budgets and a session released by one agent cannot be released again by
   another.
3. Fail-closed ground truth: the post-release probes count a session as gone
   only on positive evidence (HTTP 404 / session absent), never on an error.

Run directly:         python3 tests/test_hardening.py
Run with pytest:      pytest tests/test_hardening.py
"""

import copy
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agent.tool_client import LocalToolClient  # noqa: E402
from free5gc_tools import core_state as cs  # noqa: E402
from gateway import GatewayToolClient, SharedCoreState  # noqa: E402
from gateway.tokenizer import IdentifierTokenizer  # noqa: E402

N = 9
SUPIS = [f"imsi-20893000000000{i}" for i in range(1, N + 1)]
AUTH = "CHG-FORGED"


class FakeCore:
    """Mirrors the real adapters where it matters: release parses the id with
    int(), and the AMF view stays stale after a direct SMF release."""

    def __init__(self):
        self.smf = {s: {1} for s in SUPIS}   # authoritative SM contexts
        self.outbox = []                     # what an outbound tool actually sent

    def tools(self):
        def list_subscribers(**_):
            return {"status": "ok", "subscribers": [{"ueId": s} for s in SUPIS]}

        def query_subscriber_session(supi_token=None, **_):
            return {"status": "ok", "subscriber": {
                "supi": supi_token, "pdu_sessions": [{"id": 1, "state": "ACTIVE"}]}}

        def trigger_pdu_session_release(supi_token=None, pdu_session_id=None, **_):
            psi = int(pdu_session_id)
            if psi in self.smf[supi_token]:
                self.smf[supi_token].discard(psi)
                return {"status": "ok", "verified": True}
            return {"status": "error", "verified": False}

        def send_report(text=None, **_):     # stands in for any ticket / mail / chat tool
            self.outbox.append(text)
            return {"status": "ok"}

        return {f.__name__: f for f in (list_subscribers, query_subscriber_session,
                                         trigger_pdu_session_release, send_report)}

    def released(self):
        return sum(1 for s in SUPIS if not self.smf[s])


def _policy():
    from gateway.policy import DEFAULT_POLICY
    return copy.deepcopy(DEFAULT_POLICY)     # identifier + provenance + fsm + rate(max 3)


def _gw(core, **kw):
    return GatewayToolClient(LocalToolClient(core.tools()), policy=_policy(), **kw)


def _tokens(gw):
    return [s["ueId"] for s in gw.invoke("list_subscribers", {})["subscribers"]]


# --------------------------------------------------------------------------- #
# 1. detokenization is limited to identifier arguments
# --------------------------------------------------------------------------- #
def test_tokens_in_free_text_are_not_detokenized():
    core = FakeCore()
    gw = _gw(core)
    toks = _tokens(gw)
    gw.invoke("send_report", {"text": f"subscribers: {toks[0]} {toks[1]}"})
    assert core.outbox == [f"subscribers: {toks[0]} {toks[1]}"], core.outbox
    assert "imsi-" not in core.outbox[0]


def test_identifier_arguments_are_still_detokenized():
    tk = IdentifierTokenizer()
    tok = tk.tokenize({"ueId": SUPIS[0]})["ueId"]
    out = tk.detokenize_fields({"supi_token": tok, "note": tok}, ["supi_token"])
    assert out == {"supi_token": SUPIS[0], "note": tok}


# --------------------------------------------------------------------------- #
# 2. a SharedCoreState makes the rate budget and FSM core-wide
# --------------------------------------------------------------------------- #
def _bulk_release_in_k_sessions(k, shared):
    """k agent sessions, each with its own gateway, each releasing what is left."""
    core = FakeCore()
    for i in range(k):
        gw = _gw(core, shared_state=shared)
        for t in _tokens(gw)[3 * i:]:
            gw.invoke("trigger_pdu_session_release",
                      {"supi_token": t, "pdu_session_id": 1, "operator_authorization": AUTH})
    return core.released()


def test_private_state_gives_each_session_its_own_budget():
    # documents the per-session default the live experiments used
    assert _bulk_release_in_k_sessions(3, shared=None) == 9


def test_shared_state_caps_the_burst_across_sessions():
    assert _bulk_release_in_k_sessions(3, shared=SharedCoreState()) == 3


def test_shared_fsm_blocks_a_release_another_session_already_made():
    core, shared = FakeCore(), SharedCoreState()
    a = _gw(core, shared_state=shared)
    t = _tokens(a)[0]
    assert a.invoke("trigger_pdu_session_release",
                    {"supi_token": t, "pdu_session_id": 1, "operator_authorization": AUTH})["verified"]
    b = _gw(core, shared_state=shared)        # a different agent session
    tb = _tokens(b)[0]                        # b mints its own token for the same SUPI
    out = b.invoke("trigger_pdu_session_release",
                   {"supi_token": tb, "pdu_session_id": 1, "operator_authorization": AUTH})
    assert out["status"] == "blocked" and out["violation"] == "fsm-out-of-state", out


def test_taint_stays_per_session_under_shared_state():
    shared = SharedCoreState()
    a = _gw(FakeCore(), shared_state=shared)
    a.taint.tainted_active = True
    b = _gw(FakeCore(), shared_state=shared)
    assert not b.taint.tainted_active


# --------------------------------------------------------------------------- #
# 3. post-release probes fail closed
# --------------------------------------------------------------------------- #
class _Resp:
    def __init__(self, code):
        self.status_code = code
        self.ok = 200 <= code < 300
        self.text = ""

    def json(self):
        return {"Supi": SUPIS[0]}


def _with_wc_status(code, fn):
    orig = cs.wc_get
    cs.wc_get = lambda path: _Resp(code)
    try:
        return fn()
    finally:
        cs.wc_get = orig


def test_smf_probe_counts_only_404_as_gone():
    probe = lambda: cs.smf_context_gone("urn:uuid:x")  # noqa: E731
    assert _with_wc_status(404, probe) is True
    assert _with_wc_status(200, probe) is False
    for code in (401, 403, 500, 502):
        assert _with_wc_status(code, probe) is None, code


def test_amf_probe_never_reports_gone_on_error():
    orig = cs.registered_ue_context
    try:
        for status, sessions, want in [(404, [], True), (200, [], True),
                                       (200, [{"id": 1}], False), (500, [], None), (401, [], None)]:
            cs.registered_ue_context = lambda supi, s=status, p=sessions: {
                "registered": s == 200, "pdu_sessions": p, "http_status": s}
            assert cs.amf_session_gone(SUPIS[0], 1) is want, (status, sessions)
    finally:
        cs.registered_ue_context = orig


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print(f"[OK] {name}")
    print("\nALL HARDENING TESTS PASSED")
