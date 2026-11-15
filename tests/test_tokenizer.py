"""
tests/test_tokenizer.py — Layer 1 Identifier Tokenizer (offline, no live core)
==============================================================================
Verifies the gateway's SUPI opacity guarantee without needing free5GC running.

Run directly:         python3 tests/test_tokenizer.py
Run with pytest:      pytest tests/test_tokenizer.py
"""

import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from gateway.tokenizer import IdentifierTokenizer

SUPI_RE = re.compile(r"imsi-\d{15}")

# A real free5GC list_subscribers result, as the core returns it.
CORE_RESULT = {
    "status": "ok",
    "source": "free5GC WebConsole REST API",
    "count": 3,
    "subscribers": [
        {"ueId": "imsi-208930000000001", "plmnID": "20893"},
        {"ueId": "imsi-208930000000002", "plmnID": "20893"},
        {"ueId": "imsi-208930000000003", "plmnID": "20893"},
    ],
}


def test_no_raw_supi_reaches_agent():
    tk = IdentifierTokenizer()
    agent_view = tk.tokenize(CORE_RESULT)
    assert not SUPI_RE.findall(json.dumps(agent_view)), "raw SUPI leaked to agent"
    assert agent_view["subscribers"][0]["ueId"].startswith("token_sub_")


def test_non_identifier_fields_preserved():
    tk = IdentifierTokenizer()
    agent_view = tk.tokenize(CORE_RESULT)
    assert agent_view["subscribers"][0]["plmnID"] == "20893"


def test_token_is_stable_per_supi():
    tk = IdentifierTokenizer()
    assert tk.tokenize_text("imsi-208930000000001") == tk.tokenize_text("imsi-208930000000001")


def test_round_trip_token_to_real_supi():
    tk = IdentifierTokenizer()
    tok = tk.tokenize(CORE_RESULT)["subscribers"][0]["ueId"]
    restored = tk.detokenize({"supi_token": tok, "pdu_session_id": 1})
    assert restored["supi_token"] == "imsi-208930000000001"


def test_bare_15_digit_supi_tokenized():
    tk = IdentifierTokenizer()
    out = tk.tokenize_text("dump 208930000000009 now")
    assert "208930000000009" not in out and "token_sub_" in out


def test_unknown_token_left_untouched():
    tk = IdentifierTokenizer()
    assert tk.detokenize_text("token_sub_ffffff") == "token_sub_ffffff"


# --- Layer 1 argument policy (proposal slide 6) ---------------------------- #
from gateway.mcp_gateway import GatewayToolClient
from agent.tool_client import LocalToolClient


def _gw_with_known_token():
    """Gateway whose tokenizer has already issued a token for SUPI ...001.
    `seen` captures the supi the INNER tool received (post-detokenize)."""
    seen = {}

    def fake_list(**_):
        return {"status": "ok", "count": 1,
                "subscribers": [{"ueId": "imsi-208930000000001", "plmnID": "20893"}]}

    def fake_release(**kw):
        seen["supi_token"] = kw.get("supi_token")
        return {"status": "ok", "verified": True, "supi": kw.get("supi_token")}

    inner = LocalToolClient({"list_subscribers": fake_list,
                             "trigger_pdu_session_release": fake_release})
    gw = GatewayToolClient(inner)
    tok = gw.invoke("list_subscribers", {})["subscribers"][0]["ueId"]  # mints the token
    return gw, tok, seen


def test_valid_token_arg_passes():
    gw, tok, seen = _gw_with_known_token()
    out = gw.invoke("trigger_pdu_session_release", {"supi_token": tok, "pdu_session_id": 1})
    assert out["status"] == "ok"
    # the CORE saw the real SUPI (detokenized on the way in)...
    assert seen["supi_token"] == "imsi-208930000000001"
    # ...but the AGENT only ever sees the token back (re-tokenized on the way out)
    assert out["supi"] == tok


def test_raw_supi_arg_blocked():
    gw, _, seen = _gw_with_known_token()
    out = gw.invoke("trigger_pdu_session_release",
                    {"supi_token": "imsi-208930000000001", "pdu_session_id": 1})
    assert out["status"] == "blocked" and out["layer"] == "L1"
    assert "supi_token" not in seen  # the core was never reached


def test_unknown_token_arg_blocked():
    gw, _, _ = _gw_with_known_token()
    out = gw.invoke("trigger_pdu_session_release",
                    {"supi_token": "token_sub_deadbe", "pdu_session_id": 1})
    assert out["status"] == "blocked" and out["layer"] == "L1"


if __name__ == "__main__":
    tk = IdentifierTokenizer()
    print("=== What the AGENT sees (tokenized) ===")
    print(json.dumps(tk.tokenize(CORE_RESULT), indent=2))
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print(f"[OK] {name}")
    print("\nALL TOKENIZER TESTS PASSED")
