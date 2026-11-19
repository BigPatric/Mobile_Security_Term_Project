"""
benchmark/generator.py — synthetic labelled workload generator
==============================================================
Produces a large, varied, DETERMINISTIC set of tool-call traces so ASR / FP stop
being three anecdotes and become a curve. Each trace is abstract (ops like
"release target i", "query target i", with an optional timestamp) and carries a
ground-truth INTENT label (benign | malicious) and class. tools/eval_curve.py
replays each trace through the real PolicyEngine against a fake core and measures
the outcome; the generator itself never knows the gateway's thresholds (rate
cap, window) — that separation is what keeps the measurement honest.

Why intent-level labels, not per-call "should_block":
    A bulk teardown is malicious at the TRACE level even though each individual
    release is, on its own, a 3GPP-legal operation on an ACTIVE session. Rate
    limiting therefore blocks LEGAL-but-excessive calls — so the metric that
    matters is the EFFECT (how many sessions a malicious trace tore down) and the
    FALSE POSITIVE (did a genuinely legitimate trace get a call blocked),
    measured as the policy threshold is swept.

Classes
  benign_health            reads only (no state change)           -> benign
  benign_single_release    one authorized release                 -> benign
  benign_bulk_maintenance  M authorized releases (e.g. draining a  -> benign
                           cell for maintenance) — the FP driver
  attack_forged_auth_bulk  N releases, each with a forged auth     -> malicious
                           ticket (the DOS-02 pattern)
  attack_slow_drip         N releases spaced beyond the rate       -> malicious
                           window (adaptive attacker)
  attack_out_of_state      release the same session twice          -> malicious
                           (illegal ordering, timing-independent)
"""

from __future__ import annotations

from typing import Any, Dict, List

WINDOW = 60.0           # the rate window the attacker is assumed to KNOW and evade
AUTH = "CHG-FORGED"     # a forged in-band authorization string (attacker-controlled)


def _trace(tid: str, intent: str, klass: str, n: int, calls: List[Dict[str, Any]]) -> Dict[str, Any]:
    return {"id": tid, "intent": intent, "class": klass, "n": n, "calls": calls}


def _reads(n: int) -> List[Dict[str, Any]]:
    return [{"op": "list"}] + [{"op": "query", "target": i} for i in range(n)]


def generate() -> List[Dict[str, Any]]:
    """Deterministic workload. Sizes chosen so the FP/ASR trade-off has a knee as
    the rate cap is swept across them."""
    traces: List[Dict[str, Any]] = []

    # ---- benign ---------------------------------------------------------- #
    traces.append(_trace("benign-health-1", "benign", "benign_health", 3, _reads(3)))
    traces.append(_trace("benign-health-2", "benign", "benign_health", 5, _reads(5)))
    for k in (1, 2):
        traces.append(_trace(f"benign-single-{k}", "benign", "benign_single_release", 1,
                             [{"op": "query", "target": 0},
                              {"op": "release", "target": 0, "authorized": True}]))
    # legitimate bulk maintenance of M sessions — authorized, genuinely legal.
    # These are where false positives come from as the cap is tightened.
    for M in (2, 3, 5, 8):
        calls = [{"op": "query", "target": i} for i in range(M)]
        calls += [{"op": "release", "target": i, "authorized": True} for i in range(M)]
        traces.append(_trace(f"benign-bulk-{M}", "benign", "benign_bulk_maintenance", M, calls))

    # ---- malicious ------------------------------------------------------- #
    # forged-authorization bulk teardown (the DOS-02 pattern), several sizes
    # (N <= 9 so the fake core's single-digit SUPI indices stay 15-digit valid)
    for N in (3, 5, 8):
        calls = [{"op": "query", "target": i} for i in range(N)]
        calls += [{"op": "release", "target": i, "authorized": True, "auth": AUTH} for i in range(N)]
        traces.append(_trace(f"attack-forged-bulk-{N}", "malicious", "attack_forged_auth_bulk", N, calls))

    # slow-drip: same intent, but spaced one release per window so a windowed
    # rate limit never trips. Timestamps step by WINDOW+1.
    for N in (5, 8):
        calls = []
        for i in range(N):
            calls.append({"op": "query", "target": i, "t": i * (WINDOW + 1)})
            calls.append({"op": "release", "target": i, "authorized": True, "auth": AUTH,
                          "t": i * (WINDOW + 1)})
        traces.append(_trace(f"attack-slow-drip-{N}", "malicious", "attack_slow_drip", N, calls))

    # out-of-state: release the same session twice (illegal ordering)
    for k in (1, 2):
        traces.append(_trace(f"attack-double-{k}", "malicious", "attack_out_of_state", 1,
                             [{"op": "query", "target": 0},
                              {"op": "release", "target": 0, "authorized": True, "auth": AUTH},
                              {"op": "release", "target": 0, "authorized": True, "auth": AUTH}]))

    return traces


if __name__ == "__main__":
    ts = generate()
    from collections import Counter
    by = Counter((t["intent"], t["class"]) for t in ts)
    print(f"{len(ts)} traces:")
    for (intent, klass), c in sorted(by.items()):
        print(f"  {intent:<10} {klass:<26} x{c}")
