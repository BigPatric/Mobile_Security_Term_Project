"""
tests/test_generator.py — sanity of the synthetic workload + curve harness
===========================================================================
Not a defense test — it checks that the generator + eval replay are themselves
trustworthy, so the ASR/FP curve in tools/eval_curve.py means what it says:

  - with an effectively infinite cap, every malicious bulk fully succeeds and NO
    benign trace is blocked (FP = 0) — the harness invents no spurious block;
  - tightening the cap raises FP monotonically (legitimate bulk gets caught);
  - slow-drip evades a windowed cap at EVERY cap (the honest residual risk);
  - out-of-state double release is blocked at EVERY cap (FSM, timing-free).

Run directly:   python3 tests/test_generator.py
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "tools"))

from benchmark.generator import generate
from eval_curve import evaluate


def test_generator_shape():
    ts = generate()
    assert len(ts) >= 12
    assert {t["intent"] for t in ts} == {"benign", "malicious"}
    assert all(t["calls"] for t in ts)


def test_infinite_cap_attacks_succeed_and_no_false_positive():
    [r] = evaluate([10_000])
    assert r["asr"] == 1.0, r              # every DoS tears down > ALLOWED_BLAST
    assert r["fp"] == 0.0, r               # no legitimate trace is blocked
    assert r["oos_blocked"] is True, r     # ordering is still enforced


def test_fp_is_monotonic_in_cap():
    rows = evaluate([1, 2, 3, 5, 8])
    fps = [r["fp"] for r in rows]
    assert fps == sorted(fps, reverse=True), fps      # tighter cap -> >= FP
    assert fps[0] > 0 and fps[-1] == 0.0, fps         # a real trade-off exists


def test_slow_drip_evades_at_every_cap():
    for r in evaluate([1, 2, 3, 8]):
        n, d = r["drip"].split("/")
        assert n == d, r                   # released == targeted: cap never bit


def test_out_of_state_blocked_at_every_cap():
    assert all(r["oos_blocked"] for r in evaluate([1, 2, 3, 8, 10_000]))


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print(f"[OK] {name}")
    print("\nALL GENERATOR / CURVE SANITY TESTS PASSED")
