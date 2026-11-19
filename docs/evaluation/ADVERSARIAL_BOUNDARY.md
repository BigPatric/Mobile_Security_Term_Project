# Adaptive Attackers — Where the Defense Stops Holding

**Updated:** 2026-11-19
**Evidence:** `python3 tests/test_adversarial.py` (5 offline, deterministic, time-controlled tests; all pass).
**Related:** [RESULTS.md](RESULTS.md) · [GENERALITY_PROOF.md](GENERALITY_PROOF.md) · [END_TO_END_FLOW.md](../architecture/END_TO_END_FLOW.md)

The three demo attacks are one-shot "do the damage now" attacks. A real attacker
**adapts**. This document lets the attacker adapt (spread out, forge, reorder, switch
buckets) and **records honestly whether each variant is blocked or gets through**.
The goal is not "block everything" but a **precise boundary**. Time is simulated with
an injected fake clock, so "slow" attacks need no real waiting and results are deterministic.

---

## Result matrix

| Attack variant | Outcome | Decided by | Test |
|---|---|---|---|
| Burst bulk teardown | ✅ **Blocked** (capped) | L3 rate (bounds the blast radius) | `test_burst_bulk_is_capped_by_rate` |
| Burst with forged authorization | ✅ **Blocked** | L3 rate (ignores the authorization claim) | `test_forged_auth_burst_still_capped_by_rate` |
| Double / out-of-state release (slow) | ✅ **Blocked** (time-independent) | L3 FSM ordering | `test_slow_drip_double_release_still_blocked_by_fsm` |
| **Slow drip: distinct sessions, spread beyond the rate window** | ❌ **Not blocked (residual risk)** | invisible to a windowed rate | `test_slow_drip_across_distinct_sessions_evades_rate` |
| **Spread across separate rate buckets** | ❌ **Not blocked (config-dependent)** | each bucket has its own budget | `test_separate_buckets_let_an_attacker_double_the_budget` |

---

## Conclusions

1. **Rate limiting bounds bursts, not sustained low-rate abuse.**
   If releases are spread beyond the window and each one hits a **different, genuinely
   ACTIVE session**, there is no out-of-state transition to catch and the windowed rate
   never sees a burst, so every call passes. This is an **inherent limit** of rate limiting, not a bug.

2. **FSM ordering constraints are time-independent and cannot be evaded by slow drip.**
   A double / out-of-state release is illegal whenever it happens, so slowing down does not help.

3. **The real floor of the defense is therefore procedure-state consistency (FSM), not rate.**
   A forged authorization fools provenance (L2) but not rate/FSM (L3); slow drip evades rate
   but not FSM. The two evasions are orthogonal, which is direct evidence for defense in depth:
   **source integrity ⟂ procedure integrity**.

4. **Bucket granularity is an explicit policy trade-off.** Putting every teardown-type operation
   in one bucket closes the "spread across buckets" hole; separate buckets leave it open.
   This is a one-line config decision, not a code problem.

---

## Residual risk → future work

- **Cross-session slow drip:** needs a **cumulative / absolute budget** (e.g. "at most M releases
  per N minutes, globally"), or anomaly detection on the fraction of sessions released in a short
  period, to cover the blind spot of a windowed rate.
- **Bucket spreading:** group semantically similar high-risk sinks into the same teardown bucket.
- Both are **new rules / config changes** on the existing policy pipeline, with no engine change,
  consistent with the argument in [GENERALITY_PROOF.md](GENERALITY_PROOF.md).
