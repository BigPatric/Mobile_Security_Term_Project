# Adaptive Attackers — Where the Defense Stops Holding

**Updated:** 2026-11-23
**Evidence:** `python3 tests/test_adversarial.py` (5 offline, deterministic, time-controlled tests),
plus the capability tests in `tests/test_capability.py` and `tests/test_e2e_scenarios.py`; all pass.
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
| Burst with forged authorization, signed L2 | ✅ **Blocked** (0 released) | L2: the ticket is not a gateway-signed capability | `test_forged_authorization_string_blocked`, `test_full_gateway` |
| Burst with forged authorization, L2 off or claim-only | ✅ **Blocked** (capped) | L3 rate (ignores the authorization claim) | `test_forged_auth_burst_still_capped_by_rate` |
| Tampered / re-scoped / expired / other-gateway capability | ✅ **Blocked** | L2 signature, scope and expiry checks | `test_tampered_fields_rejected`, `test_wrong_tool_rejected`, `test_expired_rejected`, `test_capability_from_another_gateway_rejected` |
| Reusing a genuine capability beyond its budget | ✅ **Blocked** after `max_uses` | L2 nonce use count | `test_gateway_copied_capability_bounded_by_max_uses` |
| Genuine over-scoped capability held by a hijacked agent | ✅ **Blocked** (capped) | L3 rate (L2 accepts the valid capability) | `test_genuine_overscoped_capability_still_capped_by_l3` |
| Double / out-of-state release (slow) | ✅ **Blocked** (time-independent) | L3 FSM ordering | `test_slow_drip_double_release_still_blocked_by_fsm` (live, without the gateway, the SMF answers a second release with HTTP 404, so this variant is harmless on free5GC: [RESULTS.md §5](RESULTS.md)) |
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
   A forged authorization no longer fools L2 (signed capabilities), but a *genuine* one that is
   misused still passes L2 and is bounded only by rate/FSM (L3); slow drip evades rate but not FSM.
   The evasions are orthogonal, which is direct evidence for defense in depth:
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
- **Genuine capability spent on the attacker's targets:** a capability is scoped to a tool and a use
  budget, not to a subscriber or session. Binding it to arguments would close this; until then the
  budget and L3's rate cap bound it.
- Both are **new rules / config changes** on the existing policy pipeline, with no engine change,
  consistent with the argument in [GENERALITY_PROOF.md](GENERALITY_PROOF.md).
