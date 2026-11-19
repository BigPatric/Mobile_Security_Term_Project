# Generality Proof — Why the Gateway Is Not Hard-Coded for Three Attacks

**Updated:** 2026-11-18
**Related:** [../README.md](../../README.md) · [DESIGN.md](../architecture/DESIGN.md) · [END_TO_END_FLOW.md](../architecture/END_TO_END_FLOW.md) · [RESULTS.md](RESULTS.md)
**All evidence is offline, deterministic unit tests:** `python3 tests/test_generality.py`
(14 tests; no live core and no particular testbed size needed).

---

## Claim

The gateway is a **policy-driven, procedure-aware tool-call checking engine**.
The three attacks (ENUM-01 / DOS-01 / DOS-02) are experiments that *show it works*;
its value is that it is **general**: a new procedure, a new tool, or an attack we never
saw requires no engine change.

"General" has three independent meanings, each of which could be refuted separately, so the
proof has three stages. Every claim maps to a running test in `tests/test_generality.py`,
**not a verbal assertion**.

---

## Stage 1 — Composability: protection is data, not code

**Claim:** adding / removing / tuning protection on an existing tool is a config change, not a code
change. The same `PolicyEngine` class, with not one line under `gateway/` changed, enforces different
behavior when only the policy dict changes.

| Test | Shows |
|---|---|
| `test_no_builtin_cap_release_chain_without_rate_passes_bulk` | A release chain of only `[identifier]` → every session is bulk-released. **The rate cap is not built in:** if the policy does not say it, it is not enforced. |
| `test_adding_a_rate_cap_is_pure_config` | **The only difference from the previous test is three lines of policy data** → bulk is capped at 2. |
| `test_tuning_a_threshold_is_pure_config` | Same policy with `max` set to 1 / 3; the cap follows. No code path picks the number; the data does. |
| `test_same_checks_guard_a_different_tool_by_config_only` | Pointing `identifier + rate` at a **read** tool (enumeration throttling) works too. The check code never mentions a tool name. |
| `test_two_tools_can_share_or_separate_budgets_by_config` | The bucket name is a config string: same name → two tools share one budget; different names → independent budgets. |

> The code-level guarantee is in [gateway/checks/base.py](../../gateway/checks/base.py):
> *"checks never filter by tool name themselves — WHICH checks apply to WHICH
> tool is decided by the policy config."*

---

## Stage 2 — Cross-procedure: the fsm / rate engine is not tied to PDU sessions

**Claim:** the same engine can enforce a procedure it has **no built-in knowledge of**, as long as
the procedure is declared as data (states / transitions / observe rules).

| Test | Shows |
|---|---|
| `test_foreign_procedure_fsm_enforced_by_same_engine` | A **deliberately non-5G** `door_lock` procedure (LOCKED/UNLOCKED): unlock before any observation is blocked (`fsm-no-context`) → observing `read_doors` learns LOCKED → one unlock is allowed → a repeated unlock is blocked (`fsm-out-of-state`). **There are no identifiers here (L1/L2 are meaningless and off); only the L3 procedure machinery runs, in a domain it has never seen.** This is the most decisive "not hard-coded" proof. |
| `test_foreign_procedure_rate_cap_by_same_engine` | The same `RateCheck` that bounds the PDU-release blast radius caps bulk door opening, unchanged. Rate limiting is not 5G-specific at all. |
| `test_foreign_procedure_full_cycle_lock_unlock` | Two transitions of the same procedure (unlock / lock) compose into a cycle, each guarded by its own `FsmCheck` event. |
| `test_second_5g_procedure_registration_lifecycle` | A second **real 3GPP** procedure (TS 23.502 registration), with different states (REGISTERED/DEREGISTERED) and a different tool, all declared in config. A double deregister is blocked as out-of-state, fully symmetric with a double PDU release. |
| `test_second_5g_procedure_rate_cap` | A bulk-deregistration DoS on another procedure is capped by the same `RateCheck`. |

> This directly answers advisor question **B1** ("with only one procedure it is easy to call it just a
> rate limit"): procedure awareness holds on **two real 5G procedures plus one fully foreign procedure**.

---

## Stage 3 — Attack-blind: it blocks a class of violations, not three specific attacks

**Claim:** none of the attack variants below is ENUM-01 / DOS-01 / DOS-02, and **no** check was written
or tuned for them, yet the existing fsm / rate / core_precheck rules still block them. The gateway
defends against **a class of procedure-integrity violations**, not against recognized attacks.

| Test (unscripted attack variant) | Blocked by which general rule |
|---|---|
| `test_unscripted_release_of_never_seen_session_blocked_by_fsm` | Releasing a session that was never queried → FSM: no legal transition from UNKNOWN (`fsm-no-context`). |
| `test_unscripted_target_a_nonexistent_session_blocked_by_core_precheck` | A syntactically valid PDU session id that **does not exist** → `core_precheck` asks the core directly and refuses (`core-precheck-failed`); the release never reaches the core. |
| `test_unscripted_forged_auth_bulk_on_a_different_procedure_still_capped` | **The DOS-02 hole moved to a procedure we never wrote an attack for** (UE deregistration): every call carries a forged `operator_authorization`, and `rate` (`exempt_authorized: false`) still caps the bulk. **A forged authorization fools provenance, not procedure-state / count accounting.** |
| `test_unscripted_replay_after_legit_release_blocked_by_fsm` | Replaying the same call after a legitimate release → the FSM has committed RELEASED, so the replay is out-of-state; no replay-specific logic exists. |

---

## Limits of the claim

- **"Pure config" applies only to the protection logic.** fsm / rate / provenance / core_precheck need
  no changes. But letting the agent call a **new core operation** (e.g. a real establishment /
  deregistration) needs a thin tool adapter in `free5gc_tools/`.
  → That decoupling is itself what makes the architecture general:
  **extending protection = changing config; connecting a new core operation = adding a tool adapter.**
- **Rate bounds the blast radius; it does not reach zero.** The calls before the cap still pass, and a
  slow drip deliberately kept under the window is not stopped by rate (inherent to rate limiting).
  FSM ordering violations, however, are **fully blocked** (double / out-of-state release = 0 passes);
  the two complement each other.
- These are **offline, deterministic** proofs (the engine logic is general). Quantified live
  ASR / FP / latency are in [RESULTS.md](RESULTS.md).

---

## Summary

> A new procedure, a new tool, an attack we never thought of: **the gateway code does not change**;
> only the policy data does. That is what general means here.
