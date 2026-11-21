# Design — Threat Model and the Three Layers

Why the gateway looks the way it does. For the function-by-function path, see
[END_TO_END_FLOW.md](END_TO_END_FLOW.md); for the numbers, see [RESULTS.md](../evaluation/RESULTS.md).
Back to the [README](../../README.md).

---

## Threat model

| | |
|---|---|
| **Attacker controls** | The agent's untrusted inputs: alert logs, tenant tickets, telemetry |
| **Attacker cannot** | Touch the gateway, the free5GC core, or its configuration |
| **Agent** | Assumed fully compromised: it obeys any injected directive |
| **Enforcement point** | The gateway, never the agent |

The agent is the thing being defended, not trusted. The single question the
project asks is: *can the defense stop a hijacked agent from doing real damage to
the core?*

## The seam

The agent only ever calls `ToolClient.invoke(name, args)`
([agent/tool_client.py](../../agent/tool_client.py)). Swapping `LocalToolClient` for
`GatewayToolClient` inserts the whole defense **without changing the agent**, and
lets the ablation study toggle layers one at a time.

## The three layers, and why each is needed

- **L1 — Identifier Tokenizer.** Even a fully compromised agent only ever holds
  opaque tokens, so anything it exfiltrates is a meaningless string, and
  *identifier leakage = 0%*. It also rejects raw SUPIs injected through logs.
  Following CaMeL, this layer removes the *capability* to touch the secret instead of relying
  on the model to resist injection.
- **L2 — Provenance / Taint.** Content from an untrusted source may not drive a
  high-risk state change without operator authorization. This blocks the injected
  DoS and records which source tainted the call.
- **L3 — Procedure-Aware Verifier.** Every call, including trusted and
  operator-authorized ones, must follow the TS 23.502 PDU-session state machine
  and stay within rate limits. This blocks out-of-order operations (double or
  no-context release) and control-plane DoS (bulk teardown).

**Key point: L3 does not depend on verifying authorization.** When an authorization
is forged or stolen, or a trusted insider makes a mistake, L1 and L2 cannot tell. L3
still *bounds the damage* by rate (a cap on blast radius) and *fully blocks*
procedure-illegal operations through the FSM. It is the backstop that holds after the
provenance/authorization line is defeated. DOS-02 demonstrates exactly this
(see [END_TO_END_FLOW.md §10](END_TO_END_FLOW.md)).

Each layer closes a distinct attack class. The ablation (removing one layer at a
time) shows that none of them is redundant.

| Layer | Mechanism | Stops | Property protected |
|---|---|---|---|
| L1 | SUPI ⇄ opaque token at the boundary | ENUM-01 | Confidentiality |
| L2 | Taint from `get_alert_logs` to high-risk sinks | DOS-01 | Source integrity |
| L3 | TS 23.502 FSM + rate, binds all callers | DOS-02 | Procedure integrity |

## Policy as data

The layers are not hard-wired. `PolicyEngine` ([gateway/policy.py](../../gateway/policy.py))
compiles `config.yaml` → `gateway.policy` into one ordered check chain per tool.
Adding a tool, a procedure or a threshold is a config change. The proof is in
[GENERALITY_PROOF.md](../evaluation/GENERALITY_PROOF.md).

---

## L3 — current scope

L3 currently enforces one procedure live, **PDU-session release**
(`trigger_pdu_session_release`), with two checks on every caller:

- **FSM / ordering:** an already-`RELEASED` session cannot be released again, which
  is a hard block (TS 23.502 §4.3.4).
- **Rate / volume:** at most `max` releases per sliding window, which caps bulk teardown.

State is learned from results already crossing the gateway (`query_subscriber_session`
→ `ACTIVE`, a confirmed release → `RELEASED`). `core_precheck` adds one
gateway-initiated core lookup on high-risk calls. The offline tests also run the same engine on a
second 5G procedure (registration / deregistration) and on a non-5G one.

## Roadmap (future work)

1. **Full PDU-session FSM:** add establishment and modification (TS 23.502
   §4.3.2–4.3.3) live, not only release.
2. **More high-risk sinks:** bring `modify_slice_quota` and other state-changing
   operations under the same FSM + rate framework.
3. **Replay / freshness:** reject replayed (even validly signed) release messages
   with a nonce, timestamp or idempotency key.
4. **Finer policy:** per-tenant / per-slice rate limits and adaptive thresholds
   (a learned "normal" rate) instead of one global cap.
5. **State reconciliation:** periodically reconcile the gateway FSM with real core
   state, so it does not drift when a session is released by another path.
6. **Capability-bound authorization:** replace the plaintext
   `operator_authorization` with a gateway-verifiable *signed* capability whose
   scope covers the procedure and volume.
7. **L2 hardening:** treat an `operator_authorization` value that appeared in
   untrusted content as tainted, so DOS-02 is also caught on the provenance side.
8. **Real LLM agent:** replace the scripted worst-case agent with a real model
   and measure baseline ASR (not implemented). The advisor ruled this
   optional for the course on 2026-11-18.
