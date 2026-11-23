# Design — Threat Model and the Three Layers

Why the gateway looks the way it does. For the function-by-function path, see
[END_TO_END_FLOW.md](END_TO_END_FLOW.md); for the numbers, see [RESULTS.md](../evaluation/RESULTS.md).
Back to the [README](../../README.md).

---

## Threat model

| | |
|---|---|
| **Attacker controls** | The agent's untrusted inputs: alert logs, tenant tickets, telemetry |
| **Attacker cannot** | Touch the gateway, the free5GC core, or its configuration; obtain the gateway secret or a capability the operator did not issue |
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
  *identifier leakage = 0%*. Tokens are HMAC-SHA256 of the SUPI under a gateway
  secret ([gateway/secret.py](../../gateway/secret.py)), so they cannot be mapped back
  by hashing a PLMN's SUPI space offline. It also rejects raw SUPIs injected through logs.
  Following CaMeL, this layer removes the *capability* to touch the secret instead of relying
  on the model to resist injection.
- **L2 — Provenance / Taint.** Content from an untrusted source may not drive a
  high-risk state change without operator authorization. This blocks the injected
  DoS and records which source tainted the call. The authorization must be a
  **capability the gateway signed** ([gateway/capability.py](../../gateway/capability.py)):
  HMAC over tool, use budget, expiry and nonce, minted only on the trusted operator-task
  path. A ticket string copied out of an untrusted log does not verify, so it cannot
  launder a tainted call. (The original claim-only check, where any non-empty string
  passed, is still available as `verify_authorization: false` for comparison.)
- **L3 — Procedure-Aware Verifier.** Every call, including trusted and
  operator-authorized ones, must follow the TS 23.502 PDU-session state machine
  and stay within rate limits. This blocks out-of-order operations (double or
  no-context release) and control-plane DoS (bulk teardown).

**Key point: L3 does not depend on verifying authorization.** Signed capabilities
stop a *forged* authorization at L2, but not a *genuine* one that is misused: a broad
capability held by an agent that is later hijacked, a stolen one, or an insider's
mistake. L2 accepts those, because they verify. L3 still *bounds the damage* by rate
(a cap on blast radius) and *fully blocks* procedure-illegal operations through the
FSM. DOS-02 showed this live with the claim-only L2 (3 of 9 sessions, see
[END_TO_END_FLOW.md §10](END_TO_END_FLOW.md)); with signed L2 the same holds offline for
a hijacked agent holding a real 9-use capability (`test_genuine_overscoped_capability_still_capped_by_l3`).

Each layer closes a distinct attack class:

| Layer | Mechanism | Stops | Property protected |
|---|---|---|---|
| L1 | SUPI ⇄ keyed opaque token at the boundary | ENUM-01 | Confidentiality |
| L2 | Taint from `get_alert_logs` to high-risk sinks, unless a gateway-signed capability verifies | DOS-01, DOS-02 (forged ticket) | Source integrity |
| L3 | TS 23.502 FSM + rate, binds all callers | genuine-but-misused authorization, double release; DOS-02 under claim-only L2 | Procedure integrity |

With the claim-only L2, removing any one layer let one of the three live attacks through.
With signed L2, L1+L2 alone stops all three live attacks; L3's role is the misuse and
ordering cases above, which the live scenarios do not include.

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
  is a hard block (TS 23.502 §4.3.4). Measured live, a second release is harmless on
  free5GC (the SMF answers HTTP 404), so for release this shows the mechanism rather
  than preventing damage; its value is in procedures where a wrong order does harm.
- **Rate / volume:** at most `max` releases per sliding window (3 per 60 s), which caps
  bulk teardown. The value is an operator-tunable parameter, not derived from a standard.
  Its cost is measured live: an authorized bulk drain (BENIGN-05) is blocked after 3
  releases, because rate cannot tell legitimate bulk from malicious bulk.

State is learned from results already crossing the gateway (`query_subscriber_session`
→ `ACTIVE`, a confirmed release → `RELEASED`). `core_precheck` adds one
gateway-initiated core lookup on high-risk calls (three WebConsole REST calls, median
13 ms live). The offline tests also run the same engine on a
second 5G procedure (registration / deregistration) and on a non-5G one.

## Roadmap (future work)

1. **Full PDU-session FSM:** add establishment and modification (TS 23.502
   §4.3.2–4.3.3) live, not only release.
2. **More high-risk sinks:** bring `modify_slice_quota` and other state-changing
   operations under the same FSM + rate framework.
3. **Replay / freshness:** release replays are already caught by the FSM, and
   capability replays by the nonce use count; an idempotency key per release
   request would cover replays across gateway restarts.
4. **Finer policy:** per-tenant / per-slice rate limits and adaptive thresholds
   (a learned "normal" rate) instead of one global cap, and a path for legitimate bulk
   work, e.g. a rate check that honors the use budget of a signed capability.
   Cumulative budgets would also cover slow drip.
5. **State reconciliation:** periodically reconcile the gateway FSM with real core
   state, so it does not drift when a session is released by another path.
6. **Narrower capabilities (signed capabilities are done):** capabilities are
   scoped to a tool, a use budget and an expiry. Binding them to specific
   arguments (subscriber, session) would stop a hijacked agent from spending a
   genuine capability on targets of the attacker's choosing; persisting use counts
   would let them survive a gateway restart or span several gateway instances; and
   the operator path that requests them should itself be authenticated (in the
   harness it is simply trusted).
7. **Direct precheck:** query the AMF OAM directly instead of through the free5GC
   WebConsole, which leaks per request (see [RESULTS.md §4](../evaluation/RESULTS.md)).
8. **Real LLM agent:** replace the scripted worst-case agent with a real model
   and measure baseline ASR (not implemented). The advisor ruled this
   optional for the course on 2026-11-18.
