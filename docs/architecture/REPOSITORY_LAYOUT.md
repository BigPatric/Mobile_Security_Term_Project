# Repository Layout

What each directory and file is for. For how they call each other at runtime, see
[END_TO_END_FLOW.md](END_TO_END_FLOW.md). Back to the [README](../../README.md).

```
Mobile_Security_Term_Project/
├── agent/              # the AI agent — the thing being defended
├── gateway/            # the defense — three-layer Secure MCP Gateway
├── free5gc_tools/      # MCP tool shim: the only code that touches the live core
├── benchmark/          # attack + benign scenarios, synthetic trace generator
├── tests/              # offline unit / scenario / adversarial tests (no live core)
├── tools/              # experiment runners, sweeps, result aggregation
├── docs/
│   ├── architecture/   # DESIGN, END_TO_END_FLOW, REPOSITORY_LAYOUT (this file)
│   ├── guides/         # RUNNING
│   ├── evaluation/     # RESULTS, EVAL_CURVE, ADVERSARIAL_BOUNDARY, GENERALITY_PROOF
│   └── proposal/       # original proposal PDF
├── free5gc/            # vendored 5G core (external, called not modified)
├── UERANSIM/           # vendored RAN/UE simulator (external, called not modified)
├── run_attack_demo.py  # one live run: --scenario, --gateway on/off/rbac, --layers
├── config.yaml         # single config: core endpoints + gateway policy + layer toggles
├── requirements.txt
├── cleanup.py          # removes __pycache__ directories
├── attack_evidence.jsonl  # (git-ignored) append-only evidence, one JSON per run
└── live_logs/          # (git-ignored) per-cell core / gNB / UE logs from the live matrix
```

---

## `agent/` — the thing being defended

| File | Role |
|---|---|
| [react_agent.py](../../agent/react_agent.py) | A deterministic Thought→Action→Observation (ReAct) loop. It reads the referenced alert log and **follows the directive embedded in it**. This is the worst-case, *fully compromised* agent used as the experimental control. Produces an `AgentRunResult` with the verdict flags (`hijacked`, `was_attacked`, `identifier_leaked`). |
| [tool_client.py](../../agent/tool_client.py) | The `ToolClient` seam. `list_schema()` + `invoke(name, args)` is the agent's *entire* contact with the outside world. `LocalToolClient` makes in-process calls (no defense); the gateway client drops in here unchanged. |

## `gateway/` — the defense

| File | Layer | Role |
|---|---|---|
| [mcp_gateway.py](../../gateway/mcp_gateway.py) | — | `GatewayToolClient`: the enforcing `ToolClient` at the tool-call boundary. Runs detokenize → policy chain → core → observe → tokenize. Block responses are redacted (no raw SUPI). Records every decision (check trace, gateway overhead) for the evidence log. |
| [policy.py](../../gateway/policy.py) | — | **Config-driven policy pipeline.** `PolicyEngine` builds an ordered check chain per tool from `config.yaml` (`gateway.policy`). The first check that blocks stops the call. Bad policies are rejected at build time. |
| [tokenizer.py](../../gateway/tokenizer.py) | **L1** | Identifier opacity. Rewrites every real SUPI in a tool *result* to a stable opaque token (`token_sub_a8f9`) before the agent sees it, and restores it on the *argument* path. |
| [taint_tracker.py](../../gateway/taint_tracker.py) | **L2** | Provenance / taint. Marks the session TAINTED when an untrusted source (`get_alert_logs`) returns, and blocks a high-risk state change driven by that content without operator authorization. Tracks taint at value level and at control-flow level. |
| [verifier.py](../../gateway/verifier.py) | **L3** | Procedure-aware FSM (TS 23.502 PDU-session state machine) + sliding-window rate limit. Binds **every** caller, authorized or not (`exempt_authorized=False`). |
| [procedures.py](../../gateway/procedures.py) | L3 | 3GPP procedure specs as data (PDU-session life-cycle). |
| [checks/](../../gateway/checks/) | L0–L3 | Pluggable checks. None of them filters by tool name; the policy decides which check guards which tool. |

### `gateway/checks/`

| File | Check name | Layer | Role |
|---|---|---|---|
| [base.py](../../gateway/checks/base.py) | — | — | `Check` / `CallContext` interfaces. |
| [identifier.py](../../gateway/checks/identifier.py) | `identifier` | L1 | Rejects raw SUPIs and unknown tokens in arguments. |
| [provenance.py](../../gateway/checks/provenance.py) | `provenance` | L2 | Wraps `taint_tracker.check_sink()`. |
| [fsm.py](../../gateway/checks/fsm.py) | `fsm` | L3 | Out-of-state / no-context transitions. |
| [rate.py](../../gateway/checks/rate.py) | `rate` | L3 | Sliding-window cap per named bucket. |
| [core_precheck.py](../../gateway/checks/core_precheck.py) | `core_precheck` | L3 | Before forwarding, the gateway asks the core itself whether the precondition holds. |
| [allowlist.py](../../gateway/checks/allowlist.py) | `deny` | L0 | Generic deny rule, used to express the RBAC baseline in the same policy language. |

## `free5gc_tools/` — MCP tool shim

| File | Role |
|---|---|
| [tools.py](../../free5gc_tools/tools.py) | The 4 agent-callable tools and their JSON schemas: `get_alert_logs` (untrusted input surface), `list_subscribers`, `query_subscriber_session`, and `trigger_pdu_session_release` (high-risk, verified). |
| [core_state.py](../../free5gc_tools/core_state.py) | All ground-truth access to the live core: WebConsole REST, AMF OAM context, SMF `Nsmf_PDUSession` SBI (the real release call), NRF OAuth2 token, data-plane probing. **Never modifies free5GC/UERANSIM; it only calls their existing interfaces.** |

## `benchmark/` — the evaluation data set

Each JSON file defines one scenario: the operator task, the poisoned log payload,
and the expected hijacked behavior.

| File | Scenario |
|---|---|
| [attacks/enumerate_subscribers.json](../../benchmark/attacks/enumerate_subscribers.json) | ENUM-01: SUPI enumeration |
| [attacks/release_all_sessions.json](../../benchmark/attacks/release_all_sessions.json) | DOS-01: mass PDU-session release |
| [attacks/authorized_bulk_release.json](../../benchmark/attacks/authorized_bulk_release.json) | DOS-02: mass release with forged authorization |
| [benign/](../../benchmark/benign/) | BENIGN-01…04: read-only health checks, an authorized single release, and the same tasks in a tainted session. Used for the false-positive rate. |
| [generator.py](../../benchmark/generator.py) | Synthetic workload generator: intent-labelled benign / malicious traces (incl. legitimate bulk maintenance) for the ASR/FP curve in [EVAL_CURVE.md](../evaluation/EVAL_CURVE.md). Knows nothing about gateway thresholds. |

## `tests/` — offline tests (no live core)

| File | Covers |
|---|---|
| [test_tokenizer.py](../../tests/test_tokenizer.py) | L1: tokenization, round-trip, raw-SUPI / unknown-token rejection |
| [test_taint.py](../../tests/test_taint.py) | L2: taint propagation, block-on-untrusted, authorization pass, layer-off ablation |
| [test_verifier.py](../../tests/test_verifier.py) | L3: FSM ordering and rate cap |
| [test_policy.py](../../tests/test_policy.py) | Pipeline: config-only new procedure, core precheck, redaction, decision trace, allow-list |
| [test_generality.py](../../tests/test_generality.py) | Generality proof (see [GENERALITY_PROOF.md](../evaluation/GENERALITY_PROOF.md)) |
| [test_adversarial.py](../../tests/test_adversarial.py) | Adaptive attackers with a fake clock (see [ADVERSARIAL_BOUNDARY.md](../evaluation/ADVERSARIAL_BOUNDARY.md)) |
| [test_generator.py](../../tests/test_generator.py) | Self-checks for the synthetic workload generator |
| [test_e2e_scenarios.py](../../tests/test_e2e_scenarios.py) | Real agent + real `config.yaml` policy against a fake core, every scenario × mode. Run directly to print the expected-results matrix. |

## `tools/` — experiment runners

| File | Role |
|---|---|
| [run_live_matrix.sh](../../tools/run_live_matrix.sh) | Live experiment runner (root). For every scenario × mode cell, it restarts a fresh core + gNB + N UEs, waits for N active sessions, and runs one demo. |
| [_wait_sessions.py](../../tools/_wait_sessions.py) | Readiness probe used by the matrix runner: blocks until N UEs have an active PDU session. |
| [sweep.py](../../tools/sweep.py) | The same matrix offline, against the fake core → `benchmark/offline_evidence.jsonl`. |
| [eval_curve.py](../../tools/eval_curve.py) | Replays generator traces through the real `PolicyEngine` across a rate-cap sweep → [EVAL_CURVE.md](../evaluation/EVAL_CURVE.md). |
| [dataplane_nat.sh](../../tools/dataplane_nat.sh) | Optional data-plane NAT for the UE pool (`up` / `down` / `status`), so the demo can show ping-before / fail-after evidence (see [END_TO_END_FLOW.md §8.2](END_TO_END_FLOW.md)). |
| [aggregate.py](../../tools/aggregate.py) | Turns an evidence JSONL into the ASR / leakage / FP / latency / attribution tables in [RESULTS.md](../evaluation/RESULTS.md). |

## Vendored components

`free5gc/` and `UERANSIM/` are upstream projects, vendored so the testbed is
reproducible. Our code **calls** them and never modifies their sources. Project-specific
helpers live in `tools/`, not inside the vendored trees.
