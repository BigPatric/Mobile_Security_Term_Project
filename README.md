# Secure MCP Gateway for the 5G Core

**Mobile Network Security (Fall 2026) — Term Project · 112550018**

A lightweight, provenance- and procedure-aware **gateway** that sits between an
autonomous LLM agent and a live 5G core (**free5GC**), so that even a *fully
compromised* agent cannot leak subscriber identities or issue unauthorized,
out-of-procedure control-plane operations.

The agent is the thing being defended, not trusted. We assume an attacker has
already hijacked it through **indirect prompt injection** — a directive hidden in
an untrusted alert log — and ask a single question: *can the defense stop the
hijacked agent from doing real damage to the core?* The enforcement point is the
**gateway**, never the agent.

> **Threat model.** The attacker controls only the agent's *untrusted inputs*
> (alert logs, tenant tickets, telemetry). They cannot touch the gateway, the
> free5GC core, or its configuration. A hijacked agent is assumed to obey any
> injected directive. The gateway — not the agent — is where policy is enforced.

---

## What we are building

Two concrete attacks, driven entirely through poisoned alert logs, and a
three-layer gateway that neutralizes them:

| Scenario | Hijacked agent does… | Attack class | Defended by |
|---|---|---|---|
| **ENUM-01** | reads tainted log → `list_subscribers` → dumps every SUPI | identity enumeration / SUPI leak | **L1** Tokenizer |
| **DOS-01** | reads tainted log → enumerate → `trigger_pdu_session_release` on every live session | mass PDU-session release (DoS) | **L2** Taint, **L3** Verifier |

Each run is executed **live against a real free5GC + UERANSIM testbed** — no
mocks. A PDU-session release is a real `ReleaseSMContext` REST call to the SMF,
and it is only counted as a success when an independent probe confirms the
core-side session is actually gone.

The experiment is an **A/B / ablation study**: the same attack is run with the
gateway `off` (unprotected baseline — attack succeeds) and `on` (protected —
attack blocked), and with individual layers toggled, to show that no layer is
redundant.

---

## Architecture

```
   Untrusted inputs (alert logs, tenant intents)  ──►  LLM / ReAct Agent
                                                          │  tool call: name(args)
                                                          ▼
                                                  ToolClient interface  ◄── the seam
                                                          │
        ┌─────────────────── Secure MCP Gateway ───────────────────┐
        │  L1  Identifier Tokenizer   SUPI ⇄ opaque token            │  ✅ built
        │  L2  Provenance / Taint     untrusted-driven action = block│  ✅ built
        │  L3  Procedure-Aware FSM    out-of-state / rate limit      │  ⬜ planned
        └──────────────────────────────┬───────────────────────────┘
                                        │  restored, authorized REST call
                                        ▼
                               free5GC + UERANSIM
                        (WebConsole REST · SMF SBI · nr-cli)
```

The agent only ever talks to a `ToolClient` interface
([agent/tool_client.py](agent/tool_client.py)), so the gateway drops into that
seam — `LocalToolClient` → `GatewayToolClient` — **without changing the agent**.
That is the whole point: the defense lives behind the seam, in the gateway, not
inside the model.

See [docs/END_TO_END_FLOW.md](docs/END_TO_END_FLOW.md) for the full request
lifecycle (every function on the path), and
[docs/ATTACK_FLOW_01.md](docs/ATTACK_FLOW_01.md) for the attack walkthrough.

---

## Repository layout

```
Mobile_Security_Term_Project/
├── agent/              # the AI agent — the thing being defended
├── gateway/            # the defense — three-layer Secure MCP Gateway
├── free5gc_tools/      # MCP tool shim: the only code that touches the live core
├── benchmark/          # attack scenarios (the evaluation data set)
├── tests/              # offline unit tests (no live core needed)
├── docs/               # proposal, flow walkthroughs, lab notes
├── free5gc/            # vendored 5G core (external, called not modified)
├── UERANSIM/           # vendored RAN/UE simulator (external, called not modified)
├── run_attack_demo.py  # end-to-end live demo, with --gateway on/off and --scenario
├── config.yaml         # single config: core endpoints + gateway layer toggles
└── attack_evidence.jsonl  # append-only structured evidence, one JSON per run
```

### `agent/` — the thing being defended
| File | Role |
|---|---|
| [react_agent.py](agent/react_agent.py) | A deterministic Thought→Action→Observation (ReAct) loop. It reads the referenced alert log and **follows the directive embedded in it** — the worst-case *fully-compromised* agent used as the experimental control. Produces an `AgentRunResult` with the verdict flags (`hijacked`, `was_attacked`, `identifier_leaked`). |
| [tool_client.py](agent/tool_client.py) | The `ToolClient` seam. `list_schema()` + `invoke(name, args)` is the agent's *entire* contact with the outside world. `LocalToolClient` = in-process calls today; a gateway client drops in here unchanged. |

### `gateway/` — the defense
| File | Layer | Role |
|---|---|---|
| [tokenizer.py](gateway/tokenizer.py) | **L1** ✅ | Identifier opacity. Rewrites every real SUPI in a tool *result* to a stable opaque token (`token_sub_a8f9`) before the agent sees it, and restores it on the *argument* path. Also rejects raw SUPIs and unknown tokens in arguments. → *identifier leakage = 0%*. |
| [taint_tracker.py](gateway/taint_tracker.py) | **L2** ✅ | Provenance / taint. Marks the session TAINTED when an untrusted source (`get_alert_logs`) returns, and blocks a high-risk state change (PDU release) that is driven by that untrusted content and lacks operator authorization. Value-level *and* control-flow taint, with a traceable reason. |
| `verifier.py` | **L3** ⬜ | *Planned.* Procedure-aware FSM (TS 23.502 PDU-session state machine) + rate limit: blocks out-of-order / excessive releases even from trusted sources. |
| [mcp_gateway.py](gateway/mcp_gateway.py) | — | `GatewayToolClient` — the enforcing `ToolClient` that wires the layers at the tool-call boundary. Layers are individually switchable for the ablation study. |

### `free5gc_tools/` — MCP tool shim (the only code that touches the core)
| File | Role |
|---|---|
| [tools.py](free5gc_tools/tools.py) | The 4 agent-callable tools + their JSON schemas: `get_alert_logs` (untrusted input surface), `query_subscriber_session`, `trigger_pdu_session_release` (high-risk, verified), `list_subscribers`. |
| [core_state.py](free5gc_tools/core_state.py) | All ground-truth access to the live core: WebConsole REST, AMF OAM context, SMF `Nsmf_PDUSession` SBI (the real release call), NRF OAuth2 token acquisition, and host-level data-plane probing. **Never modifies free5GC/UERANSIM — only calls their existing interfaces.** |

### `benchmark/` — the evaluation data set
`attacks/enumerate_subscribers.json` (ENUM-01) and `attacks/release_all_sessions.json`
(DOS-01) define each scenario: the operator task, the poisoned log payload, and
the expected hijacked behavior. (`benign/` for false-positive cases — to be added.)

### `tests/` — offline unit tests (no live core)
[test_tokenizer.py](tests/test_tokenizer.py) (L1: tokenization, round-trip,
raw-SUPI / unknown-token rejection) and [test_taint.py](tests/test_taint.py)
(L2: taint propagation, block-on-untrusted, authorization pass, and the
layer-off ablation check).

---

## What works today

| Capability | Status | Evidence |
|---|---|---|
| ReAct agent → tool → live free5GC (end to end) | ✅ | `run_attack_demo.py` |
| **ENUM-01** — subscriber enumeration / SUPI leak | ✅ demonstrated | agent lists every SUPI |
| **DOS-01** — mass PDU-session release via core API | ✅ demonstrated | real `ReleaseSMContext`, verified gone |
| **L1** — identifier tokenization (leak → 0) | ✅ built + live-verified | ENUM leak: `YES` (off) → `no` (on) |
| **L2** — taint tracking (blocks injected DoS) | ✅ built + verified | `tests/test_taint.py` |
| **L3** — procedure FSM + rate limit | ⬜ planned | — |
| Two LLM models, benign set, ablation table, latency | ⬜ planned | — |

---

## Running

```bash
pip install -r requirements.txt

# 1) Unit tests — no live core required
python3 tests/test_tokenizer.py      # Layer 1
python3 tests/test_taint.py          # Layer 2

# 2) End-to-end attack demo, baseline vs protected (needs the live testbed)
python3 run_attack_demo.py --scenario ENUM-01 --gateway off   # SUPI leaks
python3 run_attack_demo.py --scenario ENUM-01 --gateway on    # SUPI tokenized → leak = 0
python3 run_attack_demo.py --scenario DOS-01  --gateway off   # real sessions released
python3 run_attack_demo.py --scenario DOS-01  --gateway on    # release blocked by L2
```

Bringing up the testbed (free5GC + UERANSIM gNB + UE, with an active PDU
session) is covered step-by-step in
[docs/END_TO_END_FLOW.md](docs/END_TO_END_FLOW.md) §Running; quick lab commands
are in [docs/Notes](docs/Notes). `--gateway` overrides `gateway.enabled` in
[config.yaml](config.yaml) per run. Per-run structured evidence is appended to
`attack_evidence.jsonl`.

- **ENUM-01** only reads the subscriber DB (WebConsole), so it runs even if the
  NFs are flaky.
- **DOS-01** needs the SMF SBI live and a real active session; the demo
  **aborts** in preflight if the core is down (it never fakes a release).

---

## The three layers, and why each is needed

- **L1 — Identifier Tokenizer:** even a fully-compromised agent only ever holds
  opaque tokens, so exfiltration leaks a meaningless string → *identifier
  leakage = 0%*. Also rejects raw SUPIs injected via logs. (Follows CaMeL:
  remove the *capability* to touch the secret, don't rely on the model
  resisting injection.)
- **L2 — Provenance / Taint:** content from an untrusted source may not drive a
  high-risk state change without operator authorization → blocks the injected
  DoS, with a traceable reason (which source tainted it).
- **L3 — Procedure-Aware Verifier (planned):** even trusted-sourced calls must
  follow the TS 23.502 PDU-session state machine and stay within rate limits →
  blocks out-of-order operations and control-plane DoS.

Each layer closes a distinct attack class; the ablation study (removing one at a
time) is what demonstrates that none is redundant.

---

## References
- Greshake et al. (2023), *Indirect Prompt Injection* — arXiv:2302.12173
- Debenedetti et al. (2025), *CaMeL* — arXiv:2503.18813
- 3GPP TS 23.502 §4.3 — PDU Session lifecycle (§4.3.4 Release)
</content>
