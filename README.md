# Secure MCP Gateway for the 5G Core

**Mobile Network Security (Fall 2026) — Term Project · 112550018**

A lightweight, provenance- and procedure-aware **gateway** that sits between an
autonomous LLM agent and a 5G core (**free5GC**), so that even a *fully
compromised* agent cannot leak subscriber identities or issue unauthorized,
out-of-procedure control-plane operations.

> **Threat model.** The attacker controls only the agent's *untrusted inputs*
> (alert logs, tenant tickets), not the gateway or free5GC. A hijacked agent is
> assumed to obey injected directives; the gateway — not the agent — is the
> enforcement point.

---

## Architecture

```
   Untrusted inputs (alert logs, tenant intents)  ──►  LLM / ReAct Agent
                                                          │  tool call: name(args)
                                                          ▼
        ┌─────────────────── Secure MCP Gateway ───────────────────┐
        │  L1  Identifier Tokenizer   SUPI ⇄ opaque token           │  ✅ built
        │  L2  Provenance / Taint     untrusted-driven action = block│  ✅ built
        │  L3  Procedure-Aware FSM    out-of-state / rate limit      │  ⬜ planned
        └──────────────────────────────┬───────────────────────────┘
                                        │  restored, authorized REST call
                                        ▼
                               free5GC + UERANSIM
                        (WebConsole REST · SMF SBI · nr-cli)
```

The agent only ever talks to a `ToolClient` interface, so the gateway drops into
that seam without changing the agent. See [agent/tool_client.py](agent/tool_client.py).

---

## Repository layout

| Path | Role |
|---|---|
| **`agent/`** | The AI agent (the thing being defended). `react_agent.py` is a deterministic ReAct loop that reads an alert log and follows embedded directives — the worst-case *fully-compromised* agent used as the experimental control. `tool_client.py` is the `ToolClient` seam the gateway plugs into. |
| **`gateway/`** | The defense. `tokenizer.py` = **Layer 1** (identifier opacity + raw-SUPI rejection); `taint_tracker.py` = **Layer 2** (provenance / taint tracking); `verifier.py` = **Layer 3** (procedure FSM + rate limit, *planned*); `mcp_gateway.py` = the `GatewayToolClient` that enforces the layers at the tool-call boundary. |
| **`free5gc_tools/`** | MCP tool shim. `tools.py` exposes 4 agent-callable tools (`get_alert_logs`, `query_subscriber_session`, `trigger_pdu_session_release`, `list_subscribers`). `core_state.py` holds all ground-truth access to the live core (WebConsole REST, SMF `Nsmf` SBI, data-plane probe). **Never modifies free5GC/UERANSIM — only calls their existing interfaces.** |
| **`benchmark/`** | Evaluation data set. `attacks/*.json` define attack scenarios (ENUM-01, DOS-01) with the injected log payloads. (`benign/` for false-positive cases — to be added.) |
| **`tests/`** | Offline unit tests (no live core needed). `test_tokenizer.py` (Layer 1), `test_taint.py` (Layer 2), including per-layer ablation checks. |
| **`docs/`** | Design + reference material: the proposal PDF, the implementation guide, `ATTACK_FLOW_01.md` (attack walkthrough), and lab `Notes`. |
| **`free5gc/`**, **`UERANSIM/`** | Vendored 5G core and RAN/UE simulator (the live testbed). External components, called but not modified. |
| `run_attack_demo.py` | End-to-end attack demo against the live core, with `--gateway on/off` for A/B comparison and `--scenario ENUM-01|DOS-01`. |
| `config.yaml` | Single config: agent mode, core endpoints, and `gateway.layers` toggles for the ablation study. |
| `requirements.txt` · `cleanup.py` | Python deps (`requests`, `PyYAML`, `colorama`) · a `__pycache__` cleaner. |

---

## What works today

| Capability | Status | Evidence |
|---|---|---|
| ReAct agent → tool → live free5GC (end to end) | ✅ | `run_attack_demo.py` |
| **ENUM-01** — subscriber enumeration / SUPI leak | ✅ demonstrated | agent lists every SUPI |
| **DOS-01** — mass PDU-session release via core API | ✅ demonstrated | real `ReleaseSMContext` on free5GC |
| **Layer 1** — identifier tokenization (leak → 0) | ✅ built + live-verified | ENUM leak: `YES` (off) → `no` (on) |
| **Layer 2** — taint tracking (blocks injected DoS) | ✅ built + verified | `tests/test_taint.py` |
| **Layer 3** — procedure FSM + rate limit | ⬜ planned | — |
| Two LLM models, benign set, ablation table, latency | ⬜ planned | — |

---

## Running

```bash
# Unit tests (no live core required)
python3 tests/test_tokenizer.py      # Layer 1
python3 tests/test_taint.py          # Layer 2

# End-to-end attack demo, baseline vs protected
python3 run_attack_demo.py --scenario ENUM-01 --gateway off   # SUPI leaks
python3 run_attack_demo.py --scenario ENUM-01 --gateway on    # SUPI tokenized
python3 run_attack_demo.py --scenario DOS-01  --gateway on    # needs full testbed (SMF + active UE session)
```

Per-run evidence is appended to `attack_evidence.jsonl`.

---

## Layers at a glance

- **L1 — Identifier Tokenizer:** even if the agent is fully compromised, it only
  ever holds opaque tokens → *identifier leakage = 0%*. Also rejects raw SUPIs
  injected via logs.
- **L2 — Provenance / Taint:** content from an untrusted source may not drive a
  high-risk state change without operator authorization → blocks the injected
  DoS, with a traceable reason (which source tainted it).
- **L3 — Procedure-Aware Verifier (planned):** even trusted-sourced calls must
  follow the TS 23.502 PDU-session state machine and stay within rate limits →
  blocks out-of-order operations and control-plane DoS.

Each layer closes a distinct attack class; the ablation study (removing one at a
time) is what demonstrates that none is redundant.
