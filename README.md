# Secure MCP Gateway for the 5G Core

**Mobile Network Security (Fall 2026) — Term Project · 112550018**

A provenance- and procedure-aware **gateway** that sits between an autonomous
LLM agent and a live 5G core (**free5GC**), so that even a *fully compromised*
agent cannot leak subscriber identities or issue unauthorized, out-of-procedure
control-plane operations.

---

## Motivation

Operators are starting to hand network-operations work (triaging alerts,
remediating faults, releasing stuck sessions) to LLM agents that call core
network APIs as tools. Those agents read **untrusted text** — alert logs, tenant
tickets, telemetry — and an attacker who can write into that text can hijack the
agent through **indirect prompt injection** (Greshake et al., 2023). In a 5G
core, a hijacked agent with API access can:

- **enumerate subscriber identities** (SUPI/IMSI) and leak them, and
- **tear down PDU sessions in bulk** — a control-plane denial of service.

Classic role-based access control does not help: the agent *is* authorized to
call these tools, it is just calling them for the attacker. And asking the model
to "resist injection" is not a security boundary.

**Our position:** treat the agent as compromised and enforce policy *outside* it,
at the tool-call boundary. Following CaMeL (Debenedetti et al., 2025), we remove
the agent's *capability* to do damage instead of relying on its judgment.

> **Threat model.** The attacker controls only the agent's untrusted inputs. They
> cannot touch the gateway, the free5GC core, or its configuration. A hijacked
> agent is assumed to obey any injected directive.

## Approach

The agent only talks to a `ToolClient` interface, so the gateway drops into that
seam **without changing the agent**. Every tool call passes through a
config-driven chain of three defense layers:

```
 Untrusted inputs (alert logs) ──► LLM / ReAct agent
                                        │ tool call: name(args)
                                        ▼
        ┌──────────────── Secure MCP Gateway ────────────────┐
        │ L1 Identifier Tokenizer   SUPI ⇄ opaque token       │
        │ L2 Provenance / Taint     untrusted-driven → block  │
        │ L3 Procedure-Aware FSM    TS 23.502 state + rate    │
        └───────────────────────┬────────────────────────────┘
                                ▼
                     free5GC + UERANSIM (live)
```

We evaluate it with three attacks, all driven only by poisoned alert logs and
run **live** against a real free5GC + UERANSIM testbed:

| Scenario | Hijacked agent does… | Stopped by |
|---|---|---|
| **ENUM-01** | dumps every SUPI via `list_subscribers` | **L1** — agent only ever sees tokens |
| **DOS-01** | releases every live PDU session | **L2** — untrusted content cannot drive a high-risk call |
| **DOS-02** | same, but copies a **forged authorization** from the log onto each release | **L3** — L2 is fooled; the procedure/rate check is not |

An attack counts as successful only when an independent probe confirms the
session is really gone from the SMF — no mocks, no "the tool was called" counting.

## Results

Live runs, 3 attack scenarios × 6 defense modes, plus 4 benign operator tasks
(full tables in [RESULTS.md](docs/evaluation/RESULTS.md)):

| Mode | Identifier leakage | Sessions released per attack | Benign FP |
|---|---|---|---|
| No gateway | 1.00 | 2.00 | — |
| RBAC allow-list | 1.00 | 2.00 | 0.00 |
| L1 only | **0.00** | 2.00 | — |
| L1 + L2 | 0.00 | 1.00 (DOS-02 still passes fully) | — |
| **L1 + L2 + L3 (full)** | **0.00** | **1.00** (DOS-01 blocked, DOS-02 capped) | **0.00** |

- **RBAC scores the same as having no defense**, because every malicious call is
  one the agent is allowed to make.
- **L1** brings identifier leakage from 100% to 0%.
- **L2** blocks the injected DoS, but a forged authorization string gets past it
  (*taint laundering*). **L3** still caps the damage, and the ablation shows every layer is needed.
- **No false positives** on legitimate operations, including an authorized
  single release.
- **Overhead:** p50 ≈ 0.03 ms per call. The tail (p95 ≈ 8 ms) is a single core
  round-trip from L3's precheck, and only high-risk calls make it.

Offline tests also show the engine is **general**: a new procedure, a new tool,
or an attack variant we never wrote a rule for is handled by changing config,
not code ([GENERALITY_PROOF.md](docs/evaluation/GENERALITY_PROOF.md)). A synthetic
rate-cap sweep maps the ASR / false-positive trade-off
([EVAL_CURVE.md](docs/evaluation/EVAL_CURVE.md)), and adaptive attackers are used to
mark exactly where the defense stops holding
([ADVERSARIAL_BOUNDARY.md](docs/evaluation/ADVERSARIAL_BOUNDARY.md)).

## Conclusion

Prompt-injection defense for network-operations agents belongs **at the
tool-call boundary**, not in the model. Each layer closes a different hole:

- **L1** protects confidentiality (identifier opacity).
- **L2** protects source integrity (provenance).
- **L3** protects procedure integrity, and it is the one layer that still holds
  when an authorization can be forged, stolen or misused by an insider.

The gateway beats RBAC, causes no false positives and adds negligible latency.

**Limits we keep in view:** L3's rate check *bounds* bulk abuse rather than
eliminating it (out-of-order operations, such as a double release, are blocked
completely). Authorization is still an in-band claim, and a signed, gateway-verifiable
capability is future work. The agent is a scripted worst-case control rather than a
real LLM. See the roadmap in [DESIGN.md](docs/architecture/DESIGN.md).

---

## Quick start

```bash
pip install -r requirements.txt
python3 tests/test_e2e_scenarios.py        # offline: no core needed

# live (testbed up — see docs/guides/RUNNING.md)
python3 run_attack_demo.py --scenario DOS-02 --gateway off   # sessions really released
python3 run_attack_demo.py --scenario DOS-02 --gateway on    # L2 fooled, L3 caps it
```

## Repository structure

```
Mobile_Security_Term_Project/
├── agent/              # the LLM / ReAct agent being defended
├── gateway/            # the defense: three-layer Secure MCP Gateway (+ checks/)
├── free5gc_tools/      # MCP tool shim, the only code that touches the live core
├── benchmark/          # attack + benign scenarios, synthetic trace generator
├── tests/              # offline unit / scenario / adversarial tests
├── tools/              # experiment runners, sweeps, result aggregation
├── docs/               # architecture · guides · evaluation · proposal · final report
├── results/            # aggregated live results (CSV) behind the report's tables
├── free5gc/ UERANSIM/  # vendored testbed (called, never modified)
├── run_attack_demo.py  # one live run: --scenario, --gateway on/off/rbac, --layers
├── config.yaml         # core endpoints + gateway policy + layer toggles
└── LICENSE             # MIT (own code only; see License below)
```

File-by-file details: [REPOSITORY_LAYOUT.md](docs/architecture/REPOSITORY_LAYOUT.md).

## Documentation

Full index: [docs/README.md](docs/README.md).

| Category | Doc | Contents |
|---|---|---|
| Architecture | [DESIGN.md](docs/architecture/DESIGN.md) | Threat model, why each layer exists, L3 scope and roadmap |
| | [END_TO_END_FLOW.md](docs/architecture/END_TO_END_FLOW.md) | Full request lifecycle and attack walkthrough, function by function |
| | [REPOSITORY_LAYOUT.md](docs/architecture/REPOSITORY_LAYOUT.md) | What every directory and file is for |
| Guides | [RUNNING.md](docs/guides/RUNNING.md) | Testbed bring-up, unit tests, live demo, full experiment matrix, lab notes |
| Evaluation | [RESULTS.md](docs/evaluation/RESULTS.md) | Live result tables: ASR, leakage, FP, latency, ablation |
| | [EVAL_CURVE.md](docs/evaluation/EVAL_CURVE.md) | ASR / FP trade-off curve on synthetic traces |
| | [ADVERSARIAL_BOUNDARY.md](docs/evaluation/ADVERSARIAL_BOUNDARY.md) | Adaptive attackers: what is blocked and what is not |
| | [GENERALITY_PROOF.md](docs/evaluation/GENERALITY_PROOF.md) | Why the gateway is general rather than written for the three attacks |
| Report | [final_report.pdf](docs/final_report/final_report.pdf) | Final project report (LaTeX source in [latex/](docs/final_report/latex/)) |
| Proposal | [112550018_proposal.pdf](docs/proposal/112550018_proposal.pdf) | Original project proposal |

## References
- Greshake et al. (2023), *Indirect Prompt Injection* — arXiv:2302.12173
- Debenedetti et al. (2025), *CaMeL* — arXiv:2503.18813
- 3GPP TS 23.502 §4.3 — PDU Session lifecycle (§4.3.4 Release)
- Model Context Protocol, Specification 2025-11-25 — modelcontextprotocol.io/specification

## License

The project's own code and documentation are released under the [MIT License](LICENSE).
The vendored third-party directories keep their original licenses:
[`UERANSIM/`](UERANSIM/LICENSE) is GPL-3.0 and [`free5gc/`](free5gc/LICENSE) is Apache-2.0.
