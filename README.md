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
| **DOS-02** | same, but copies a **forged authorization** from the log onto each release | **L2** — the forged ticket is not a gateway-signed capability (with the original claim-only L2: **L3**'s rate cap) |

An attack counts as successful only when an independent probe confirms the
session is really gone from the SMF — no mocks, no "the tool was called" counting.

## Results

Live on free5GC + UERANSIM (nine UEs, each run checked against the SMF's real state):

- **RBAC is no better than no defense**: every malicious call is one the agent is allowed to make.
- **L1** cuts identifier leakage from 100% to 0%.
- **L2** requires a capability the gateway signed itself, so both the plain injected DoS and the one
  carrying a forged change ticket release **0 of 9 sessions** under L1+L2 and the full gateway
  (8.9 without a gateway). With the legacy claim-only L2 the forged ticket gets past it
  (*taint laundering*), and **L3** caps that attack at its rate budget (3 of 9 sessions).
- **No false positives** on the four single-release benign tasks. The rate cap does block a legitimate
  bulk drain after 3 releases (BENIGN-05), the known trade-off of a rate limit.
- Overhead: a median of about 0.04 ms per ordinary call; a forwarded release adds a median of 13 ms
  (9–27 ms) for L3's core precheck.
- 150 runs on the final code plus a 30-run latency rerun; every one of the 498 counted releases is
  confirmed by an SMF 204 and a probe 404. A second release of the same session gets HTTP 404 from the SMF.

Full numbers are in the [final report](docs/final_report/final_report.pdf) and
[RESULTS.md](docs/evaluation/RESULTS.md). Offline experiments show that new procedures
and tools are protected by changing config alone
([GENERALITY_PROOF.md](docs/evaluation/GENERALITY_PROOF.md)), map the rate-cap
trade-off ([EVAL_CURVE.md](docs/evaluation/EVAL_CURVE.md)), and mark where the defense
stops holding ([ADVERSARIAL_BOUNDARY.md](docs/evaluation/ADVERSARIAL_BOUNDARY.md)).

## Conclusion

Prompt-injection defense for network-operations agents belongs **at the
tool-call boundary**, not in the model. Each layer closes a different hole:

- **L1** protects confidentiality (identifier opacity).
- **L2** protects source integrity (provenance).
- **L3** protects procedure integrity, and it is the one layer that still holds
  when a genuine authorization is stolen or misused by an insider.

The gateway beats RBAC, causes no false positives on single-release benign tasks, and adds under 1 ms
to ordinary calls; a forwarded release pays one core round trip. Its rate cap also blocks legitimate
bulk maintenance past 3 releases.

**Limits we keep in view:** L3's rate check *bounds* bulk abuse rather than
eliminating it (out-of-order operations, such as a double release, are blocked
completely), a rate cap low enough to matter also blocks legitimate bulk maintenance, and
slow-drip attacks evade it. Signed capabilities are only as trustworthy as the operator path that
requests them, and are scoped to a tool and use budget, not to a subscriber. The agent is a scripted
worst-case control rather than a real LLM; a small real-model study is future work. See the roadmap in [DESIGN.md](docs/architecture/DESIGN.md).

---

## Quick start

```bash
pip install -r requirements.txt
python3 tests/test_e2e_scenarios.py        # offline: no core needed

# live (testbed up — see docs/guides/RUNNING.md)
python3 run_attack_demo.py --scenario DOS-02 --gateway off   # sessions really released
python3 run_attack_demo.py --scenario DOS-02 --gateway on    # forged ticket rejected by L2, 0 released
python3 run_attack_demo.py --scenario DOS-02 --gateway on --l2-claim-only   # legacy L2 fooled, L3 caps at 3
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
├── results/            # evidence/ (raw JSONL) · tables/ (CSV) · archive/ (superseded); see results/README.md
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
| Evaluation | [RESULTS.md](docs/evaluation/RESULTS.md) | Live result tables: ASR, leakage, FP, latency, ablation, double release |
| | [results/README.md](results/README.md) | What each evidence file and CSV contains, and how to regenerate them |
| | [EVAL_CURVE.md](docs/evaluation/EVAL_CURVE.md) | ASR / FP trade-off curve on synthetic traces |
| | [ADVERSARIAL_BOUNDARY.md](docs/evaluation/ADVERSARIAL_BOUNDARY.md) | Adaptive attackers: what is blocked and what is not |
| | [GENERALITY_PROOF.md](docs/evaluation/GENERALITY_PROOF.md) | Why the gateway is general rather than written for the three attacks |
| Report | [final_report.pdf](docs/final_report/final_report.pdf) | Final project report (LaTeX source in [latex/](docs/final_report/latex/)) |
| Proposal | [112550018_proposal.pdf](docs/proposal/112550018_proposal.pdf) | Original project proposal |
| | [progress_report.pdf](docs/proposal/progress_report.pdf) | Mid-term progress report |

## References
- Greshake et al. (2023), *Indirect Prompt Injection* — arXiv:2302.12173
- Debenedetti et al. (2025), *CaMeL* — arXiv:2503.18813
- 3GPP TS 23.502 §4.3 — PDU Session lifecycle (§4.3.4 Release)
- Model Context Protocol, Specification 2025-11-25 — modelcontextprotocol.io/specification

## License

The project's own code and documentation are released under the [MIT License](LICENSE).
The vendored third-party directories keep their original licenses:
[`UERANSIM/`](UERANSIM/LICENSE) is GPL-3.0 and [`free5gc/`](free5gc/LICENSE) is Apache-2.0.
