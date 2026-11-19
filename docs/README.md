# Documentation

Back to the [project README](../README.md).

```
docs/
├── architecture/   # how the system is built and why
├── guides/         # how to run it
├── evaluation/     # what we measured and what it shows
└── proposal/       # original project proposal
```

Suggested reading order for a first-time reader:
**DESIGN → END_TO_END_FLOW → RUNNING → RESULTS**, then the other evaluation docs.

## Architecture — how it works

| Doc | Contents |
|---|---|
| [DESIGN.md](architecture/DESIGN.md) | Threat model, why each layer exists, L3 scope and roadmap |
| [END_TO_END_FLOW.md](architecture/END_TO_END_FLOW.md) | Full request lifecycle and attack walkthrough, function by function (中文) |
| [REPOSITORY_LAYOUT.md](architecture/REPOSITORY_LAYOUT.md) | What every directory and file is for |

## Guides — how to run it

| Doc | Contents |
|---|---|
| [RUNNING.md](guides/RUNNING.md) | Testbed bring-up, unit tests, live demo, full experiment matrix, lab notes |

## Evaluation — what it shows

| Doc | Contents | Evidence |
|---|---|---|
| [RESULTS.md](evaluation/RESULTS.md) | Live result tables: ASR, leakage, FP, latency, ablation (中文) | live free5GC run, `tools/aggregate.py` |
| [EVAL_CURVE.md](evaluation/EVAL_CURVE.md) | ASR / FP trade-off curve over a rate-cap sweep, on synthetic traces (中文) | `tools/eval_curve.py` |
| [ADVERSARIAL_BOUNDARY.md](evaluation/ADVERSARIAL_BOUNDARY.md) | Adaptive attackers (spread, forge, reorder, bucket-hop): what is blocked and what is not (中文) | `tests/test_adversarial.py` |
| [GENERALITY_PROOF.md](evaluation/GENERALITY_PROOF.md) | Why the gateway is general rather than written for the three attacks (中文) | `tests/test_generality.py` |

## Proposal

| Doc | Contents |
|---|---|
| [112550018_proposal.pdf](proposal/112550018_proposal.pdf) | Original project proposal |
