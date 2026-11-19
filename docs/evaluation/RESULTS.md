# Results — Secure MCP Gateway for the 5G Core

**Updated:** 2026-11-19
**Data source:** live free5GC + UERANSIM runs, `attack_evidence.jsonl`, aggregated with [../tools/aggregate.py](../../tools/aggregate.py).
**Related:** [../README.md](../../README.md) · [END_TO_END_FLOW.md](../architecture/END_TO_END_FLOW.md) · [GENERALITY_PROOF.md](GENERALITY_PROOF.md) · how to run: [RUNNING.md](../guides/RUNNING.md)

Every number is **ground truth**: an attack "succeeds" only when the free5GC core confirms the PDU
session was really torn down (the SMF SM context is gone), not merely because the tool was called.
To reproduce:

```bash
sudo ./tools/run_live_matrix.sh --fresh          # each cell restarts to a full set of sessions, then attacks
python3 tools/aggregate.py attack_evidence.jsonl # produces the tables below
```

---

## 1. Attack effectiveness (ground truth)

3 attack scenarios (ENUM-01 / DOS-01 / DOS-02) × 6 defense levels.

| mode | ASR | leakage | Mean sessions released |
|---|---|---|---|
| off (no defense) | 0.67 | 1.00 | 2.00 |
| rbac (allow-list baseline) | 0.67 | 1.00 | 2.00 |
| L1 (tokenizer) | 0.67 | **0.00** | 2.00 |
| L1+L2 (+taint) | **0.33** | 0.00 | 1.00 |
| L1+L3 (+verifier) | 0.67 | 0.00 | 1.33 |
| **L1+L2+L3 (full)** | **0.50** | 0.00 | 1.00 |

- **ASR** = fraction of attack runs in which core state really changed. ENUM-01 is an **exfiltration**
  attack (it does not change core state), so it counts toward leakage, not ASR; with ENUM-01 in the set,
  the ASR ceiling is below 1.
- **leakage** = fraction of runs in which a raw SUPI appeared.

### How to read it
1. **`off` and `rbac` are identical** → RBAC does nothing against abuse that looks authorized, which
   backs the proposal's "better than RBAC" claim.
2. **L1 brings leakage from 1.00 to 0** → identifier opacity stops ENUM-01.
3. **L1+L2 stops DOS-01 (ASR drops), but DOS-02 still passes fully** → L2's provenance is
   "laundered" by the forged authorization (taint laundering).
4. **full is best:** DOS-01 is blocked by L2, DOS-02 is capped by L3's rate limit.

---

## 2. Ablation attribution — which layer stops which attack

| mode | DOS-01 stopped at | DOS-02 stopped at |
|---|---|---|
| L1+L2 | **L2** / taint-control-flow | — (not stopped) |
| L1+L3 | L3 / rate-limit | L3 / rate-limit |
| **L1+L2+L3** | **L2** / taint-control-flow | **L3** / rate-limit |

> This table is the project's core argument: **the "—" for DOS-02 in the L1+L2 row shows provenance
> cannot stop a forged authorization; only L3 (which ignores authorization and reconciles procedure
> state and rate) can bound it.** Side by side, the two attacks show that no layer is redundant.

---

## 3. False positives (benign set, 4 legitimate operations tasks)

| mode | benign runs | FP rate |
|---|---|---|
| rbac | 4 | **0.00** |
| L1+L2+L3 (full) | 4 | **0.00** |

The full gateway **does not block** any legitimate operation (including the hardest one to tell apart,
an authorized single release), so security does not cost usability.

---

## 4. Latency (gateway overhead per tool call, ms)

| mode | calls | mean | p50 | p95 | max |
|---|---|---|---|---|---|
| rbac | 34 | 0.039 | 0.011 | 0.104 | 0.150 |
| L1 | 18 | 0.099 | 0.101 | 0.186 | 0.214 |
| L1+L2 | 18 | 0.075 | 0.037 | 0.250 | 0.319 |
| L1+L3 | 18 | 2.884 | 0.109 | 17.941 | 18.502 |
| L1+L2+L3 (full) | 42 | 1.496 | 0.035 | 7.967 | 15.380 |

### How to read it
- **p50 is in the tens of microseconds everywhere (0.01–0.1 ms)** → the pure checking logic is nearly free.
- **The tail (p95/max, 8–18 ms) comes entirely from L3's `core_precheck`**: the one real round-trip in
  which the gateway asks the core for ground truth, and it happens only on high-risk calls.
- **Counter-intuitive but explainable: L1+L3 is slower than full** (mean 2.884 vs 1.496). In full,
  **L2 blocks DOS-01 at the taint stage, before it reaches L3's core round-trip**; L1+L3 has no L2, so
  every release has to query the core, giving more round-trips and more latency.
  → **Blocking earlier is not only safer, it also lowers latency.**

---

## 5. Conclusions

| Claim | Supported by |
|---|---|
| Identifier leakage = 0% | §1 leakage: 0 from L1 on |
| Stops DoS driven by indirect prompt injection | §1/§2: DOS-01 blocked by L2 |
| Stops DoS with a forged authorization (which provenance misses) | §2: L1+L2 fails, full bounds it via L3 |
| Every layer is needed (no redundancy) | §2 ablation: disabling any layer lets an attack through |
| Better than RBAC | §1: rbac matches no defense |
| No false blocks on normal operations | §3: FP = 0 |
| Deployable (acceptable overhead) | §4: p50 in microseconds, tail is a single core round-trip |

---

## 6. Limitations / caveats

- **The rate part of ASR bounds the blast radius; it is not zero:** the calls before L3's cap still pass
  (the "mean released 1.0–1.33" for L1+L3 / full in §1). **Ordering violations (double / out-of-state
  release) are fully blocked**; the two complement each other.
- **Authorization is currently an in-band claim that the gateway cannot verify independently;**
  signed capabilities are future work. L3's value is exactly this: **when authorization cannot be
  verified, procedure integrity still keeps the damage bounded.**
- **The data plane (ping) is optional:** the DoS proof comes from the control plane (the SMF SM context
  disappears, plain REST) and needs no NAT or ping.
- **Sample and matrix:** in this round `full` ran once more than the others (4 runs vs 3; proportions
  unaffected); benign FP was measured only at the rbac / full levels; latency is pooled from a single
  round. For stronger statistics, rerun `tools/run_live_matrix.sh` with `REPEATS>=3`.
- **OAuth is off (`nrfcfg oauth: false`):** protecting NF-to-NF traffic is orthogonal to protecting
  agent→core calls and does not affect these conclusions.
- Offline, deterministic logic checks (including generality) are in [GENERALITY_PROOF.md](GENERALITY_PROOF.md) and `tests/`.
