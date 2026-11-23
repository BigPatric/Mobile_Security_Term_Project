# Results — Secure MCP Gateway for the 5G Core

**Updated:** 2026-11-23 (final code; nine UEs, 5 repeats per cell, rate cap 3; 150 + 30 live runs)
**Data source:** [`results/`](../../results/README.md): `evidence/attack_evidence_final.jsonl` (140 runs),
`evidence/attack_evidence_final_benign05.jsonl` (10 runs), `evidence/attack_evidence_latency.jsonl` (30-run
latency rerun) and `evidence/double_release.jsonl`, aggregated with [tools/aggregate.py](../../tools/aggregate.py)
into `tables/main_*.csv` and `tables/latency_rerun_*.csv`.
**Related:** [../README.md](../../README.md) · [END_TO_END_FLOW.md](../architecture/END_TO_END_FLOW.md) · [GENERALITY_PROOF.md](GENERALITY_PROOF.md) · how to run: [RUNNING.md](../guides/RUNNING.md)

Every number is **ground truth**. An attack "succeeds" only when the free5GC core confirms that the
PDU session was really torn down: the SMF answers the release with 2xx, **and** a later probe of the SM
context gets HTTP 404. Each evidence record stores both statuses. All 498 releases that no check blocked
(428 in the main matrix, 70 in the latency rerun) were SMF 204 followed by probe 404.

To reproduce:

```bash
sudo N_UES=9 REPEATS=5 PRESET=final ./tools/run_live_matrix.sh --fresh      # 140 runs + double release
sudo N_UES=9 REPEATS=5 EVIDENCE=results/evidence/attack_evidence_final_benign05.jsonl \
  CELLS="BENIGN-05|--gateway on;BENIGN-05|--gateway rbac" ./tools/run_live_matrix.sh   # 10 runs
sudo N_UES=9 REPEATS=5 PRESET=latency ./tools/run_live_matrix.sh --fresh    # 30 runs, precheck latency
python3 tools/aggregate.py --csv results/tables/main \
  results/evidence/attack_evidence_final.jsonl results/evidence/attack_evidence_final_benign05.jsonl
python3 tools/aggregate.py --csv results/tables/latency_rerun results/evidence/attack_evidence_latency.jsonl
```

Superseded evidence from earlier code versions (the 130-run matrix and the 40-run signed rerun) is in
[`results/archive/`](../../results/archive/). It is no longer cited.

---

## 1. Attack effectiveness (ground truth)

3 attack scenarios (ENUM-01 / DOS-01 / DOS-02) × 6 defense levels × 5 repeats (15 attack runs per mode),
nine UEs with one active PDU session each, L3 rate cap `max: 3` per 60 s. L2 verifies gateway-signed
capabilities. DOS-02 also runs under the legacy claim-only L2 (`--l2-claim-only`) for comparison.

| mode | ASR | leakage | DOS-01 released | DOS-02 released |
|---|---|---|---|---|
| off (no defense) | 0.67 | 1.00 | 9.0 | 8.8 (8–9) |
| rbac (allow-list baseline) | 0.67 | 1.00 | 9.0 | 9.0 |
| L1 (tokenizer) | 0.67 | **0.00** | 8.0 (7–9) | 8.6 (8–9) |
| L1+L2 (+taint) | **0.00** | 0.00 | **0** | **0** |
| L1+L3 (+verifier) | 0.67 | 0.00 | 3 | 3 |
| **L1+L2+L3 (full)** | **0.00** | 0.00 | **0** | **0** |
| L1+L2, claim-only L2 | — | 0.00 | — | 8.4 (8–9) |
| full, claim-only L2 | — | 0.00 | — | 3 |

Values are means over 5 runs; a range is given where the runs differ.

- **ASR** = fraction of attack runs in which core state really changed. ENUM-01 is an **exfiltration**
  attack (it changes no core state), so it counts toward leakage, not ASR; the ASR ceiling is 2/3.
- **leakage** = fraction of runs in which a raw SUPI reached the agent.
- **Released below 9** in an unblocked run means one or two UEs had not finished registering when the
  attack started. This happened in 12 of the 80 bulk-release runs. The agent released every session that
  existed in every unblocked run.

### How to read it
1. **`off` and `rbac` are identical** (same ASR and leakage). RBAC does nothing against abuse that looks
   authorized.
2. **L1 brings leakage from 1.00 to 0.** Identifier opacity stops ENUM-01.
3. **Signed L2 stops both DoS attacks outright.** All 9 release attempts in every DoS run under L1+L2 and
   full were blocked at L2. The forged `CHG-20481` in DOS-02 is not a gateway-signed capability.
4. **Claim-only L2 is laundered by DOS-02** (8.4 released); only L3's rate cap then bounds it (3 of 9).
   This is the before/after comparison for signed capabilities.
5. **Full gateway: mean teardown per DoS attack 8.9 → 0.** Under the claim-only L2 it was 8.9 → 1.5.

---

## 2. Ablation attribution: which layer stops which attack

| mode | DOS-01 stopped at | DOS-02 stopped at |
|---|---|---|
| L1+L2 | **L2** / taint-control-flow | **L2** / taint-control-flow |
| L1+L3 | L3 / rate-limit | L3 / rate-limit |
| **L1+L2+L3** | **L2** / taint-control-flow | **L2** / taint-control-flow |
| full, claim-only L2 | — | L3 / rate-limit |

With signed capabilities, L1+L2 alone stops all three live attacks. L3's rate cap is the fallback for
when L2 is bypassed (claim-only row) or a genuine capability is misused (offline test: a hijacked agent
with a valid 9-use capability is capped at 3).

---

## 3. False positives (5 legitimate operations tasks × 5 repeats)

| task | rbac | full |
|---|---|---|
| BENIGN-01 health check | FP 0/5 | FP 0/5 |
| BENIGN-02 authorized single release | FP 0/5, 1 released | FP 0/5, 1 released |
| BENIGN-03 health check after harmless alert | FP 0/5 | FP 0/5 |
| BENIGN-04 authorized single release, tainted session | FP 0/5, 1 released | FP 0/5, 1 released |
| **BENIGN-05 authorized bulk drain (9-use capability)** | FP 0/5, 8.8 released | **FP 5/5**: 3 released, 6 blocked by L3 rate |
| **overall** | **0.00** (25 runs) | **0.20** (25 runs) |

The full gateway blocks no single-release task. It **does** block legitimate bulk maintenance after 3
releases, because the rate cap binds authorized callers too (`exempt_authorized: false`) and cannot tell
legitimate from malicious bulk. This reproduces the offline trade-off ([EVAL_CURVE.md](EVAL_CURVE.md),
FP 0.25 at cap 3) on the live core.

---

## 4. Latency (gateway overhead per tool call, ms)

**Calls that do not query the core** (150-run matrix, signed-capability runs):

| mode | calls | mean | p50 | p95 | max |
|---|---|---|---|---|---|
| rbac | 444 | 0.053 | 0.033 | 0.133 | 0.321 |
| L1 | 203 | 0.113 | 0.113 | 0.179 | 0.552 |
| L1+L2 | 210 | 0.046 | 0.038 | 0.102 | 0.516 |
| L1+L3 | 180 | 0.045 | 0.036 | 0.107 | 0.186 |
| L1+L2+L3 (full) | 420 | 0.047 | 0.035 | 0.127 | 0.272 |

**Forwarded releases with L3's core precheck** (30-run latency rerun, `results/evidence/attack_evidence_latency.jsonl`,
fresh core and fresh WebConsole every run): 70 prechecks, **median 13.1 ms, p95 17.9 ms, 9.1–26.5 ms**, no trend
across the runs.

| cell | prechecks | median | range |
|---|---|---|---|
| DOS-01 × L1+L3 | 15 | 13.3 | 9.2–17.3 |
| DOS-02 × L1+L3 | 15 | 12.1 | 9.1–17.9 |
| DOS-02 × full, claim-only L2 | 15 | 13.1 | 9.8–21.2 |
| BENIGN-02 × full | 5 | 10.2 | 9.3–10.9 |
| BENIGN-04 × full | 5 | 11.2 | 9.4–26.5 |
| BENIGN-05 × full | 15 | 13.6 | 9.7–17.5 |

### How to read it
- **The gateway's own checks cost under 0.6 ms**, including every blocked release.
- **A forwarded release pays one core round trip** (three WebConsole REST calls): about 13 ms, within the
  50 ms design target.
- **Why the main matrix showed 90–479 ms** (90–194 ms in the first 140 runs, 198–479 ms in BENIGN-05, which ran two hours later). The free5GC WebConsole is not started or stopped by `run.sh` /
  `force_kill.sh`, so one instance served every run (it had run since 2026-11-21 and held 617 MB). On every
  request it appends the NRF's AMF/SMF profiles to an in-memory list that it never clears
  (`webconsole/backend/webui_context/context.go`, `UpdateNfProfiles`), so each request got slower with the
  total served. The precheck grew about 20 ms per repeat. `run_live_matrix.sh` now restarts the WebConsole with
  the core (and clears the NRF's stale `urilist`, which also accumulates but is not on the precheck path).
- **The rerun changed nothing but the latency**: every cell released exactly as many sessions per run as in
  the main matrix (3 per capped attack and BENIGN-05, 1 for BENIGN-02/04) and blocked every further attempt;
  all 70 releases were SMF 204 + probe 404.

---

## 5. Double release (no gateway)

`tools/double_release.py`, on a fresh core, for UE 1 and UE 2 (`results/evidence/double_release.jsonl`):

| step | result |
|---|---|
| 1st release (tool) | SMF 204, probe 404 → verified released (AMF still lists the session: stale view) |
| 2nd release, straight to the SMF | **HTTP 404** `SMContext Ref is not found` |
| 2nd release, through the tool | SMF 404 → tool reports an error, nothing changes |

A second release of the same session is harmless on free5GC. The L3 FSM blocks it anyway; its value lies
in procedures where a wrong order does cause harm.

---

## 6. Conclusions

| Claim | Supported by |
|---|---|
| Identifier leakage = 0% | §1: 0 from L1 on |
| Stops DoS driven by indirect prompt injection | §1/§2: DOS-01 blocked by L2, 0 released |
| Stops DoS with a forged authorization | §1/§2: signed L2 blocks DOS-02 (0 released); claim-only L2 fails, L3 bounds it at 3 |
| Better than RBAC | §1: rbac matches no defense |
| No false blocks on single-release operations | §3: FP 0 on BENIGN-01–04 |
| Known cost: bulk maintenance is capped | §3: BENIGN-05 FP 5/5 |
| Overhead | §4: < 0.6 ms per ordinary call; median 13 ms per forwarded release |
| Ground truth is not fail-open | 498/498 counted releases: SMF 204 + probe 404 |

---

## 7. Limitations / caveats

- **Rate cap is a parameter.** 3 per 60 s sits just above the single-release benign tasks; it is not
  derived from a standard. Any cap low enough to bound a DoS also blocks legitimate bulk work (§3,
  [EVAL_CURVE.md](EVAL_CURVE.md)). It bounds bursts, not slow drip ([ADVERSARIAL_BOUNDARY.md](ADVERSARIAL_BOUNDARY.md)).
- **Testbed scale.** Nine UEs; the blocked fraction of a burst is 1 − 3/N, so 2/3 here is the worst case.
- **Scripted agent.** Always hijacked, the worst case for the actions it covers; no real-LLM runs.
- **Shared state across sessions** (fix (i) in the report) is covered only by offline tests: each live run
  is one agent session.
- **Screenshots** of DOS-02 in the report come from an earlier three-UE run with the claim-only L2.
- **OAuth is off (`nrfcfg oauth: false`).** Protecting NF-to-NF traffic is orthogonal to protecting
  agent→core calls.
- Offline, deterministic logic checks (including generality) are in [GENERALITY_PROOF.md](GENERALITY_PROOF.md) and `tests/`.
