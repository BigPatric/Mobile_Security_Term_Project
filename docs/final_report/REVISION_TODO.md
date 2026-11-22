# Final report: open problems and reruns

The text of `latex/main.tex` is now internally consistent, and every number in it matches
`results/*.jsonl`. What remains are three gaps in the **evidence**. The report states each
one honestly, but only new live runs can close them. They are listed by importance.

## Serious problems

### 1. No live data from the final code, and the ground-truth probe was flawed

- All live numbers (the 130-run matrix and the 40-run signed rerun) were recorded **before**
  the three fixes in Sec. VI ("Fixes made after the live runs"). The final code has never run
  on the live core.
- Fix (iii) matters most. During the recorded runs, the post-release probe counted a failed
  WebConsole lookup (HTTP 401/500) as "SM context gone". The logs do not record the probe's
  HTTP status, and the release counts cannot rule this out, because a probe that always said
  "gone" would have produced exactly the same counts.
- What is safe today: every result that rests on **blocking** (0 releases under L2, the calls
  stopped by the rate cap, the FP rates), because a blocked call never reaches the core.
- What is uncertain: every count of releases that **went through** (8.9 per undefended DoS,
  3 per capped run). These are upper bounds, so the reported reduction (8.9 → 1.5) may be
  overstated.

**Rerun:** the cells where releases reach the core, with the fixed probe, and with the probe's
HTTP status written to the evidence record.

| Cells | L2 setting |
|---|---|
| DOS-01 and DOS-02 under `off`, `rbac`, `L1`, `L1,L3`; DOS-02 under `L1,L2` and full | claim-only (irrelevant for modes without L2) |
| BENIGN-02 and BENIGN-04 under full | signed (current default) |

Claim-only L2 is set in `config.yaml` (the `provenance` check of
`trigger_pdu_session_release`): `verify_authorization: false`. Restore `true` afterwards.

```bash
# before running: add the probe's HTTP status to the evidence record
# (free5gc_tools/tools.py, release_api / post-condition block)

# claim-only cells (config.yaml: verify_authorization: false)
sudo N_UES=9 REPEATS=5 EVIDENCE=results/attack_evidence_final_claim.jsonl \
  CELLS="DOS-01|--gateway off;DOS-02|--gateway off;\
DOS-01|--gateway rbac;DOS-02|--gateway rbac;\
DOS-01|--gateway on --layers L1;DOS-02|--gateway on --layers L1;\
DOS-01|--gateway on --layers L1,L3;DOS-02|--gateway on --layers L1,L3;\
DOS-02|--gateway on --layers L1,L2;DOS-02|--gateway on" \
  ./tools/run_live_matrix.sh

# signed cells (config.yaml: verify_authorization: true)
sudo N_UES=9 REPEATS=5 EVIDENCE=results/attack_evidence_final_signed.jsonl \
  CELLS="BENIGN-02|--gateway on;BENIGN-04|--gateway on" \
  ./tools/run_live_matrix.sh
```

About 60 runs (10 claim-only cells and 2 signed cells, 5 repeats each). Afterwards, Sec. VI (iii) can say the counts were re-verified instead of
"cannot be ruled out", and Table II / Fig. 4 can use the new numbers.

### 2. What a double release does is unverified

- The report now says L3's FSM is the one check no other layer provides, but that the
  violation it blocks for release (a second release of the same session) is "most likely"
  harmless, because the SMF no longer holds the context. That was inferred from the code
  (`free5gc_tools/tools.py` returns an error on any non-2xx from the SMF), not measured.

**Rerun:** under `--gateway off`, release the same session twice and record the SMF's HTTP
status for the second call. One or two runs suffice. Then replace "most likely" in Sec. V-B
and the Conclusion with the measured result.

### 3. Precheck latency drifts and the cause is unknown

- The core precheck that every forwarded release pays took a p95 of about 21–22 ms in the
  first 26 runs, a median of 76 ms over the 130-run matrix, and 146–195 ms in the later
  rerun. The report can only give a range of about 20–195 ms.
- The abstract's "77 ms" is one point in that range.

**Rerun:** time the precheck repeatedly on one freshly started core, then on a core after
many bring-up/tear-down cycles. If the drift is core state, the report can give a realistic
deployment figure.

## Lower priority (would strengthen the report, not fix an error)

- **Rate-cap false positives live.** The FP cost of cap 3 (0.25) comes only from synthetic
  traces. A benign task with a signed capability for 5 releases would show it on the real core.
- **Shared state across sessions (fix (i)).** Only covered by offline tests. Two or three
  concurrent agent sessions attacking one core would verify the shared cap live.
- **A real LLM.** The design is already in the report's future work: DOS-01 and DOS-02 under
  `off` and full, five repeats each.

## Title

The current title says "for LLM Agents" while the evaluation uses a scripted agent; the
abstract and conclusion now say so. Options:

- Keep "LLM Agents": the threat (indirect prompt injection) is specific to LLM agents, and the
  scripted agent models a hijacked one.
- Replace with "Tool-Using Agents": matches what was evaluated, but the prompt-injection
  framing then has to carry the LLM context alone.
