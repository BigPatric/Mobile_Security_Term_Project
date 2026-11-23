# Live results

Evidence and tables behind the final report and [docs/evaluation/RESULTS.md](../docs/evaluation/RESULTS.md).
Everything here was recorded on the final code (2026-11-23): keyed tokens, signed capabilities, the
fail-closed post-release probe, and a WebConsole restarted with every core.

## evidence/: raw records, one JSON line per run

| File | Runs | What |
|---|---|---|
| `attack_evidence_final.jsonl` | 140 | Main matrix (`PRESET=final`): 3 attacks × 6 modes, DOS-02 × 2 claim-only-L2 modes, BENIGN-01–04 × {RBAC, full}; 5 repeats each |
| `attack_evidence_final_benign05.jsonl` | 10 | BENIGN-05, authorized bulk drain, × {RBAC, full} |
| `attack_evidence_latency.jsonl` | 30 | Latency rerun (`PRESET=latency`): the 6 cells whose releases pass L3's core precheck, on a fresh WebConsole |
| `double_release.jsonl` | 2 | Same session released twice without the gateway (`tools/double_release.py`), UE 1 and UE 2 |

Each release call records `release_http_status` (the SMF's answer) and `post_probe` (the HTTP status of every
post-release probe). In all 498 counted releases the SMF answered 204 and the probe got 404.

The precheck latencies in `attack_evidence_final*.jsonl` (90–479 ms) are inflated by a leaking, long-lived
WebConsole (see RESULTS.md §4). Use `attack_evidence_latency.jsonl` for the precheck figure. Everything
else in those files (released and blocked counts, leakage, FP) is unaffected.

## tables/: aggregated CSVs (`tools/aggregate.py`)

| Prefix | Source | Files |
|---|---|---|
| `main_` | `attack_evidence_final.jsonl` + `attack_evidence_final_benign05.jsonl` | `effectiveness`, `false_positives`, `latency`, `cells` |
| `latency_rerun_` | `attack_evidence_latency.jsonl` | same four |

`cells` has one row per scenario × mode: mean (min–max) sessions released, blocked calls, leakage and FP
counts. Runs with the claim-only L2 appear as `L1+L2(claim)` and `L1+L2+L3(claim)`.

Regenerate:

```bash
python3 tools/aggregate.py --csv results/tables/main \
  results/evidence/attack_evidence_final.jsonl results/evidence/attack_evidence_final_benign05.jsonl
python3 tools/aggregate.py --csv results/tables/latency_rerun results/evidence/attack_evidence_latency.jsonl
```

## archive/: superseded

Evidence and tables from earlier code versions: the 130-run matrix (claim-only L2, unkeyed tokens,
fail-open probe) and the 40-run signed-capability rerun. Kept for reference only; not cited in the report.
