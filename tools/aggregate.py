#!/usr/bin/env python3
"""
tools/aggregate.py — turn attack_evidence.jsonl into the quantified result tables
=================================================================================
Reads one or more evidence logs (the JSONL that run_attack_demo.py and
tools/sweep.py append, one record per run) and computes the metrics the project
claims, grouped by gateway MODE (off / rbac / L1 / L1+L2 / L1+L3 / L1+L2+L3):

  ASR       Attack Success Rate  — share of ATTACK runs where the core state
                                   actually changed (real_core_state_changed),
                                   i.e. ground truth, not intent.
  Leakage   share of ATTACK runs where a raw SUPI was leaked.
  Released  mean PDU sessions actually torn down per ATTACK run.
  FP rate   False-Positive rate  — share of BENIGN runs where the gateway
                                   blocked a legitimate call.
  Latency   per-tool-call gateway overhead (ms): mean / p50 / p95 / max,
                                   pooled over every call in that mode.
  Caught-by which layer/violation stopped the attack (ablation attribution).

Usage:
    python3 tools/aggregate.py [evidence.jsonl ...]         # default: attack_evidence.jsonl
    python3 tools/aggregate.py --csv results/results FILE ...  # also write results/results_*.csv

Metrics are defined on GROUND TRUTH recorded in the evidence, so this script is
pure arithmetic — it never re-runs anything and never fabricates a number.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections import defaultdict
from typing import Any, Dict, List, Optional

# Friendly gateway_layers names -> short layer ids, so a mode gets a compact label.
_LAYER_ID = {"tokenizer": "L1", "taint": "L2", "verifier": "L3", "allowlist": "L0"}
# Stable column order for the tables.
_MODE_ORDER = ["off", "rbac", "L1", "L1+L2", "L1+L3", "L2+L3", "L1+L2+L3"]


def mode_label(row: Dict[str, Any]) -> str:
    """Derive a compact, stable mode label from an evidence record, so live and
    offline evidence bucket the same way."""
    mode = row.get("gateway_mode")
    if mode == "off":
        return "off"
    if mode == "rbac":
        return "rbac"
    ids = sorted((_LAYER_ID.get(n, n) for n in row.get("gateway_layers", [])),
                 key=lambda x: (len(x), x))
    return "+".join(ids) if ids else "none"


def _mode_sort_key(label: str):
    return (_MODE_ORDER.index(label), label) if label in _MODE_ORDER else (len(_MODE_ORDER), label)


def _overheads(row: Dict[str, Any]) -> List[float]:
    return [d["gateway_overhead_ms"] for d in row.get("gateway_decisions", [])
            if isinstance(d, dict) and d.get("gateway_overhead_ms") is not None]


def _pct(vals: List[float], q: float) -> float:
    if not vals:
        return float("nan")
    s = sorted(vals)
    i = min(len(s) - 1, int(round(q * (len(s) - 1))))
    return s[i]


def load(paths: List[str]) -> List[Dict[str, Any]]:
    rows = []
    for p in paths:
        if not os.path.exists(p):
            print(f"  (skip: {p} not found)", file=sys.stderr)
            continue
        with open(p) as f:
            for line in f:
                line = line.strip()
                if line:
                    rows.append(json.loads(line))
    return rows


def aggregate(rows: List[Dict[str, Any]]) -> Dict[str, Any]:
    by_mode_cat: Dict[str, Dict[str, List[Dict[str, Any]]]] = defaultdict(lambda: defaultdict(list))
    lat_by_mode: Dict[str, List[float]] = defaultdict(list)
    caught: Dict[str, Dict[str, set]] = defaultdict(lambda: defaultdict(set))  # mode -> scenario -> {L/violation}

    for r in rows:
        m = mode_label(r)
        cat = r.get("scenario_category") or ("benign" if str(r.get("scenario_id", "")).startswith("BENIGN") else "attack")
        by_mode_cat[m][cat].append(r)
        lat_by_mode[m].extend(_overheads(r))
        if cat == "attack":
            for c in r.get("tool_calls", []):
                b = c.get("blocked_by")
                if b:
                    caught[m][r.get("scenario_id")].add(f"{b.get('layer')}/{b.get('violation')}")
    return {"by_mode_cat": by_mode_cat, "lat": lat_by_mode, "caught": caught}


def _mean(xs):
    return sum(xs) / len(xs) if xs else float("nan")


def _fmt(x, nd=2):
    return "—" if x != x else f"{x:.{nd}f}"   # x!=x -> NaN


def print_tables(agg: Dict[str, Any]) -> List[tuple]:
    by, lat, caught = agg["by_mode_cat"], agg["lat"], agg["caught"]
    modes = sorted(by.keys(), key=_mode_sort_key)
    csv_tables = []

    # -- effectiveness (attacks) --------------------------------------------- #
    hdr = ["mode", "attack_runs", "ASR", "leakage", "avg_released"]
    rows = []
    for m in modes:
        runs = by[m].get("attack", [])
        if not runs:
            continue
        asr = _mean([1.0 if r.get("real_core_state_changed") else 0.0 for r in runs])
        leak = _mean([1.0 if r.get("identifier_leaked") else 0.0 for r in runs])
        rel = _mean([r.get("sessions_released", 0) for r in runs])
        rows.append([m, len(runs), asr, leak, rel])
    csv_tables.append(("effectiveness", hdr, rows))
    print("\n=== Effectiveness on ATTACK scenarios (ground truth) ===")
    print(f"{'mode':<10}{'runs':>6}{'ASR':>8}{'leakage':>9}{'released':>10}")
    for m, n, asr, leak, rel in rows:
        print(f"{m:<10}{n:>6}{_fmt(asr):>8}{_fmt(leak):>9}{_fmt(rel):>10}")
    print("  note: ASR = core-state-change rate over ALL attack runs; ENUM-01 is a")
    print("        leakage attack (changes no core state) so it shows under 'leakage',")
    print("        not ASR — hence max ASR < 1 when ENUM-01 is in the set.")

    # -- false positives (benign) -------------------------------------------- #
    hdr = ["mode", "benign_runs", "FP_rate"]
    rows = []
    for m in modes:
        runs = by[m].get("benign", [])
        if not runs:
            continue
        fp = _mean([1.0 if r.get("false_positive") else 0.0 for r in runs])
        rows.append([m, len(runs), fp])
    csv_tables.append(("false_positives", hdr, rows))
    print("\n=== False positives on BENIGN scenarios ===")
    print(f"{'mode':<10}{'runs':>6}{'FP_rate':>9}")
    for m, n, fp in rows:
        print(f"{m:<10}{n:>6}{_fmt(fp):>9}")

    # -- latency ------------------------------------------------------------- #
    hdr = ["mode", "calls", "mean_ms", "p50_ms", "p95_ms", "max_ms"]
    rows = []
    for m in modes:
        xs = lat[m]
        if not xs:
            continue
        rows.append([m, len(xs), _mean(xs), _pct(xs, 0.5), _pct(xs, 0.95), max(xs)])
    csv_tables.append(("latency", hdr, rows))
    print("\n=== Gateway overhead per tool call (ms) ===")
    print(f"{'mode':<10}{'calls':>6}{'mean':>8}{'p50':>8}{'p95':>8}{'max':>8}")
    for m, n, me, p50, p95, mx in rows:
        print(f"{m:<10}{n:>6}{_fmt(me,3):>8}{_fmt(p50,3):>8}{_fmt(p95,3):>8}{_fmt(mx,3):>8}")

    # -- ablation attribution ------------------------------------------------ #
    print("\n=== Which layer caught each attack (ablation attribution) ===")
    scns = sorted({s for m in caught for s in caught[m]})
    for m in modes:
        if m not in caught:
            continue
        cells = [f"{s}:{','.join(sorted(caught[m].get(s, {'—'})))}" for s in scns]
        print(f"{m:<10} " + "   ".join(cells))

    return csv_tables


def write_csv(prefix: str, tables: List[tuple]) -> None:
    import csv
    for name, hdr, rows in tables:
        path = f"{prefix}_{name}.csv"
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        with open(path, "w", newline="") as f:
            w = csv.writer(f)
            w.writerow(hdr)
            w.writerows(rows)
        print(f"  wrote {path}", file=sys.stderr)


def main() -> None:
    ap = argparse.ArgumentParser(description="Aggregate gateway evidence into result tables.")
    ap.add_argument("evidence", nargs="*", default=["attack_evidence.jsonl"],
                    help="evidence JSONL file(s) (default: attack_evidence.jsonl)")
    ap.add_argument("--csv", metavar="PREFIX", default=None, help="also write <PREFIX>_*.csv")
    args = ap.parse_args()

    rows = load(args.evidence)
    if not rows:
        raise SystemExit("no evidence records found")
    print(f"loaded {len(rows)} run(s) from {', '.join(args.evidence)}")
    tables = print_tables(aggregate(rows))
    if args.csv:
        write_csv(args.csv, tables)


if __name__ == "__main__":
    main()
