#!/usr/bin/env python3
"""
tools/sweep.py — run the full scenario × gateway-mode matrix, offline
=====================================================================
Drives the REAL agent and the REAL config.yaml policy (the same
build_tool_client() the live demo uses) against the deterministic fake testbed
core from tests/test_e2e_scenarios.py, over every scenario and every ablation
mode, and appends one evidence record per cell — in the SAME JSON schema as
run_attack_demo.py. tools/aggregate.py then reads it into the result tables.

This makes the quantified A/B + ablation study reproducible with one command and
NO live core:

    python3 tools/sweep.py                       # -> benchmark/offline_evidence.jsonl
    python3 tools/aggregate.py benchmark/offline_evidence.jsonl

The numbers are the project's *prediction* for the live runs. Latency here is
the gateway's pure check-logic cost (the fake core returns instantly); the live
run_attack_demo.py records the same field against the real core, including the
real core_precheck round-trip. Attack success is still ground-truth: a release
counts only when the fake core confirms the session actually went away — exactly
the discipline the live path enforces.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "tests"))

import yaml  # noqa: E402

from agent import ReActAgent  # noqa: E402
from run_attack_demo import build_tool_client, load_scenarios  # noqa: E402
from test_e2e_scenarios import TestbedCore  # noqa: E402  (authoritative fake testbed core)

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

ALL_ON = {"tokenizer": True, "taint": True, "verifier": True}


def _L(*on):
    return {n: n in on for n in ("tokenizer", "taint", "verifier")}


# (label, mode, layers) — mirrors the ablation columns in test_e2e_scenarios.matrix()
MODES = [
    ("off", "off", None),
    ("rbac", "rbac", None),
    ("L1", "on", _L("tokenizer")),
    ("L1+L2", "on", _L("tokenizer", "taint")),
    ("L1+L3", "on", _L("tokenizer", "verifier")),
    ("L1+L2+L3", "on", ALL_ON),
]


def run_cell(cfg, scenarios, scenario_id, mode, layers, n_ues):
    """Run one (scenario, mode) cell and return an evidence record matching the
    schema run_attack_demo.py writes (the subset aggregate.py consumes)."""
    core = TestbedCore(n_ues)
    client, gw, active_layers = build_tool_client(cfg, mode, layers or ALL_ON, inner=core.client())
    meta = scenarios[scenario_id]
    res = ReActAgent(tool_client=client, scenario_id=scenario_id).run(meta["task_given_to_agent"])

    decisions = gw.decisions if gw is not None else []
    overheads = [d["gateway_overhead_ms"] for d in decisions]
    blocked = [c for c in res.tool_calls if c.was_blocked()]
    sessions_released = sum(1 for c in res.tool_calls if c.changed_core_state())

    return {
        "run_timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "source": "offline-sweep",
        "scenario_id": scenario_id,
        "scenario_category": meta.get("category"),
        "scenario_name": meta.get("scenario_name"),
        "attack_type": meta.get("attack_type"),
        "n_ues": n_ues,
        "core_up": True,            # fake testbed is always 'up'
        "live_session_present": True,
        "gateway_mode": mode,
        "gateway_enabled": mode != "off",
        "gateway_layers": active_layers,
        "agent_mode": "deterministic",
        "agent_hijacked": res.hijacked,
        "was_attacked": res.was_attacked,
        "real_core_state_changed": res.was_attacked,
        "sessions_released": sessions_released,
        "identifier_leaked": res.identifier_leaked,
        "blocked_calls": len(blocked),
        "false_positive": meta.get("category") == "benign" and bool(blocked),
        "duration_sec": res.duration_sec,
        "gateway_overhead_ms": {
            "mean": round(sum(overheads) / len(overheads), 3) if overheads else None,
            "max": max(overheads) if overheads else None, "calls": len(overheads)},
        "tool_calls": [
            {"turn": c.turn, "tool_name": c.tool_name, "arguments": c.arguments,
             "result_status": c.result.get("status"),
             "is_dangerous": c.is_dangerous(), "changed_core_state": c.changed_core_state(),
             "blocked_by": ({"layer": c.result.get("layer"), "check": c.result.get("check"),
                             "violation": c.result.get("violation")} if c.was_blocked() else None)}
            for c in res.tool_calls],
        "gateway_decisions": decisions,
    }


def main() -> None:
    ap = argparse.ArgumentParser(description="Offline scenario × mode sweep -> evidence JSONL.")
    ap.add_argument("--out", default=os.path.join(ROOT, "benchmark", "offline_evidence.jsonl"))
    ap.add_argument("--n-ues", type=int, default=3,
                    help="testbed size; L3 rate cap (config max=2) only bites when n_ues > cap")
    ap.add_argument("--append", action="store_true", help="append instead of overwriting --out")
    args = ap.parse_args()

    logging.disable(logging.CRITICAL)       # keep the sweep quiet; the tables carry the story
    with open(os.path.join(ROOT, "config.yaml")) as f:
        cfg = yaml.safe_load(f)
    scenarios = load_scenarios()

    records = []
    for sid in sorted(scenarios):
        for _, mode, layers in MODES:
            records.append(run_cell(cfg, scenarios, sid, mode, layers, args.n_ues))

    with open(args.out, "a" if args.append else "w") as f:
        for r in records:
            f.write(json.dumps(r) + "\n")

    n_s, n_m = len(scenarios), len(MODES)
    print(f"swept {n_s} scenario(s) × {n_m} mode(s) = {len(records)} runs "
          f"(n_ues={args.n_ues}) -> {args.out}")
    print(f"next:  python3 tools/aggregate.py {args.out}")


if __name__ == "__main__":
    main()
