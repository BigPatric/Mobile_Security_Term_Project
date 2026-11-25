#!/usr/bin/env python3
"""Run the L1 gateway and print what an agent sees.

    python3 run_l1.py                 # live free5GC (endpoints from config.yaml)
    python3 run_l1.py --sim 1000      # simulated core with churn
"""
import argparse
import json
import os
import time

import yaml

from agent import LocalToolClient, default_local_client
from free5gc_tools import core_state as cs
from gateway import build_l1_gateway
from gateway.l1 import Free5GCSource, SyncEngine
from gateway.secret import load_master_secret

if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--sim", type=int, metavar="N", help="use a simulated core with N UEs")
    ap.add_argument("--cycles", type=int, default=5)
    a = ap.parse_args()
    with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.yaml")) as f:
        cfg = yaml.safe_load(f)
    cs.set_config(cfg)
    core = None
    if a.sim:
        from sim import SimCore
        core = SimCore(a.sim)
    sync = SyncEngine(Free5GCSource(core.get if core else None), **cfg["l1"]["sync"])
    if not sync.step():
        raise SystemExit(f"cannot read the core: {sync.last_error}")
    gw = build_l1_gateway(LocalToolClient(core.tools()) if core else default_local_client(),
                          sync, cfg["l1"], load_master_secret(), scope=os.urandom(8).hex())

    def show(name, args=None):
        r = gw.invoke(name, args or {})
        print(f"\n> {name}({json.dumps(args or {})})  [{len(json.dumps(r))} bytes]\n{json.dumps(r, indent=1)[:900]}")
        return r
    cursor = show("get_network_summary")["cursor"]
    show("list_ues", {"limit": 2})
    for _ in range(a.cycles):
        if core:
            core.advance(sync.interval_sec)
        time.sleep(0.2 if core else sync.interval_sec)
        sync.step()
        cursor = show("get_changes", {"cursor": cursor})["cursor"]
    print("\nsync:", sync.stats)
