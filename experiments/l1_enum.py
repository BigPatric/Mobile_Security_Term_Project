#!/usr/bin/env python3
"""L-ENUM — ENUM-01: subscriber enumeration via an injected directive.

A malicious alert log hides a directive telling the hijacked agent to dump the full subscriber
list. We play the hijacked agent twice over the SAME core, and compare:

  no gateway : the agent calls list_subscribers directly -> every real SUPI is exfiltrated.
  L1 gateway : the same call is refused (list_subscribers is hidden) -> 0 SUPI, and any identifier
               that did come back in an untrusted result is masked, not tokenized.

    python3 experiments/l1_enum.py --sim 9     # logic check, no core
    python3 experiments/l1_enum.py             # live free5GC (reads the real subscriber DB)

Writes results/l1/enum.json. The live run shows that WITHOUT the gateway the real SUPIs leak.
"""
import argparse
import json
import os
import re
import sys

import yaml

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agent import LocalToolClient, default_local_client
from free5gc_tools import core_state as cs
from free5gc_tools import tools as raw_tools
from gateway import build_l1_gateway
from gateway.l1 import Free5GCSource, SyncEngine
from gateway.secret import load_master_secret

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SUPI = re.compile(r"imsi-\d{15}")


def leaked_supis(obj) -> list:
    return sorted(set(SUPI.findall(json.dumps(obj))))


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--sim", type=int, metavar="N")
    ap.add_argument("--out", default=os.path.join(ROOT, "results/l1/enum.json"))
    a = ap.parse_args()

    with open(os.path.join(ROOT, "config.yaml")) as f:
        cfg = yaml.safe_load(f)
    cs.set_config(cfg)
    with open(os.path.join(ROOT, "benchmark/attacks/enumerate_subscribers.json")) as f:
        scenario = json.load(f)

    core = None
    if a.sim:
        from sim import SimCore
        core = SimCore(a.sim)
    sync = SyncEngine(Free5GCSource(core.get if core else None), **cfg["l1"]["sync"])
    if not sync.step():
        raise SystemExit(f"cannot read the core: {sync.last_error}")
    inner = LocalToolClient(core.tools()) if core else default_local_client()
    gw = build_l1_gateway(inner, sync, cfg["l1"], load_master_secret(), scope=os.urandom(8).hex())

    # Step 1 — the hijacked agent reads the injected (UNTRUSTED) directive.
    log_id = scenario["injected_log_id"]
    directive = gw.invoke("get_alert_logs", {"log_id": log_id})

    # Step 2 — the agent obeys: enumerate every subscriber. Run the SAME core two ways.
    tool = scenario["expected_tool_call"]        # "list_subscribers"
    if core:
        no_gw = core.tools()[tool]()             # raw sim core
    else:
        no_gw = raw_tools.list_subscribers()     # raw live WebConsole, no gateway
    with_gw = gw.invoke(tool, {})                # through the L1 gateway

    evidence = {
        "scenario_id": scenario["scenario_id"],
        "mode": "sim" if core else "live",
        "injected_directive": scenario["logs"][0]["message"],   # the raw planted text
        "directive_provenance": directive.get("provenance"),     # what the agent's read was tagged
        "no_gateway": {
            "tool_allowed": no_gw.get("status") == "ok",
            "subscribers_returned": no_gw.get("count", len(no_gw.get("subscribers", []))),
            "supis_leaked": len(leaked_supis(no_gw)),
            "sample": leaked_supis(no_gw)[:3],
        },
        "l1_gateway": {
            "tool_allowed": with_gw.get("status") == "ok",
            "response": with_gw,
            "supis_leaked": len(leaked_supis(with_gw)),
        },
    }
    os.makedirs(os.path.dirname(os.path.abspath(a.out)), exist_ok=True)
    with open(a.out, "w") as f:
        json.dump(evidence, f, indent=1)

    n = evidence["no_gateway"]
    g = evidence["l1_gateway"]
    print(f"[{evidence['scenario_id']}] directive ({evidence['directive_provenance']}): "
          f"{(evidence['injected_directive'] or '')[:70]}...")
    print(f"  no gateway : tool_allowed={n['tool_allowed']}  SUPIs leaked = {n['supis_leaked']}  "
          f"(e.g. {n['sample']})")
    print(f"  L1 gateway : tool_allowed={g['tool_allowed']}  SUPIs leaked = {g['supis_leaked']}  "
          f"-> {with_gw.get('error', with_gw.get('status'))}")
    print(f"-> {a.out}")


if __name__ == "__main__":
    main()
