#!/usr/bin/env python3
"""Run the L1 gateway and print what an agent sees.

    python3 run_l1.py                 # live free5GC: 5-cycle demo (endpoints from config.yaml)
    python3 run_l1.py --sim 1000      # simulated core with churn
    python3 run_l1.py --serve         # gateway terminal: poll forever, stream status + [TOOL] logs
"""
import argparse
import json
import logging
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
    ap.add_argument("--serve", action="store_true",
                    help="run as the gateway terminal: poll every interval forever and stream status")
    ap.add_argument("--proof", action="store_true",
                    help="show one UE's real record (inside the gateway) next to what the agent sees")
    ap.add_argument("--out", metavar="PATH",
                    help="write per-cycle evidence (version/ues/bytes/changes/stale) to a JSON file")
    a = ap.parse_args()
    # Stream the tools' [TOOL]/[SMF] logs (incl. the real SUPI on a release) to this terminal.
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s",
                        datefmt="%H:%M:%S")
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

    if a.proof:
        # Privacy, shown: one UE as the gateway holds it (real identity) vs what the agent gets.
        version, items = sync.store.items()
        if not items:
            raise SystemExit("no UE in the store — attach a UE (live) or use --sim N")
        supi, rec = items[0]
        token = gw.tokenizer.token_for(supi)
        real = {"supi": rec.state.supi, "tac (location)": rec.state.tac,
                "sessions": [{"id": s.id, "dnn": s.dnn, "slice": f"{s.sst}-{s.sd}",
                              "sm_context_ref": s.ref} for s in rec.state.sessions]}
        seen = gw.invoke("get_ue", {"supi_token": token})
        print("=" * 72)
        print("INSIDE THE GATEWAY — real identity (never leaves the gateway):\n")
        print(json.dumps(real, indent=1))
        print("\nWHAT THE AGENT SEES — get_ue(supi_token):\n")
        print(json.dumps(seen, indent=1))
        print("\n" + "-" * 72)
        print(f"SUPI            {real['supi']!r:>40}   ->  token {token!r}")
        if real["sessions"]:
            ref = real["sessions"][0]["sm_context_ref"]
            etag = seen.get("ue", {}).get("sessions", [{}])[0].get("etag")
            print(f"SM-context ref  {ref!r:>40}   ->  etag  {etag!r}")
        print(f"TAC (location)  {real['tac (location)']!r:>40}   ->  (absent from the view)")
        # The oracle defense: a known SUPI planted in an untrusted log is masked, not tokenized.
        planted = gw.invoke("get_alert_logs", {"log_id": "__none__"})
        print("-" * 72)
        print("Planted-identifier oracle: untrusted results mask, they do not tokenize "
              "(masked != token, so no lookup).")
        print(f"  get_alert_logs -> {json.dumps(planted)[:120]}")
        raise SystemExit(0)

    if a.serve:
        # Gateway terminal: one line of live status per poll cycle, forever.
        print(f"L1 gateway up — polling every {sync.interval_sec}s, Ctrl-C to stop\n"
              f"{'time':>8} {'ver':>6} {'ues':>6} {'age':>6} {'stale':>6}  stats")
        n = 0
        try:
            while True:
                if core:
                    core.advance(sync.interval_sec)
                time.sleep(0.5 if core else sync.interval_sec)
                sync.step()
                n += 1
                s = gw.invoke("get_network_summary", {})
                print(f"{time.strftime('%H:%M:%S'):>8} {sync.store.version:>6} "
                      f"{s.get('ues', '-'):>6} {str(s.get('age_sec', '-')):>6} "
                      f"{str(s.get('stale', '-')):>6}  {sync.stats}"
                      + (f"  ERR={sync.last_error}" if sync.last_error else ""), flush=True)
                if n % 5 == 0:   # every 5 cycles, show what the agent actually gets (tokens only)
                    view = gw.invoke("list_ues", {"limit": 2}).get("ues", [])
                    print(f"         agent view: {json.dumps(view)[:200]}", flush=True)
        except KeyboardInterrupt:
            print(f"\nstopped. sync: {sync.stats}")
        raise SystemExit(0)

    summary = show("get_network_summary")
    cursor = summary["cursor"]
    show("list_ues", {"limit": 2})
    rows = [{"cycle": 0, "version": sync.store.version, "ues": summary.get("ues"),
             "summary_bytes": len(json.dumps(summary)), "stale": summary.get("stale"),
             "age_sec": summary.get("age_sec")}]
    for i in range(a.cycles):
        if core:
            core.advance(sync.interval_sec)
        time.sleep(0.2 if core else sync.interval_sec)
        t0 = time.perf_counter()
        sync.step()                                   # the bulk GET round-trip (real network, live)
        poll_ms = round((time.perf_counter() - t0) * 1000, 2)
        ch = show("get_changes", {"cursor": cursor})
        cursor = ch["cursor"]
        rows.append({"cycle": i + 1, "version": sync.store.version,
                     "ues": gw.invoke("get_network_summary", {}).get("ues"),
                     "changes": len(ch.get("updated", [])) + len(ch.get("removed", [])),
                     "change_bytes": len(json.dumps(ch)), "poll_ms": poll_ms,
                     "resync_required": ch.get("resync_required", False),
                     "stale": ch.get("stale"), "age_sec": ch.get("age_sec")})
    print("\nsync:", sync.stats)
    if a.out:
        out = {"mode": "sim" if core else "live", "n_cycles": a.cycles,
               "interval_sec": sync.interval_sec, "sync_stats": sync.stats,
               "last_error": sync.last_error, "cycles": rows}
        os.makedirs(os.path.dirname(os.path.abspath(a.out)), exist_ok=True)
        with open(a.out, "w") as f:
            json.dump(out, f, indent=1)
        print(f"-> {a.out}")
