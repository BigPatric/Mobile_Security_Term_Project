#!/usr/bin/env python3
"""D3 — a real, network-initiated PDU-session release through the L1 gateway, with evidence.

Picks one UE that has an active session, triggers the release the way an agent would (it only
ever holds a token), and records three independent proofs to results/l1/release.json:
  1. the real SUPI appears only in the gateway's [TOOL] log, never in the agent's result;
  2. the SMF ReleaseSMContext call returns its real HTTP status (204 = torn down);
  3. the UE's data-plane tunnel goes from reachable to gone.

    python3 experiments/l1_release.py          # live free5GC
    python3 experiments/l1_release.py --sim 9  # simulated core (logic check, no real teardown)

HIGH-RISK on the live core: this really tears the session down. The UE can re-establish it.
"""
import argparse
import io
import json
import logging
import os
import sys
import time

import yaml

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agent import LocalToolClient, default_local_client
from free5gc_tools import core_state as cs
from gateway import build_l1_gateway
from gateway.l1 import Free5GCSource, SyncEngine
from gateway.secret import load_master_secret

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--sim", type=int, metavar="N")
    ap.add_argument("--out", default=os.path.join(ROOT, "results/l1/release.json"))
    a = ap.parse_args()

    # Capture the gateway's [TOOL] logs so we can show the real SUPI surfaces there (and nowhere else).
    buf = io.StringIO()
    h = logging.StreamHandler(buf)
    h.setFormatter(logging.Formatter("%(levelname)s %(message)s"))
    logging.getLogger().addHandler(h)
    logging.getLogger().setLevel(logging.INFO)

    with open(os.path.join(ROOT, "config.yaml")) as f:
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

    # Pick one UE with an active session. `supi`/`ref` are gateway-internal; the agent only gets `token`.
    target = next(((s, r) for s, r in sync.store.items()[1] if r.state.sessions), None)
    if target is None:
        raise SystemExit("no UE with an active PDU session — attach a UE first")
    supi, rec = target
    sess = rec.state.sessions[0]
    token = gw.tokenizer.token_for(supi)
    psi = sess.id
    ref = sess.ref

    # --- pre-state: independent probes straight at the core (not via the gateway) ---
    pre_ip = cs.pdu_session_ip(ref) if not core else None
    pre = {"amf_session_active": cs.amf_session_active(supi, psi) if not core else True,
           "smf_context_gone": cs.smf_context_gone(ref) if not core else False,
           "data_plane": cs.data_plane_probe(pre_ip) if not core else {"reachable": None}}

    # --- action: release exactly as the agent would — read the UE, take the etag it saw, release ---
    seen = gw.invoke("get_ue", {"supi_token": token})
    if_etag = next((s.get("etag") for s in seen.get("ue", {}).get("sessions", [])
                    if s.get("id") == psi), None)
    print(f"releasing (agent sees token {token!r}, psi={psi}, if_etag={if_etag!r}) ...")
    result = gw.invoke("trigger_pdu_session_release",
                       {"supi_token": token, "pdu_session_id": psi, "if_etag": if_etag})

    # --- post-state: same independent probes ---
    if not core:
        time.sleep(1.0)
    post = {"amf_session_gone": cs.amf_session_gone(supi, psi) if not core else None,
            "smf_context_gone": cs.smf_context_gone(ref) if not core else True,
            "data_plane": cs.data_plane_probe(pre_ip) if not core else {"reachable": None}}

    logs = buf.getvalue()
    agent_result_str = json.dumps(result)
    evidence = {
        "mode": "sim" if core else "live",
        "agent_side": {
            "supi_token": token,                       # all the agent ever holds
            "pdu_session_id": psi,
            "release_result": result,                  # returned to the agent (SUPI tokenized out)
            "real_supi_in_agent_result": supi in agent_result_str,   # must be False
        },
        "gateway_side": {
            "real_supi": supi,                         # known only inside the gateway / core
            "sm_context_ref": ref,
            "real_supi_in_tool_log": supi in logs,     # the real SUPI surfaces here (expected True)
            "tool_log": [ln for ln in logs.splitlines() if "[TOOL]" in ln or "[GW]" in ln],
        },
        "core_truth": {"pre": pre, "post": post,
                       "release_api": result.get("release_api"),
                       "verified": result.get("verified"), "status": result.get("status")},
    }
    os.makedirs(os.path.dirname(os.path.abspath(a.out)), exist_ok=True)
    with open(a.out, "w") as f:
        json.dump(evidence, f, indent=1)

    a_leak = evidence["agent_side"]["real_supi_in_agent_result"]
    print(f"\nstatus={result.get('status')} verified={result.get('verified')}")
    print(f"agent result holds the real SUPI? {a_leak}  (want False)")
    print(f"real SUPI in [TOOL] log?          {evidence['gateway_side']['real_supi_in_tool_log']}  (want True)")
    print(f"SMF context gone after release?   pre={pre['smf_context_gone']} -> post={post['smf_context_gone']}")
    if not core:
        print(f"data-plane tunnel up?             pre={pre['data_plane'].get('up')} "
              f"-> post={post['data_plane'].get('up')} ({pre['data_plane'].get('iface')})")
    print(f"-> {a.out}")


if __name__ == "__main__":
    main()
