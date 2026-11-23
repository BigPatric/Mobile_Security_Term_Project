#!/usr/bin/env python3
"""
tools/double_release.py — what does a SECOND release of the same session do?
============================================================================
Measures the claim in Sec. V-B that the violation L3's FSM blocks for release
(releasing an already-released session) is harmless because the SMF no longer
holds the context. Runs WITHOUT the gateway (= --gateway off) on a live core:

    1. release <supi> PDU session 1 through the tool (the normal path)
    2. release the SAME SM-context ref again, straight at the SMF
    3. release it again through the tool (AMF view is stale after a direct
       SMF release, so the tool's own pre-check may still let it through)

Each step's real HTTP status is appended as one JSON line to --out.

    python3 tools/double_release.py --supi imsi-208930000000001 --supi imsi-208930000000002
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--supi", action="append", default=None,
                    help="victim SUPI (repeatable; default: UE 1 and UE 2)")
    ap.add_argument("--psi", type=int, default=1)
    ap.add_argument("--out", default=os.path.join(ROOT, "results", "evidence", "double_release.jsonl"))
    args = ap.parse_args()
    supis = args.supi or ["imsi-208930000000001", "imsi-208930000000002"]

    import yaml
    import free5gc_tools.core_state as cs
    import free5gc_tools.tools as tools
    with open(os.path.join(ROOT, "config.yaml")) as f:
        cfg = yaml.safe_load(f)
    tools._CFG = cfg
    cs.set_config(cfg)

    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    ok = True
    for supi in supis:
        first = tools.trigger_pdu_session_release(supi, args.psi)
        ref = first.get("sm_context_ref")
        rec = {
            "run_timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "supi": supi, "pdu_session_id": args.psi, "sm_context_ref": ref,
            "first": {"status": first.get("status"), "verified": first.get("verified"),
                      "smf_http_status": (first.get("release_api") or {}).get("http_status"),
                      "post_probe": first.get("post_probe")},
        }
        if first.get("status") != "ok" or not ref:
            rec["error"] = "first release did not verify; second release not attempted"
            ok = False
        else:
            second = cs.smf_release_sm_context(ref)
            rec["second_direct_smf"] = {"http_status": second.status_code, "body": second.detail}
            third = tools.trigger_pdu_session_release(supi, args.psi)
            rec["second_via_tool"] = {"status": third.get("status"), "verified": third.get("verified"),
                                      "smf_http_status": (third.get("release_api") or {}).get("http_status"),
                                      "detail": third.get("detail") or third.get("error")}
        with open(args.out, "a") as f:
            f.write(json.dumps(rec, default=str) + "\n")
        print(json.dumps(rec, indent=2, default=str), flush=True)
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
