#!/usr/bin/env python3
"""
tools/_wait_sessions.py — block until N UEs have an ACTIVE PDU session
======================================================================
Readiness probe used by tools/run_live_matrix.sh between bring-up and the demo
run. Uses the project's OWN core_state helpers so it checks exactly the signal
run_attack_demo.py gates on (AMF-registered active PDU session), not a guess.

    python3 tools/_wait_sessions.py --need 3 --timeout 60
Exit 0 once >= --need victims have an active session; exit 1 on timeout.
"""

from __future__ import annotations

import argparse
import os
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--need", type=int, default=3)
    ap.add_argument("--timeout", type=float, default=60.0)
    ap.add_argument("--interval", type=float, default=2.0)
    args = ap.parse_args()

    try:
        import yaml
        import free5gc_tools.core_state as cs
        with open(os.path.join(ROOT, "config.yaml")) as f:
            cfg = yaml.safe_load(f)
        cs.set_config(cfg)
    except Exception as e:                       # deps missing / import error
        print(f"[wait] cannot import core_state ({e}); falling back to a fixed wait", flush=True)
        time.sleep(min(args.timeout, 30))
        sys.exit(0)

    supis = [f"imsi-20893000000000{i}" for i in range(1, args.need + 1)]
    deadline = time.time() + args.timeout
    while True:                                  # always probe at least once (--timeout 0 = one check)
        active = 0
        for s in supis:
            try:
                if cs.amf_session_active(s, 1):
                    active += 1
            except Exception:
                pass
        print(f"[wait] {active}/{args.need} active PDU session(s)", flush=True)
        if active >= args.need:
            sys.exit(0)
        if time.time() + args.interval > deadline:
            break
        time.sleep(args.interval)
    print(f"[wait] TIMEOUT after {args.timeout:g}s", flush=True)
    sys.exit(1)


if __name__ == "__main__":
    main()
