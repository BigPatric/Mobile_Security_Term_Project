#!/usr/bin/env python3
"""
experiments/provision_subscribers.py — bulk-provision N subscribers in the LIVE free5GC
=======================================================================================
Live UEs can only attach to IMSIs that already exist in free5GC's subscriber DB,
all sharing the key/OPc in UERANSIM/config/free5gc-ue.yaml. This script creates
N consecutive subscribers in ONE WebConsole REST call, using free5GC's own bulk
endpoint:

    POST /api/subscriber/{templateSupi}/{plmn}/{N}

The body is a full SubsData object. Rather than hand-craft it (and risk drifting
from free5GC v4.1.0's schema), we fetch the ONE subscriber that already exists
(the UERANSIM default, imsi-208930000000001) with GET /api/subscriber/{supi}/{plmn}
and repost it — the WebConsole's GET returns exactly the SubsData shape POST wants.
free5GC increments the IMSI (and the msisdn GPSI) for each of the N copies.

    python3 experiments/provision_subscribers.py 1000          # create 1000 from the default
    python3 experiments/provision_subscribers.py 1000 --from imsi-208930000000001
    python3 experiments/provision_subscribers.py --check       # how many subscribers exist now

After this, start UERANSIM with `nr-ue -c ... -n N` and the N UEs can register.
This writes to the live core; it does not touch the gateway or any token.
"""
from __future__ import annotations

import argparse
import os
import sys
import time

import yaml

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from free5gc_tools import core_state as cs  # noqa: E402


def load_cfg():
    with open(os.path.join(ROOT, "config.yaml")) as f:
        cfg = yaml.safe_load(f)
    cs.set_config(cfg)
    return cfg


def count_subscribers() -> int:
    resp = cs.wc_get("/api/subscriber")
    if not resp.ok:
        raise SystemExit(f"GET /api/subscriber -> HTTP {resp.status_code}")
    data = resp.json()
    return len(data) if isinstance(data, list) else 0


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("n", type=int, nargs="?", help="number of subscribers to create")
    ap.add_argument("--from", dest="template", default="imsi-208930000000001",
                    help="existing subscriber to copy (default: the UERANSIM default IMSI)")
    ap.add_argument("--check", action="store_true", help="only report the current count")
    a = ap.parse_args()

    cfg = load_cfg()
    plmn = str(cfg["free5gc"]["plmn_id"])
    try:
        _run(a, plmn)
    except cs.CoreUnavailable as e:
        raise SystemExit(f"live core not reachable: {e}\n"
                         f"Start free5GC + the WebConsole first (see README).")


def _run(a, plmn: str) -> None:

    if a.check or a.n is None:
        print(f"subscribers currently in free5GC: {count_subscribers()}")
        if a.n is None:
            return

    template = cs.norm_supi(a.template)
    before = count_subscribers()
    print(f"template subscriber: {template} (plmn {plmn}); {before} subscriber(s) exist now")

    resp = cs.wc_get(f"/api/subscriber/{template}/{plmn}")
    if not resp.ok:
        raise SystemExit(f"cannot read template {template}: HTTP {resp.status_code}. "
                         f"Provision at least one subscriber in the WebConsole first.")
    body = resp.json()

    t0 = time.perf_counter()
    resp = cs.wc_post(f"/api/subscriber/{template}/{plmn}/{a.n}", body,
                      timeout=max(60, a.n // 5))
    dt = time.perf_counter() - t0
    if not resp.ok:
        raise SystemExit(f"bulk create failed: HTTP {resp.status_code} {resp.text[:300]}")

    after = count_subscribers()
    print(f"POST .../{a.n} -> HTTP {resp.status_code} in {dt:.1f}s; "
          f"subscribers now: {after} (+{after - before})")
    print("Next: cd UERANSIM && sudo ./build/nr-ue -c config/free5gc-ue.yaml "
          f"-n {a.n} -t 2000   (let them register, then run the gateway)")


if __name__ == "__main__":
    main()
