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


def _supi_int(supi: str) -> int:
    """Digits of an 'imsi-<15 digits>' id as an int."""
    return int(cs.norm_supi(str(supi))[len("imsi-"):])


def list_subscribers() -> list:
    resp = cs.wc_get("/api/subscriber")
    if not resp.ok:
        raise SystemExit(f"GET /api/subscriber -> HTTP {resp.status_code}")
    data = resp.json()
    return data if isinstance(data, list) else []


def count_subscribers() -> int:
    return len(list_subscribers())


def max_existing_imsi() -> int:
    """Highest IMSI currently provisioned, 0 if none."""
    vals = []
    for s in list_subscribers():
        ueid = s.get("ueId") if isinstance(s, dict) else None
        if ueid:
            try:
                vals.append(_supi_int(ueid))
            except ValueError:
                pass
    return max(vals) if vals else 0


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("n", type=int, nargs="?", help="number of subscribers to create")
    ap.add_argument("--from", dest="template", default="imsi-208930000000001",
                    help="existing subscriber to copy (default: the UERANSIM default IMSI)")
    ap.add_argument("--start", type=int, default=None,
                    help="first IMSI to create (digits or full imsi-...). "
                         "Default: one past the highest IMSI that already exists.")
    ap.add_argument("--keep-gpsi", action="store_true",
                    help="keep the template's msisdn (this endpoint reuses one gpsi for all N, "
                         "so it collides unless blanked). Default blanks it.")
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

    # The bulk endpoint numbers from the path ueId upward, so starting at an IMSI
    # that already exists is an immediate 409. Start one past the highest existing.
    if a.start is not None:
        # a full 15-digit IMSI, else a small offset added to the template base
        start = a.start if a.start >= 10 ** 14 else _supi_int(template) + a.start
    else:
        start = max_existing_imsi() + 1
    start_imsi = f"imsi-{start:015d}"
    end_imsi = f"imsi-{start + a.n - 1:015d}"
    print(f"template: {template} (plmn {plmn}); {before} subscriber(s) exist now")
    print(f"creating {a.n}: {start_imsi} .. {end_imsi}")

    resp = cs.wc_get(f"/api/subscriber/{template}/{plmn}")
    if not resp.ok:
        raise SystemExit(f"cannot read template {template}: HTTP {resp.status_code}. "
                         f"Provision at least one subscriber in the WebConsole first.")
    body = resp.json()

    # This endpoint reuses ONE gpsi string for all N, so the template's msisdn would
    # collide with its owner. Blank it (SUPI-based attach needs no msisdn) unless asked.
    if not a.keep_gpsi:
        amd = body.get("AccessAndMobilitySubscriptionData")
        if isinstance(amd, dict) and isinstance(amd.get("gpsis"), list) and amd["gpsis"]:
            amd["gpsis"] = [""]          # keep length >= 1; handler indexes gpsis[0]

    t0 = time.perf_counter()
    resp = cs.wc_post(f"/api/subscriber/{start_imsi}/{plmn}/{a.n}", body,
                      timeout=max(60, a.n // 5))
    dt = time.perf_counter() - t0
    if not resp.ok:
        raise SystemExit(f"bulk create failed: HTTP {resp.status_code} {resp.text[:300]}")

    after = count_subscribers()
    print(f"POST .../{start_imsi}/{plmn}/{a.n} -> HTTP {resp.status_code} in {dt:.1f}s; "
          f"subscribers now: {after} (+{after - before})")
    print(f"Next: cd UERANSIM && sudo ./build/nr-ue -c config/free5gc-ue.yaml "
          f"-n {a.n} -t 2000   (its IMSI base must match {start_imsi})")


if __name__ == "__main__":
    main()
