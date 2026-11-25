#!/usr/bin/env python3
"""
experiments/l1_scale.py — L1 privacy and synchronization at 9 … 5000 UEs
========================================================================
SIMULATED core (sim/fake_free5gc.py), not the live testbed. Writes results/l1/scale.json
and prints the tables quoted in docs/L1_RESULTS.md.

    python3 experiments/l1_scale.py

E1 tokens    v1 16-bit tokens vs. the current ones (two gateways, one key)
E2 sync      requests and bytes per cycle; staleness the agent's view really has
E3 payload   bytes handed to the agent
E4 leakage   real identifiers reaching an agent that reads everything
E5 actions   release aimed at a session the agent saw `delay` seconds ago
E6 gateway   CPU time per call (wall clock, this machine)
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import platform
import random
import statistics
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import yaml  # noqa: E402

from agent.tool_client import LocalToolClient  # noqa: E402
from gateway import build_l1_gateway  # noqa: E402
from gateway.l1 import Free5GCSource, IdentifierTokenizer, SyncEngine  # noqa: E402
from sim import SimCore, serve  # noqa: E402

NS = (9, 100, 1000, 5000)
SEEDS = range(5)
KEY = b"x" * 32
REL = "trigger_pdu_session_release"
with open(os.path.join(ROOT, "config.yaml")) as f:
    CFG = yaml.safe_load(f)["l1"]


class Clock:
    def __init__(self, t=0.0):
        self.t = t

    def __call__(self):
        return self.t


class V1Tokenizer:
    """The token rule at commit 03a6e45: 16 bits, lengthened on collision."""

    def __init__(self, key):
        self.key, self.fwd, self.rev = key, {}, {}

    def token_for(self, supi):
        if supi not in self.fwd:
            d, n = hmac.new(self.key, supi.encode(), hashlib.sha256).hexdigest(), 4
            while self.rev.get(d[:n], supi) != supi:
                n += 1
            self.fwd[supi], self.rev[d[:n]] = d[:n], supi
        return self.fwd[supi]


def mean(xs):
    return statistics.fmean(xs)


def make(core, clock, wall, policy_fresh=True, **kw):
    sync = SyncEngine(Free5GCSource(core.get), now_fn=clock, **kw)
    sync.step()
    cfg = json.loads(json.dumps(CFG))
    if not policy_fresh:                     # E5 baseline
        cfg["policy"]["tools"][REL]["checks"] = ["identifier"]
    return sync, build_l1_gateway(LocalToolClient(core.tools()), sync, cfg, KEY, "s", now_fn=wall)


def pages(gw):
    page, out = "", []
    while page is not None:
        r = gw.invoke("list_ues", {"page_token": page} if page else {})
        out.append(r)
        page = r["next_page"]
    return out


def e1():
    rows = []
    for n in (*NS, 10000):
        supis = SimCore(n, registered=0).supis
        res = {"v1": ([], []), "now": ([], [])}
        for seed in range(20):
            key = hashlib.sha256(bytes([seed])).digest()
            for name, mk in (("v1", lambda: V1Tokenizer(key)), ("now", lambda: IdentifierTokenizer(key))):
                a, b = mk(), mk()
                order = supis[:]
                random.Random(seed).shuffle(order)
                for s in supis:
                    a.token_for(s)
                for s in order:
                    b.token_for(s)
                rev = b.rev if name == "v1" else b._rev[0]
                res[name][0].append(sum(a.token_for(s) != b.token_for(s) for s in supis))
                res[name][1].append(sum(rev.get(a.token_for(s), s) != s for s in supis))
        rows.append({"n": n, **{f"{k}_disagree": mean(v[0]) for k, v in res.items()},
                     **{f"{k}_wrong_ue": mean(v[1]) for k, v in res.items()},
                     "v1_runs_with_wrong_ue": sum(x > 0 for x in res["v1"][1])})
    return rows


def e2():
    from free5gc_tools import core_state as cs
    cost, stale = [], []
    for n in NS:
        core = SimCore(n)
        srv, url = serve(core)
        try:
            cs._wc_token = ""
            cs.set_config({"free5gc": {"webconsole_url": url, "username": "a", "password": "b", "plmn_id": "20893"}})
            cs._get_token()
            core.requests = core.bytes = 0
            src = Free5GCSource()
            t = time.perf_counter()
            src.snapshot()
            bulk = (core.requests, core.bytes, (time.perf_counter() - t) * 1e3)
            core.requests = core.bytes = 0
            t = time.perf_counter()
            if n <= 1000:                                        # v1: list, then 2-3 GETs per UE
                cs.wc_get("/api/subscriber")
                for s in core.supis:
                    cs.subscriber_profile(s)
                    for p in cs.registered_ue_context(s)["pdu_sessions"]:
                        cs.user_plane_activated(p["sm_context_ref"])
                ms = (time.perf_counter() - t) * 1e3
            else:        # one TCP connection per request runs out of local ports: count only
                v1 = core.tools()
                v1["list_subscribers"]()
                for s in core.supis:
                    v1["query_subscriber_session"](s)
                ms = None
            per = (core.requests, core.bytes, ms)
        finally:
            srv.shutdown()
            srv.server_close()
        cost.append({"n": n, "bulk_requests": bulk[0], "bulk_kb": bulk[1] / 1e3, "bulk_ms": bulk[2],
                     "per_ue_requests": per[0], "per_ue_kb": per[1] / 1e3, "per_ue_ms": per[2]})
    for interval in (1, 2, 5, 10, 30):       # fraction of UEs whose shown state is wrong, 1000 UEs
        wrong, total, reqs = 0, 0, 0
        for seed in SEEDS:
            core, clock, wall = SimCore(1000, seed), Clock(), Clock(3600 * 100 + 600)
            sync, _ = make(core, clock, wall, interval_sec=interval, audit_per_cycle=0)
            core.requests = 0
            for tick in range(1, 601):       # 60 s at 0.1 s
                core.advance(0.1)
                clock.t = tick / 10
                if tick % (interval * 10) == 0:
                    sync.step()
                have = {u: (r.state.cm_state, tuple(s.ref for s in r.state.sessions))
                        for u, r in sync.store.items()[1]}
                real = {u: (x["cm"], tuple(v[0] for _, v in sorted(x["sess"].items())))
                        for u, x in core.ues.items()}
                wrong += sum(have.get(u) != real.get(u) for u in have.keys() | real.keys())
                total += len(have.keys() | real.keys())
            reqs += core.requests
        stale.append({"interval_s": interval, "wrong_pct": 100 * wrong / total,
                      "requests_per_min": reqs / len(SEEDS)})
    return cost, stale


def e3():
    rows = []
    for n in NS:
        core, clock, wall = SimCore(n), Clock(), Clock(3600 * 100 + 600)
        sync, gw = make(core, clock, wall, audit_per_cycle=0)
        dump = len(json.dumps(core.tools()["list_subscribers"]())) + sum(
            len(json.dumps(core.tools()["query_subscriber_session"](s))) for s in core.supis)
        first = gw.invoke("get_network_summary", {})
        pgs = pages(gw)
        cur, deltas, resyncs = first["cursor"], [], 0
        for _ in range(30):
            core.advance(2)
            clock.t += 2
            sync.step()
            r = gw.invoke("get_changes", {"cursor": cur})
            cur = r["cursor"]
            resyncs += r["resync_required"]
            if not r["resync_required"]:
                deltas.append(len(json.dumps(r)))
        rows.append({"n": n, "v1_full_bytes": dump, "summary_bytes": len(json.dumps(first)),
                     "page_bytes_max": max(len(json.dumps(p)) for p in pgs),
                     "all_pages_bytes": sum(len(json.dumps(p)) for p in pgs), "pages": len(pgs),
                     "delta_2s_bytes_mean": mean(deltas) if deltas else None, "delta_resyncs_of_30": resyncs})
    return rows


def e4():
    rows = []
    for n in NS:
        core, clock, wall = SimCore(n), Clock(), Clock(3600 * 100 + 600)
        sync, gw = make(core, clock, wall, audit_per_cycle=0)
        core.alert = f"UE {core.supis[0]} / {core.gpsi[core.supis[0]]} degraded"
        rel = lambda: next(u for p in pages(gw) for u in p["ues"] if u["sessions"])  # noqa: E731
        u = rel()
        seen = json.dumps([pages(gw), gw.invoke("get_network_summary", {}),
                           gw.invoke("get_alert_logs", {"log_id": "a"}),
                           gw.invoke(REL, {"supi_token": u["supi_token"], "pdu_session_id": 1,
                                           "if_etag": u["sessions"][0]["etag"]})])
        tools = core.tools()
        raw = [tools["list_subscribers"]()] + [tools["query_subscriber_session"](s) for s in core.supis] \
            + [tools["get_alert_logs"]("a")]
        # v1 replaced SUPIs only
        import re
        v1 = re.sub(r"(?:imsi-)?\d{15}", "token", json.dumps(raw))
        ids = core.real_identifiers()
        rows.append({"n": n, "no_gateway": sum(i in json.dumps(raw) for i in ids) if n <= 1000 else None,
                     "v1": sum(i in v1 for i in ids) if n <= 1000 else None,
                     "now": sum(i in seen for i in ids), "identifiers_checked": len(ids)})
    return rows


def e5():
    rows = []
    for delay in (0, 2, 10, 30, 120):
        out = {False: {"hit_intended": 0, "hit_other": 0, "refused": 0, "tries": 0},
               True: {"hit_intended": 0, "hit_other": 0, "refused": 0, "tries": 0}}
        false_block, live = 0, 0
        for fresh in (False, True):
            for seed in SEEDS:
                core, clock, wall = SimCore(1000, seed), Clock(), Clock(3600 * 100 + 600)
                sync, gw = make(core, clock, wall, policy_fresh=fresh, audit_per_cycle=0)
                seen = []
                for p in pages(gw):
                    for u in p["ues"]:
                        if u["sessions"]:
                            supi = gw.tokenizer.resolve(u["supi_token"])
                            seen.append((u, supi, core.ues[supi]["sess"][1][0]))
                for _ in range(delay * 2):
                    core.advance(0.5)
                    clock.t += 0.5
                    if clock.t % 2 == 0:
                        sync.step()
                for u, supi, ref in random.Random(seed).sample(seen, 200):
                    still = ref in core.smf
                    now = core.ues.get(supi, {"sess": {}})["sess"].get(1)
                    other = now is not None and now[0] != ref and now[0] in core.smf
                    args = {"supi_token": u["supi_token"], "pdu_session_id": 1}
                    if fresh:
                        args["if_etag"] = u["sessions"][0]["etag"]
                    gw.invoke(REL, args)
                    o = out[fresh]
                    o["tries"] += 1
                    if still and ref not in core.smf:
                        o["hit_intended"] += 1
                    elif other and now[0] not in core.smf:
                        o["hit_other"] += 1
                    else:
                        o["refused"] += 1
                        if fresh and still:
                            false_block += 1
                    live += fresh and still
        rows.append({"delay_s": delay, "tries": out[True]["tries"],
                     **{f"off_{k}": v for k, v in out[False].items() if k != "tries"},
                     **{f"on_{k}": v for k, v in out[True].items() if k != "tries"},
                     "on_false_blocks": false_block, "on_still_valid": live})
    return rows


def e6():
    rows = []
    for n in NS:
        core, clock, wall = SimCore(n), Clock(), Clock(3600 * 100 + 600)
        sync, gw = make(core, clock, wall, audit_per_cycle=0)
        tok = pages(gw)[0]["ues"][0]["supi_token"]

        def med(fn, reps=30):
            ts = []
            for _ in range(reps):
                t = time.perf_counter()
                fn()
                ts.append((time.perf_counter() - t) * 1e3)
            return statistics.median(ts)
        cold = []
        for e in range(5):
            wall.t += 3600
            t = time.perf_counter()
            gw.invoke("list_ues", {})
            cold.append((time.perf_counter() - t) * 1e3)
        tok = pages(gw)[0]["ues"][0]["supi_token"]
        rows.append({"n": n, "get_ue_ms": med(lambda: gw.invoke("get_ue", {"supi_token": tok})),
                     "list_page_ms": med(lambda: gw.invoke("list_ues", {})),
                     "summary_ms": med(lambda: gw.invoke("get_network_summary", {})),
                     "first_list_after_rotation_ms": statistics.median(cold),
                     "poll_cycle_ms": med(sync.step, 10)})
    return rows


def table(title, rows):
    print(f"\n{title}")
    keys = list(rows[0])
    fmt = lambda v: "-" if v is None else (f"{v:.2f}" if isinstance(v, float) else str(v))  # noqa: E731
    print(" | ".join(keys))
    for r in rows:
        print(" | ".join(fmt(r[k]) for k in keys))


if __name__ == "__main__":
    import logging
    logging.disable(logging.CRITICAL)
    out = {"core": "simulated (sim/fake_free5gc.py)", "churn_per_ue_per_s": SimCore.RATES,
           "python": platform.python_version(), "machine": platform.platform(),
           "date": time.strftime("%Y-%m-%d")}
    out["E1"] = e1()
    out["E2_cost"], out["E2_staleness"] = e2()
    out["E3"], out["E4"], out["E5"], out["E6"] = e3(), e4(), e5(), e6()
    for k, v in out.items():
        if isinstance(v, list):
            table(k, v)
    path = os.path.join(ROOT, "results", "l1", "scale.json")
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        json.dump(out, f, indent=1)
    print(f"\n-> {os.path.relpath(path, ROOT)}")
