#!/usr/bin/env python3
"""
experiments/l1_live_scale.py — privacy + sync cost on the LIVE core, at the attached N
======================================================================================
Run this AFTER provisioning N subscribers and attaching N UEs with UERANSIM. It
measures, against whatever is registered right now, the two claims the project
makes at scale and records one data point per N into results/l1/live_scale.json.

It isolates the question you care about — does keeping the secret (per-UE tokens)
cost update performance? — into three numbers per cycle:

  * sync_ms      one bulk GET + the versioned-store diff. No tokens. The update path.
  * token_cold_ms  HMAC a whole fresh epoch's worth of tokens (N mints). The one-time
                   cost the secret adds when an epoch turns over.
  * token_warm_ms  the same population re-tokenized from the per-epoch cache (~0).
  * view_ms      the real agent-facing view across all pages, tokens applied.

The story: sync_ms and view_ms stay ~flat as N grows (1 request/cycle, bounded pages),
and the secret's cost is token_cold_ms paid once per epoch, amortized to token_warm_ms
(~0) every other cycle. So privacy does not degrade the update.

    python3 experiments/l1_live_scale.py              # 5 cycles against the live core
    python3 experiments/l1_live_scale.py --cycles 10
    python3 experiments/l1_live_scale.py --out results/l1/live_scale.json

Requires the live stack up (core, gNB, attached UEs, WebConsole) — see README.
"""
from __future__ import annotations

import argparse
import json
import os
import statistics
import sys
import time

import yaml

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from agent import default_local_client  # noqa: E402
from free5gc_tools import core_state as cs  # noqa: E402
from gateway import build_l1_gateway  # noqa: E402
from gateway.l1 import Free5GCSource, IdentifierTokenizer, SyncEngine  # noqa: E402
from gateway.secret import load_master_secret  # noqa: E402


def enumerate_view(gw, limit):
    """Walk every page of the agent-facing list_ues. Returns (rows, bytes)."""
    rows, nbytes, token = [], 0, None
    while True:
        page = gw.invoke("list_ues", {"limit": limit, **({"page_token": token} if token else {})})
        ues = page.get("ues", [])
        rows += ues
        nbytes += len(json.dumps(page))
        token = page.get("next_page")
        if not token or not ues:
            break
    return rows, nbytes


def mint_all(secret, scope, supis, cfg_tokens):
    """Fresh tokenizer (empty cache) -> time the HMAC over the whole population."""
    tok = IdentifierTokenizer(secret, scope=scope, **{k: v for k, v in cfg_tokens.items()})
    t0 = time.perf_counter()
    toks = [tok.token_for(s) for s in supis]
    cold = (time.perf_counter() - t0) * 1000
    t0 = time.perf_counter()
    toks2 = [tok.token_for(s) for s in supis]          # second pass hits the cache
    warm = (time.perf_counter() - t0) * 1000
    unique = len(set(toks)) == len(toks)
    stable = toks == toks2
    return cold, warm, unique, stable, len(toks)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--cycles", type=int, default=5)
    ap.add_argument("--out", default=os.path.join(ROOT, "results", "l1", "live_scale.json"))
    a = ap.parse_args()

    with open(os.path.join(ROOT, "config.yaml")) as f:
        cfg = yaml.safe_load(f)
    cs.set_config(cfg)
    l1 = cfg["l1"]
    secret = load_master_secret()
    scope = os.urandom(8).hex()

    sync = SyncEngine(Free5GCSource(), **l1["sync"])
    if not sync.step():
        raise SystemExit(f"cannot read the live core: {sync.last_error}")
    gw = build_l1_gateway(default_local_client(), sync, l1, secret, scope=scope)

    n = len(sync.store)
    if n == 0:
        raise SystemExit("no UE registered — attach UEs with UERANSIM first (see README).")
    limit = int((l1.get("views") or {}).get("page_size", 50))
    print(f"live core: {n} UE registered; measuring {a.cycles} cycles "
          f"(poll every {sync.interval_sec}s, page size {limit})\n")

    cycles = []
    print(f"{'cyc':>3} {'ues':>5} {'sync_ms':>8} {'view_ms':>8} {'view_kb':>8} "
          f"{'tok_cold':>9} {'tok_warm':>9} {'stale':>6}")
    for i in range(a.cycles):
        time.sleep(sync.interval_sec)
        t0 = time.perf_counter()
        sync.step()                                     # the update path: bulk GET + diff
        sync_ms = (time.perf_counter() - t0) * 1000

        _, supis = sync.store.supis()
        cold, warm, unique, stable, minted = mint_all(secret, scope, supis, l1.get("tokens") or {})

        t0 = time.perf_counter()
        rows, nbytes = enumerate_view(gw, limit)        # the real agent view, tokens applied
        view_ms = (time.perf_counter() - t0) * 1000

        ues = len(sync.store)
        stale = sync.is_stale()
        cycles.append({"cycle": i + 1, "ues": ues, "sync_ms": round(sync_ms, 2),
                       "view_ms": round(view_ms, 2), "view_kb": round(nbytes / 1024, 3),
                       "token_cold_ms": round(cold, 3), "token_warm_ms": round(warm, 3),
                       "tokens_unique": unique, "tokens_stable": stable,
                       "view_rows": len(rows), "stale": stale,
                       "last_error": sync.last_error})
        print(f"{i+1:>3} {ues:>5} {sync_ms:>8.2f} {view_ms:>8.2f} {nbytes/1024:>8.3f} "
              f"{cold:>9.3f} {warm:>9.3f} {str(stale):>6}"
              + ("" if unique and stable else "  !! token anomaly"))

    def med(k):
        return round(statistics.median(c[k] for c in cycles), 3)

    point = {"n": n, "cycles": a.cycles, "interval_sec": sync.interval_sec,
             "page_size": limit, "sync_stats": sync.stats,
             "secret_source": "env MCP_GATEWAY_SECRET" if os.environ.get("MCP_GATEWAY_SECRET")
                              else "ephemeral (per-process)",
             "median": {"sync_ms": med("sync_ms"), "view_ms": med("view_ms"),
                        "view_kb": med("view_kb"), "token_cold_ms": med("token_cold_ms"),
                        "token_warm_ms": med("token_warm_ms")},
             "all_tokens_unique_and_stable": all(c["tokens_unique"] and c["tokens_stable"]
                                                 for c in cycles),
             "cycle_rows": cycles}

    os.makedirs(os.path.dirname(os.path.abspath(a.out)), exist_ok=True)
    existing = []
    if os.path.exists(a.out):
        try:
            prev = json.load(open(a.out))
            existing = prev.get("points", []) if isinstance(prev, dict) else []
        except (ValueError, OSError):
            existing = []
    existing = [p for p in existing if p.get("n") != n] + [point]
    existing.sort(key=lambda p: p["n"])
    with open(a.out, "w") as f:
        json.dump({"core": "live (free5GC v4.1.0 + UERANSIM)", "points": existing}, f, indent=1)

    print(f"\nmedian: sync {point['median']['sync_ms']}ms  view {point['median']['view_ms']}ms  "
          f"token_cold {point['median']['token_cold_ms']}ms  "
          f"token_warm {point['median']['token_warm_ms']}ms")
    print(f"secret: {point['secret_source']}; tokens unique+stable every cycle: "
          f"{point['all_tokens_unique_and_stable']}")
    print(f"-> {a.out}  ({len(existing)} N point(s): {[p['n'] for p in existing]})")


if __name__ == "__main__":
    main()
