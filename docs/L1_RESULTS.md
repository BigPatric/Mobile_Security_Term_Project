# L1 results (simulated core)

**Simulated, not live.** `python3 experiments/l1_scale.py` against [sim/fake_free5gc.py](../sim/fake_free5gc.py),
2026-11-25; raw numbers in [results/l1/scale.json](../results/l1/scale.json). Churn per UE per second:
attach/detach 0.002, session up/down 0.005, idle/connected 0.02, move 0.005. The simulator models the
REST interfaces, not radio, NAS or NF load, so times are gateway + local HTTP only.

**E1. Tokens.** Two gateways with the same key that see the UEs in different order (mean of 20 keys).

| UEs | v1 tokens that differ | v1 tokens resolving to the **wrong UE** | now |
|---|---|---|---|
| 100 | 0 | 0 | 0 / 0 |
| 1000 | 8.7 | 4.6 (in 20 of 20 runs) | 0 / 0 |
| 5000 | 176 | 93 | 0 / 0 |
| 10000 | 704 | 375 | 0 / 0 |

A single v1 gateway is consistent with itself; this appears with a second gateway or a restart under one key.

**E2. Cost of one synchronization cycle.**

| UEs | bulk: requests, KB, ms | per UE (v1 tools): requests, KB, ms |
|---|---|---|
| 100 | 1, 27, 3 | 290, 53, 270 |
| 1000 | 1, 274, 12 | 2890, 529, 2617 |
| 5000 | 1, 1383, 34 | 14487, 2661, not timed (ran out of local ports) |

Share of UEs whose state in the gateway is out of date at a random moment (1000 UEs, 5 seeds):

| poll every | 1 s | 2 s | 5 s | 10 s | 30 s |
|---|---|---|---|---|---|
| out of date | 1.2% | 2.6% | 6.3% | 12.0% | 28.1% |

**E3. Bytes handed to the agent.**

| UEs | v1 full dump | summary | largest page | change set per 2 s |
|---|---|---|---|---|
| 100 | 24,634 | 358 | 7,816 | 706 |
| 1000 | 245,710 | 377 | 7,907 | 5,937 |
| 5000 | 1,232,401 | 388 | 7,938 | always over the 100-entry limit: 30 of 30 asked for resync |

At 5000 UEs the default delta limit is too small for this churn; the agent falls back to the summary.

**E4. Real identifiers seen by an agent that reads everything** (SUPI, phone number, GUTI, SM-context ref).

| UEs | identifiers | no gateway | v1 L1 | now |
|---|---|---|---|---|
| 1000 | 3778 | 2889 | 1889 | 0 |
| 5000 | 18972 | not run | not run | 0 |

v1 replaced SUPIs only. The 1889 are phone numbers from `list_subscribers` (free5GC's WebConsole returns
`gpsi`) and SM-context refs. The v1 row is v1's SUPI rule applied to the simulated tool output.

**E5. Releasing a session the agent saw earlier** (1000 tries per row).

| seen … ago | no freshness check: wrong session torn down | with it | valid releases blocked by it |
|---|---|---|---|
| 2 s | 0 | 0 | 0 of 984 |
| 10 s | 2 | 0 | 0 of 932 |
| 30 s | 13 | 0 | 0 of 789 |
| 120 s | 110 | 0 | 0 of 427 |

"Wrong session" = a new session re-established under the same id after the agent looked.

**E6. Gateway time per call** (median ms, Apple laptop): at 1000 UEs get_ue 0.07, list page 2.7, summary 0.6,
first list after a rotation 5.5, poll cycle 6.7; at 5000 UEs 0.07, 7.3, 3.0, 21.6, 34.7.

## Not shown yet

No live run of the new L1, and no real LLM. The 9-UE testbed can validate the adapter; 1000 UEs is simulation only.
