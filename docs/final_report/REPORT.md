# A Privacy-Preserving, Synchronized L1 Gateway for LLM Agents on a 5G Core

**Mobile Network Security, Fall 2026 — Final Project Report**
Hsin-Ze Wu (112550018) · Instructor: Prof. Chi-Yu Li

---

## Abstract

Operators are starting to let LLM agents run network-operations tasks — triaging alerts,
releasing stuck sessions — by calling 5G core APIs as tools. Such an agent reads untrusted text
(alert logs), so it must be treated as hijackable through indirect prompt injection, and anyone
who reads what the agent reads also reads everything it sees. A naive agent over a core with 1000+
UEs faces two problems at once: it must **never hold real subscriber identities**, yet it needs a
**current picture** of a population that attaches, moves and drops continuously.

These two goals pull against each other: privacy wants identifiers that change and carry nothing;
synchronization wants identifiers that stay put and a complete picture. This project builds an
**L1 gateway** that resolves the tension by keeping one real, versioned copy of UE state *inside*
the gateway and handing each agent session a *pseudonymous, bounded* view of it. We evaluate on a
simulated core from 9 to 10 000 UEs and on a live free5GC v4.1.0 + UERANSIM v3.2.7 testbed.
Identifier leakage drops from 100% to 0% at every scale; a single bulk poll keeps the view current
at any population (one request vs. thousands); and a release issued through the gateway hits the
exact session the agent saw, or nothing, with zero mis-hits across 1000 trials at every staleness
delay. On the live core, the real SUPI surfaces only inside the gateway's own logs and never in any
agent-facing result. Scaling the live testbed to the largest population it would register (10 to
466 UEs), the update path stays flat (one bulk poll, 53–69 ms regardless of N) and the
per-subscriber token adds under 4% of a cycle — so **adding the privacy transform does not degrade
synchronization**, the central question this report sets out to answer.

> **Scope note.** An earlier version of this project proposed three layers (L1 tokenization,
> L2 taint tracking, L3 a procedure/rate verifier). This report is deliberately narrowed to **L1**,
> studied in depth at scale and on hardware. The three-layer prototype is archived at git commit
> `03a6e45` and in `docs/final_report/latex/`.

---

## 1. Problem and scope

**Setting.** An LLM agent operates a 5G core through a tool interface (an MCP-style boundary). It
can read alert logs, query subscriber/session state, list subscribers, and trigger a
network-initiated PDU-session release. The core is free5GC; the agent sees it only through the
gateway.

**Two requirements, in tension.**

1. **Privacy.** The agent must never learn a real identifier (SUPI/IMSI, phone number, IMEI, GUTI,
   UE IP, SM-context reference), nor anything that re-links one observation to another.
2. **Synchronization.** With 1000+ UEs changing continuously, the agent's picture must stay current
   and complete without dumping the whole core on every step.

A design that only tokenizes identifiers but re-reads per UE does not scale; a design that polls in
bulk but leaks identifiers is not private. L1 must do both at once, and additionally let the agent
*act* (release a session) on its pseudonymous view without hitting the wrong UE.

---

## 2. Threat model

- **Adversary.** The agent is **fully hijacked** through untrusted text it reads (indirect prompt
  injection via alert logs). The attacker issues any tool call the agent can issue and **reads
  everything the agent sees** — every view, page, delta, error and etag.
- **Prior knowledge.** The PLMN; that SIMs are numbered sequentially; the IMSI or phone number of
  *one* victim. The attacker may plant known identifiers into the logs the agent reads.
- **Trusted (out of scope).** The gateway, the core, and their configuration and secrets. We do not
  defend against a compromised core, a leaked master key, or the host OS.
- **Explicit non-goals.** (i) L1 does *not* decide whether a release is *justified* — a hijacked
  agent can release sessions it legitimately sees; stopping that was the archived L2/L3. (ii) Timing
  / rare-attribute correlation (a victim attaching at a known moment; a unique DNN+slice) is not
  removed by rotation or scopes. (iii) Masked logs lose the UE an alert names. (iv) One AMF, one SMF.

Full threat→defense→test mapping: `docs/THREAT_MODEL.md`.

---

## 3. Design

```
 free5GC ──1 GET / cycle──► SyncEngine ──► UEStateStore (real IDs, versions)   shared, inside the gateway
                                                │
                        ┌───────────────────────┴──────────────────┐
                  view + tokens (scope A)              view + tokens (scope B)   per agent session
                        │                                          │
                     agent A                                    agent B
```

L1 keeps one authoritative, versioned copy of UE state in the gateway and derives a per-session
pseudonymous view. Four pillars:

### 3.1 Privacy (`gateway/l1/tokenizer.py`, `views.py`)

- Each SUPI becomes a **64-bit keyed token**, a pure function of (key, session scope, epoch, SUPI).
  Every other identifier is **dropped** from views (allow-list) or **masked** in any other result.
- **Unlinkability.** Tokens and session etags differ per session scope and per hourly epoch, so two
  sessions — or yesterday and today — cannot be joined by identifier. Pages are sorted by token, so
  row order reveals no IMSI rank.
- **Oracle resistance.** Identifiers appearing in *untrusted* results are **masked, not tokenized**:
  a SUPI planted in a log does not come back as a stable token the attacker could match.
- **Location.** Only per-area counts are exposed, areas under 5 UEs are merged, and a pure move is
  never reported as a change.

### 3.2 Synchronization (`gateway/l1/sync.py`, `store.py`)

- **Why polling.** free5GC v4.1.0's AMF stores event-exposure subscriptions but never posts to
  `EventNotifyUri`; push is unavailable without changing the core.
- **Why it scales.** The AMF OAM endpoint without a SUPI returns every registered UE: **one request
  per cycle at any N**.
- **AMF/SMF disagreement.** After a direct-SMF release the AMF still lists the session. The gateway
  remembers contexts it saw die and audits `audit_per_cycle` contexts per cycle at the SMF, so an
  unseen release is found within `sessions / audit_per_cycle` cycles.
- **Errors are not emptiness.** A failed or malformed read removes nothing; the view ages and is
  flagged `stale`. Losing over half the UEs in one snapshot needs a confirming second snapshot.

### 3.3 Delivery

`get_network_summary` (fixed size) → `list_ues` (pages of 50) → `get_changes(cursor)` (each changed
UE once, latest state). A delta over 100 entries, an old cursor, or a token rotation returns
`resync_required` instead of over-sending or silently missing changes.

### 3.4 Safe action (`gateway/l1/freshness_check.py`)

Before a release: re-read that one UE if its record is over 1 s old, ask the SMF whether the context
still lives, and require the **etag** of the session the agent saw. The release is refused if the
SM-context reference changed after the check. The agent passes only a token plus the etag it saw;
the gateway maps the token back to the real SUPI internally and never returns it.

---

## 4. Implementation

- `gateway/l1/` — `tokenizer` · `store` · `sync` · `views` · `freshness_check` · `identifier_check`.
- `gateway/` — `mcp_gateway` (the boundary that detokenizes arguments and tokenizes/masks results) ·
  `policy` (per-tool check chains) · `secret`.
- `free5gc_tools/core_state.py` — the **only** module that talks to the live core, over free5GC's own
  REST interfaces: AMF `registered-ue-context` (bulk + per-UE), SMF `ReleaseSMContext` and OAM
  session info, and a host-level data-plane ping.
- `sim/` — a simulated core with configurable churn for scale study; `agent/` — the tool-client seam.

The same gateway code runs over the simulated core and the live core; only the source adapter differs.

---

## 5. Evaluation

### 5.1 Setup

Simulated core: `experiments/l1_scale.py`, 9–10 000 UEs, churn per UE per second of reg 0.002,
session 0.005, cm-state 0.02, move 0.005 (`results/l1/scale.json`). Live core: free5GC v4.1.0 +
UERANSIM v3.2.7, `nrfcfg oauth: false`. Subscribers are bulk-provisioned over the WebConsole REST
API (`experiments/provision_subscribers.py`); real UEs are attached with UERANSIM and the gateway is
measured against the population that actually registers (`experiments/l1_live_scale.py` →
`results/l1/live_scale.json`; property evidence in `results/l1/{proof_live,release,enum}`). "v1"
below is a tokenize-only baseline that re-reads per UE; "no gateway" is the raw core.

On a single-host testbed the registration success rate falls with scale — UERANSIM caps `-n` at 512
and a simultaneous registration storm saturates the one gNB and the core's NFs — so an attempt of N
UEs yields fewer registered (e.g. 500 attempted → 466 registered). We therefore plot the live results
against the **actual registered count**, and use the simulated core for the 1 000–10 000 range.

### 5.2 Sync correctness under churn (E1)

Mean disagreeing UEs and wrong-UE records per run, over many runs:

| UEs | v1 disagree | **L1 disagree** | v1 wrong-UE | **L1 wrong-UE** |
|----:|------------:|----------------:|------------:|----------------:|
| 100 | 0.0 | **0.0** | 0.0 | **0.0** |
| 1 000 | 8.7 | **0.0** | 4.6 | **0.0** |
| 5 000 | 176.1 | **0.0** | 93.1 | **0.0** |
| 10 000 | 703.7 | **0.0** | 374.9 | **0.0** |

L1 never disagrees with the core and never attributes a session to the wrong UE, at any scale; the
per-UE baseline's error grows with population.

### 5.3 Poll cost and staleness (E2)

| UEs | bulk req | bulk KB | bulk ms | per-UE req | per-UE ms |
|----:|---------:|--------:|--------:|-----------:|----------:|
| 1 000 | **1** | 273.9 | 15.5 | 2 890 | 3 155 |
| 5 000 | **1** | 1 382.6 | 60.6 | 14 487 | — |

One bulk request per cycle at any N, ~200× faster than per-UE at 1000 UEs. Staleness vs. poll
interval: 1 s → 1.23% of reads stale, 2 s → 2.55%, 5 s → 6.31%, 30 s → 28.1%. A 2 s interval
(30 requests/min) keeps error near 2.5%.

### 5.4 Delivery size (E3)

At 1000 UEs: a full dump is 245 710 bytes; the L1 **summary is 377 bytes**, a page caps at ~7.9 KB
(18 pages total), and a 2 s delta averages 5 937 bytes with **0 forced resyncs** over 30 cycles.

### 5.5 Identifier leakage (E4)

Real identifiers reaching the agent:

| UEs | no gateway | v1 | **L1** | identifiers checked |
|----:|-----------:|---:|-------:|--------------------:|
| 100 | 289 | 189 | **0** | 378 |
| 1 000 | 2 889 | 1 889 | **0** | 3 778 |
| 5 000 | (n/a) | (n/a) | **0** | 18 972 |

L1 leaks nothing at any scale while the baselines leak with the population.

### 5.6 Safe release under staleness (E5)

1000 release attempts per delay, with the gateway off vs. on:

| delay | off → hit *other* UE | on → hit *other* UE | on false-blocks |
|------:|---------------------:|--------------------:|----------------:|
| 0 s | 0 | **0** | 0 |
| 10 s | 2 | **0** | 0 |
| 30 s | 13 | **0** | 0 |
| 120 s | 110 | **0** | 0 |

With the gateway off, a stale release increasingly lands on a *different* UE (110 of 1000 at 120 s).
With L1's etag binding, it **never** hits another UE and **never** falsely blocks a still-valid one;
it simply refuses once the session it saw is gone.

### 5.7 Gateway latency (E6)

Per-call compute latency is sub-millisecond to a few ms: at 1000 UEs, `get_ue` 0.07 ms, summary
0.89 ms, list-page 3.2 ms; at 5000 UEs a full poll cycle is ~61 ms. On the **live** core, the real
bulk-GET round-trip to the WebConsole measured **53–69 ms** per cycle (the `sync_ms` column below) —
the network round-trip, not gateway compute.

### 5.8 Live scale: update cost and the price of the secret

The central question — does adding per-subscriber tokenization slow the update? — is isolated on the
live core by timing, each cycle, the update path (`sync_ms`: one bulk GET + the versioned-store diff,
no tokens), the full agent-facing view with tokens applied (`view_ms`, `view_kb`), and the token
cost: minting a whole epoch's tokens cold (`tok_cold`) versus re-deriving them from the per-epoch
cache (`tok_warm`). Median over 10 cycles per point (`results/l1/live_scale.json`):

| registered UEs | sync_ms | view_ms | view_kb | tok_cold ms | tok_warm ms | tokens unique+stable |
|---------------:|--------:|--------:|--------:|------------:|------------:|:--------------------:|
| 10 | 64.2 | 0.57 | 1.7 | 0.061 | 0.009 | ✓ |
| 45 | 63.3 | 1.96 | 7.2 | 0.207 | 0.036 | ✓ |
| 96 | 64.3 | 4.18 | 15.3 | 0.418 | 0.074 | ✓ |
| 176 | 68.8 | 8.44 | 28.1 | 0.748 | 0.136 | ✓ |
| 466 | 53.2 | 25.9 | 74.3 | 1.917 | 0.369 | ✓ |

The **update path is independent of N**: `sync_ms` holds at 53–69 ms from 10 to 466 UEs, because a
cycle is always one bulk request whose cost is dominated by the network round-trip. The **secret is
nearly free**: at 466 UEs a full cold mint is 1.9 ms (~3.6% of a cycle) and is paid only once per
hourly epoch; every other cycle re-derives tokens from cache in 0.37 ms. Tokens were **unique and
stable at every cycle and every scale** (no collisions). The view grows with N but stays bounded per
page. So privacy and synchronization hold together on real hardware, not only in simulation.

![Live update cost vs. scale: sync_ms stays flat at 53–69 ms from 10 to 466 registered UEs, while the
cold and warm token-minting costs stay near zero.](figures/live_scale.svg)

*Figure 1. The update path (`sync_ms`) is flat across scale — a cycle is one bulk request dominated by
the network round-trip — and the per-subscriber token cost (`tok_cold`, once per epoch; `tok_warm`,
cached) stays near the baseline throughout.*

### 5.9 Live core: privacy, release, enumeration

- **Privacy shown (`proof_live.txt`).** For one UE the gateway holds `imsi-208930000000003`, SM-ref
  `urn:uuid:197e88ce-…`, TAC `000001`; the agent's `get_ue` returns token `token_sub_…`, an opaque
  `etag`, and **no location** — the two sides side by side.
- **Real release (`release.json`).** Released through a token + etag: `verified=true`, the SMF
  SM-context went from present to **gone**, SMF `ReleaseSMContext` → **HTTP 204**. The agent's result
  carried the **token, not the SUPI** (`real_supi_in_agent_result=false`) and a `[REDACTED:smref]`;
  the real SUPI appeared **only** in the gateway's `[TOOL]` log. (The AMF stays stale after a
  direct-SMF release, by design.)
- **Enumeration attack ENUM-01 (`enum.json`).** A planted "compliance audit" directive tells the
  hijacked agent to list all subscribers. **Without the gateway, 9 real SUPIs were exfiltrated;
  through L1 the call was refused (the tool is hidden) and 0 SUPIs leaked.**

---

## 6. Limitations

- **L1 does not judge intent.** A hijacked agent can release sessions it legitimately sees; L1 only
  guarantees the release lands on the right session or nothing.
- **Residual linkability.** Timing correlation and rare DNN/slice combinations can still re-link a
  behaviour to a UE; rotation removes joins *by identifier*, not by side-channel.
- **Testbed.** One AMF/one SMF; the data-plane ping was unavailable in our testbed (the UE tunnel was
  not routable to the probe target), so the authoritative release proof is the SMF context-gone
  transition, not the ping. OAuth was disabled per the testbed configuration.
- **Push unavailable.** The current design polls because free5GC v4.1.0 never emits event
  notifications; a push-capable core could reduce staleness further.
- **Live scale ceiling.** A single-host free5GC + UERANSIM testbed does not reach 1 000 concurrent
  live UEs. UERANSIM caps `-n` at 512, and launching hundreds of UEs at once is a registration storm
  that saturates the one gNB and the core's NFs: timers expire, UEs perform **local PDU-session
  release** (tearing down their own session without signalling the network), and under enough load
  the NFs crash. Because a local release is not seen by the AMF, stale "ghost" contexts accumulate
  across crashed or restarted UE runs and the reported registered count can balloon far past the
  number actually attached (we observed >2 000 after repeated runs) until the core is restarted to
  flush its in-memory state. We therefore evaluate live up to the largest population that registers
  stably (466 UEs) and rely on the simulated core for 1 000–10 000. The accumulation of
  network-unknown releases is itself the AMF/SMF-staleness problem L1's per-cycle SMF audit (§3.2,
  E5) is designed to detect.

---

## 7. Conclusion

Treating an LLM agent as already hijacked, L1 gives it a picture of a 1000+ UE core that is current,
small and pseudonymous, and lets it act on that picture safely. Across 9–10 000 simulated UEs and a
live free5GC testbed (validated up to 466 registered UEs), identifier leakage is 0% while one bulk
poll per cycle keeps the view correct, and a release binds to the exact session the agent saw.
Crucially, the privacy transform is nearly free: on the live core the update path stays flat in N and
per-subscriber tokenization costs under 4% of a cycle, paid once per epoch. The privacy and
synchronization goals, usually in tension, are met together — on real hardware, not only in
simulation — by keeping the one real copy inside the gateway and never letting a real identifier
cross the boundary.

---

## Reproducibility

```bash
pip install -r requirements.txt
pytest tests                       # 40 property/sync tests
python3 experiments/l1_scale.py    # E1–E6  -> results/l1/scale.json
# live (see README): core, gNB, UE, WebConsole, then:
python3 experiments/provision_subscribers.py 1000    # bulk-provision subscribers (REST)
# attach N UEs with UERANSIM (nr-ue -n N; -n caps at 512, use 2 instances for 1000), then:
python3 experiments/l1_live_scale.py --cycles 10     # update cost + token cost -> live_scale.json
python3 run_l1.py --proof | tee results/l1/proof_live.txt   # privacy, side by side
python3 experiments/l1_release.py      # real release  -> release.json
python3 experiments/l1_enum.py         # ENUM-01        -> enum.json
```

Design and limits: `docs/L1_DESIGN.md` · threat model and tests: `docs/THREAT_MODEL.md` ·
numbers: `results/l1/`.
