# L1 gateway — directions and experiments

What is done, what we can do next, and the experiments that would back each direction.
Focus is fixed: **privacy + synchronization for 1000+ UEs** ([L1_DESIGN.md](L1_DESIGN.md)).
Threats and test mapping: [THREAT_MODEL.md](THREAT_MODEL.md).

> **2026-11-25:** D1–D5 done; live free5GC run (9-UE testbed) recorded for privacy, sync/cost and a
> real release — see "Live run — recorded" below. Remaining: L-ENUM (injection against the live core).

## Where we are

| Layer | Artifact | State |
|---|---|---|
| Property tests | [../tests/test_l1.py](../tests/test_l1.py) — 37 cases | pass (sim); **pytest not installed on this host** |
| Scale study | [../experiments/l1_scale.py](../experiments/l1_scale.py) → [../results/l1/scale.json](../results/l1/scale.json) | E1–E6 produced (sim, 9→10 000 UE) |
| Attack benchmark | [../benchmark/attacks/enumerate_subscribers.json](../benchmark/attacks/enumerate_subscribers.json) (ENUM-01) | offline evidence only |
| Live testbed | `run_l1.py` (demo) · `run_l1.py --serve` (gateway terminal) | runs; **prints only, no persisted evidence** |

**Biggest gap:** on the live core you cannot *see* identifiers being hidden, and no live run
leaves a result file. Privacy is asserted in unit tests but never shown end to end on real data.

## Directions

Ordered by how directly they close the gap above. Each is small and local to `run_l1.py` /
`experiments/` unless noted.

### D1 — Make the hiding visible (highest value)
The point of L1 is that the agent sees a pseudonym where the core has a real identity. Show both.
- `run_l1.py --proof`: for one UE, print the gateway's **internal** record (real SUPI/IMSI/UE-IP/
  SM-ref from `sync.store`) next to the **agent's** view (`gw.invoke` → token + etag, everything
  else masked). Side by side = the privacy claim, demonstrated. Works on `--sim` and live.
- `--serve` also prints a short slice of the agent view (e.g. `list_ues limit=2`) every N cycles,
  so a running gateway terminal continuously shows tokens, not just counts.

### D2 — Persist live evidence
- `run_l1.py --out results/l1/live.json`: record per cycle `version / ues / summary_bytes /
  changes / stale`, so a live run yields the same kind of numbers as the sim study, citable in the
  report. Lets us put a live column next to E1/E2/E3.

### D3 — A real release, end to end
- A small driver that triggers `trigger_pdu_session_release` on one token and captures the three
  independent proofs into `results/l1/release.json`:
  1. real SUPI appears only in the gateway `[TOOL]` log (never in the agent's result),
  2. SMF `ReleaseSMContext` → HTTP 204,
  3. the UE's data-plane tunnel ping goes from up to down.
  This is the live counterpart of experiment E5.

### D4 — Documentation
- README live testbed: add the 5th terminal (`run_l1.py --serve`).
- THREAT_MODEL verification table: name where each identifier surfaces (gateway log / free5gc log),
  and point to `--proof`, `live.json`, `release.json` as the live evidence.

### D5 — Environment / reproducibility
- `pip install pytest` on the testbed host; add it to `requirements.txt` if missing, so the 37
  property tests actually run here.

## Experiments

### Already produced (sim) — [../results/l1/scale.json](../results/l1/scale.json)
| ID | Question | Headline result (1000 UE) |
|---|---|---|
| E1 | Does the view stay correct under churn + direct-SMF release? | L1: 0 disagree / 0 wrong-UE (v1: 8.7 / 20 runs) |
| E2 | Poll cost and staleness | 1 request, 274 KB, 15 ms per cycle; 2 s poll → 2.55% stale |
| E3 | Delivery size vs full dump | summary 377 B vs dump 246 KB; 18 pages; deltas 0 resync |
| E4 | Identifier leakage | 0 leaked (no-gateway 2889, v1 1889) |
| E5 | Safe release under delay | 0 hit-other, 0 false-blocks at every delay |
| E6 | Gateway latency | poll cycle 8 ms @1000, 61 ms @5000 |

### Proposed (live core) — to add alongside the sim numbers
| ID | Builds on | What it measures | Produces |
|---|---|---|---|
| L-E0 | D1 | Privacy visible: one UE, real ID vs agent token/masked view | `--proof` stdout / snapshot |
| L-E1 | D2 | Live sync correctness: `ues` tracks the UEs actually attached over N cycles | `results/l1/live.json` |
| L-E3 | D2 | Live delivery size: summary / page / delta bytes on the real AMF payload | `results/l1/live.json` |
| L-E5 | D3 | Live safe release: SUPI only in log, SMF 204, tunnel drops | `results/l1/release.json` |
| L-ENUM | existing | ENUM-01 against the live core: injected directive → agent gets tokens, 0 SUPI exfiltrated | benchmark evidence |

### Stretch (only if time allows; may need core changes)
- Churn at scale on the live core (UERANSIM `-n` up to a few hundred) to compare live E2 cost
  against the sim curve.
- Push vs poll: confirm free5GC v4.1.0 AMF never calls `EventNotifyUri` (the reason L1 polls),
  as a documented negative result.

## Suggested order

1. **D1 `--proof`** — ✅ done (`run_l1.py --proof`, `--serve` also prints the agent view every 5 cycles).
2. **D5 pytest** — ✅ done (in `requirements.txt`; `pytest tests` → 40 passed).
3. **D2 `--out`** — ✅ done (`run_l1.py --out results/l1/live.json`, per-cycle rows + `poll_ms`, mode=sim/live).
   **D3 release driver** — ✅ done (`experiments/l1_release.py` → `results/l1/release.json`).
4. **D4 docs** — ✅ done (README 5th terminal + `--proof`/`--serve`/`--out`; THREAT_MODEL "where each
   identifier can be seen").

## Live run — recorded (9-UE testbed)

- **L-E0 privacy** ([../results/l1/proof_live.txt](../results/l1/proof_live.txt)): real `imsi-208930000000003`
  → token, real uuid SM-ref → etag, TAC absent from the view.
- **L-E1/E3 sync + cost** ([../results/l1/live.json](../results/l1/live.json)): 9 UE tracked, 0 failed,
  summary 212 B; real bulk-GET round-trip **`poll_ms` 35–90 ms** (vs sim E6 ~1–2 ms — the real network).
- **L-E5 safe release** ([../results/l1/release.json](../results/l1/release.json)): released through a
  token + etag; `verified=True`, SMF context gone False→True, SMF `HTTP 204`. Agent result carries the
  **token, not the SUPI** (`real_supi_in_agent_result=false`); the real SUPI appears only in the `[TOOL]`
  log. AMF stays stale on a direct-SMF release (by design). **Caveat:** the data-plane ping was already
  down pre-release in this testbed (UE tunnel not routable to 8.8.8.8), so it is not a usable before/after
  signal here; the SMF context-gone transition is the authoritative proof. OAuth is off (no NF cert), as
  configured.

**Remaining:** L-ENUM (run ENUM-01 against the live core) and the stretch items, if time allows.
