# Threat model and testing — L1 gateway

Scope: the L1 gateway between an LLM agent and free5GC (privacy + synchronization for 1000+ UEs).
This file states who the attacker is, what they can and cannot do, which properties the gateway
must hold, and how each property is tested. Design and limits: [L1_DESIGN.md](L1_DESIGN.md).

## 1. Assets

- **Subscriber identities** — SUPI/IMSI, phone number, IMEI, GUTI, UE IP, SM-context ref. The
  agent must never learn any real identifier, nor anything that re-links to one.
- **Linkability** — the fact that two observations (two sessions, two days, two tools) concern the
  same UE. Keeping views unlinkable is itself an asset.
- **An accurate, current picture** — the agent's view must track the live core without a full dump.
- **Session integrity** — a release must hit the exact session the agent saw, or nothing.

## 2. Adversary

The **agent is fully hijacked** through untrusted text it reads (alert logs / OAM messages:
indirect prompt injection). The attacker therefore issues any tool call the agent can issue and
**reads everything the agent sees** — every view, page, delta, error and etag.

Attacker's prior knowledge: the PLMN; that SIMs are numbered sequentially; and the IMSI or phone
number of **one** victim. The attacker may also plant known identifiers into the logs the agent
reads.

**Trusted** (out of scope): the gateway itself, the free5GC core, and their configuration and
secrets. We do not defend against a compromised core, a leaked master key, or the host OS.

**Explicit non-goals** (see L1_DESIGN.md "What L1 does not do"):
- L1 does **not** judge whether a release is *justified* — a hijacked agent can release sessions it
  legitimately sees. That was v1's L2/L3 (commit `03a6e45`).
- Timing / rare-attribute correlation (a victim attaching at a known moment, a unique DNN+slice) is
  not removed by rotation or scopes.
- Masked logs lose the UE an alert names.
- One AMF, one SMF (WebConsole queries the first of each).

## 3. Threats → defenses → tests

Each row: the attacker's move, the gateway's defense, and the test(s) that assert it.
Unit tests are in [../tests/test_l1.py](../tests/test_l1.py); measured results are produced by
[../experiments/l1_scale.py](../experiments/l1_scale.py) → [../results/l1/scale.json](../results/l1/scale.json).

### 3.1 Privacy — identifiers never reach the agent

| Threat | Defense | Test |
|---|---|---|
| Read a SUPI directly from a view | SUPI replaced by a 64-bit keyed token over (key, session, epoch, SUPI) | `test_no_real_identifier_reaches_the_agent_in_any_view` · exp **E4** (0 leaks vs 1889 at 1000 UE) |
| Read phone/IMEI/GUTI/UE-IP/SM-ref | not in any view (allow-list); masked in every other result | `test_v1_tools_do_not_leak_other_identifiers_any_more` |
| Raw identifier smuggled in nested tool arguments | arguments checked and blocked before the call | `test_raw_identifiers_in_nested_arguments_are_blocked` |
| Token collision / order-dependence over many UEs | tokens are a pure function, no collisions, order-independent | `test_tokens_do_not_depend_on_order_and_do_not_collide` (10 000 UE) |

### 3.2 Linkability — observations must not re-link

| Threat | Defense | Test |
|---|---|---|
| Join two agent sessions by token or etag | tokens and etags differ per session scope | `test_scopes_are_unlinkable_by_token_and_etag` |
| Join yesterday with today | tokens rotate per epoch (hourly); rotation forces resync | `test_rotation_and_grace`, `test_rotation_forces_resync_of_cursors_and_pages`, `test_etag_accepted_in_grace`, `test_grace_longer_than_epoch_is_rejected` |
| Oracle: plant a known SUPI in a log, watch which token returns | identifiers in **untrusted** results are **masked, not tokenized** (no oracle) | `test_planted_supi_in_a_log_is_not_an_oracle` · benchmark **ENUM-01** |
| Infer IMSI rank from row order | pages sorted by token, not by identifier | `test_order_does_not_reveal_imsi_rank` |
| Track a victim's location | only per-area counts; areas < 5 UE merged; a pure move is not a change | `test_moving_ue_does_not_show_up_as_a_change`, `test_small_areas_are_merged` |
| A peer gateway must resolve a token it never minted | tokens re-derived from the shared key + synced population | `test_peer_gateway_resolves_token_it_never_minted` |

### 3.3 Synchronization — current picture, bounded size

| Threat / failure | Defense | Test |
|---|---|---|
| Full dump to stay current (cost / exfil surface) | 1 bulk GET per cycle; summary + pages of 50 + deltas | exp **E1/E2/E3** (1 request at any N; 377 B summary vs 246 KB dump at 1000 UE) |
| Delta too large or cursor too old → silent miss | answers `resync_required` instead of truncating | `test_payloads_are_bounded_at_5000_ues`, `test_delta_stream_converges_to_the_full_view`, `test_too_old_or_too_big_delta_asks_for_resync` |
| Paging races as UEs attach/drop | stable pagination across churn | `test_paging_is_stable_while_ues_come_and_go` |
| A read error looks like UEs leaving | failed/malformed read removes nothing; view ages → `stale` | `test_failed_read_keeps_state_and_turns_stale`, `test_unclear_answers_are_errors_not_empty` |
| A bad snapshot wipes the population | shrink > 50% needs a confirming second snapshot; `null` ≠ empty | `test_implausible_shrink_needs_confirmation_and_null_means_empty`, `test_old_snapshot_does_not_overwrite_newer_refresh` |
| AMF still lists a session released directly at the SMF | gateway audits `audit_per_cycle` contexts/cycle at the SMF | `test_audit_finds_out_of_band_release_within_its_bound` · exp **E1** (now_wrong_ue = 0) |
| Concurrent agents + sync diverge | consistency under concurrency | `test_concurrent_agents_and_sync_stay_consistent` (1000 UE) |
| Malformed arguments crash the gateway | tolerated, returned as errors | `test_bad_arguments_do_not_crash` |

### 3.4 Safe action — release hits the right session or nothing

| Threat | Defense | Test |
|---|---|---|
| Release a stale session that now belongs to another UE | re-read if > 1 s old, confirm at SMF, require the seen etag; block if SM-ref changed | `test_release_is_written_through_although_amf_stays_stale`, `test_release_of_vanished_session_is_blocked`, `test_session_released_at_smf_is_blocked_even_if_amf_lists_it` · exp **E5** (0 hit_other, 0 false_blocks) |

## 4. What testing we are taking

Three complementary layers. (1) and (2) run with no live core; (3) needs the testbed.

1. **Unit / property tests** — [../tests/test_l1.py](../tests/test_l1.py), 37 `pytest` cases over a
   simulated core (`sim/`), including one over a **real HTTP** adapter (`test_adapter_over_real_http`).
   Deterministic; this is where every claimed security property above is asserted.
   Run: `pytest tests`.

2. **Scale study** — [../experiments/l1_scale.py](../experiments/l1_scale.py) over the simulated
   core, 9 → 10 000 UE. Produces the quantitative evidence (E1 sync correctness, E2 cost/staleness,
   E3 delivery size, E4 identifier leakage, E5 safe release, E6 gateway latency) to
   [../results/l1/scale.json](../results/l1/scale.json). Run: `python3 experiments/l1_scale.py` (~1 min).

3. **Attack benchmark** — [../benchmark/attacks/enumerate_subscribers.json](../benchmark/attacks/enumerate_subscribers.json)
   (ENUM-01: subscriber enumeration via injected OAM directive) with evidence in
   [../benchmark/offline_evidence.jsonl](../benchmark/offline_evidence.jsonl). Exercises the
   indirect-prompt-injection path end to end: a hijacked agent follows the directive, and the
   gateway returns tokens/masked fields, so no SUPI is exfiltrated.

4. **Live testbed** — against free5GC v4.1.0 + UERANSIM v3.2.7 (setup: README). The adapter reads
   the real AMF `registered-ue-context`; identifiers surface **only** inside the gateway, never in
   an agent-facing result:
   - `run_l1.py --proof` — one UE's real identity (SUPI, SM-context ref, TAC from `sync.store`)
     shown next to the agent's view (token, etag, location absent). The visible form of §3.1.
   - `run_l1.py --serve` — the gateway terminal: per-cycle status and the `[TOOL]` log where the
     **real SUPI appears on a release** (also in `free5gc/log/`); the agent's result never carries it.
   - `run_l1.py --out results/l1/live.json` — per-cycle evidence (version/ues/bytes/changes/stale),
     the live counterpart to E1/E2/E3.

   - `experiments/l1_release.py` — a real release through the gateway (token + etag), recording the
     three proofs to `results/l1/release.json`. Live result: `verified=True`, SMF context gone
     False→True, SMF `HTTP 204`; the agent's result carries the token, not the SUPI; the real SUPI
     appears only in the `[TOOL]` log. The live form of E5.

   **Where each identifier can be seen:** SUPI/IMSI → gateway `[TOOL]` log + free5GC logs only;
   SM-context ref → gateway-internal (agent sees an `etag`); location/TAC → never in a view.
