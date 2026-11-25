# L1 design: privacy and synchronization for 1000+ UEs

**Question.** An LLM agent operates a 5G core with 1000+ UEs that attach, move and drop all the
time. Can the agent's picture stay up to date while it never learns who the subscribers are?

Privacy wants identifiers that change and carry nothing. Synchronization wants identifiers that
stay put and a full picture. L1 resolves this by keeping **one real, versioned copy of UE state
inside the gateway** and giving each agent session a **pseudonymous, bounded view** of it.

```
 free5GC ──1 GET / cycle──► SyncEngine ──► UEStateStore (real IDs, versions)   shared, inside the gateway
                                                │
                        ┌───────────────────────┴──────────────────┐
                  L1ViewClient + tokens (scope A)       L1ViewClient + tokens (scope B)   per agent session
                        │                                          │
                     agent A                                    agent B
```

## Threat model

The agent is fully hijacked through text it reads (alert logs), and the attacker reads everything
the agent sees. The gateway, the core and their configuration are trusted. The attacker may know
the PLMN, that SIMs are numbered sequentially, and the IMSI or phone number of one victim.

## 1. Privacy ([tokenizer.py](../gateway/l1/tokenizer.py), [views.py](../gateway/l1/views.py))

| Leak | Defense |
|---|---|
| SUPI | 64-bit keyed token. It depends only on (key, session, epoch, SUPI) |
| Phone number, IMEI, GUTI, UE IP, SM-context ref | never in a view (allow-list), masked in every other result |
| Row order = IMSI order | pages are sorted by token; one version number per snapshot |
| Joining two sessions, or yesterday with today | tokens and etags differ per session and per epoch |
| Attacker writes a known SUPI into a log and watches which token comes back | identifiers in untrusted results are masked, not tokenized |
| Per-UE location | only counts per area, areas under 5 UEs merged; a pure move is not reported as a change |

## 2. Synchronization ([sync.py](../gateway/l1/sync.py), [store.py](../gateway/l1/store.py))

- **Why polling.** The vendored free5GC v4.1.0 AMF stores event-exposure subscriptions, but nothing
  in it sends to `EventNotifyUri`. Push is not available without changing the core.
- **Why it scales.** The AMF OAM endpoint without a SUPI returns all registered UEs: 1 request per
  cycle at any N.
- **AMF and SMF disagree.** After a direct SMF release the AMF still lists the session. The gateway
  remembers contexts it saw die and checks `audit_per_cycle` contexts per cycle at the SMF, so an
  unseen release is found within sessions / audit_per_cycle cycles (1000 sessions, 10 per 2 s: 200 s).
- **Errors are not emptiness.** A failed or malformed read removes nothing; the view ages and is
  flagged `stale`. Losing over half the UEs in one snapshot needs a second one to confirm.
- **Several gateways** that share the key re-derive each other's tokens from the synchronized UE
  population, so no token table has to be replicated.

## 3. Handing it to the agent

`get_network_summary` (fixed size) → `list_ues` (pages of 50) → `get_changes(cursor)` (each changed
UE once, latest state). A delta over 100 entries, an old cursor, or a token rotation answers
`resync_required` instead of sending too much or silently missing something.

## 4. Acting on a copy ([freshness_check.py](../gateway/l1/freshness_check.py))

Before a release: re-read that one UE if its record is over 1 s old, ask the SMF whether the context
lives, and require the `etag` of the session the agent saw. The release tool then refuses if the
SM-context ref changed after the check. Anything undeterminable blocks.

## What L1 does not do

- **It does not decide whether a release is justified.** A hijacked agent can release sessions it
  legitimately sees. Stopping that was v1's L2/L3 (commit `03a6e45`).
- **Behavior still links.** Someone who can observe when a victim attaches can match that moment to
  a change in the view. Rotation and scopes remove joins by identifier, not by timing or by a rare
  DNN/slice combination.
- **Masked logs lose information.** The agent cannot see which UE an alert names.
- **One AMF, one SMF.** The WebConsole only queries the first of each.
