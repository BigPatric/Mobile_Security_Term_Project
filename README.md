# Privacy-Preserving, Synchronized L1 Gateway for LLM Agents on a 5G Core

**Mobile Network Security (Fall 2026), Term Project · 112550018**

An LLM agent that operates a 5G core needs a current picture of 1000+ UEs. It also reads untrusted text,
so it must be treated as hijackable, and must never hold real subscriber identities. This gateway sits
between the agent and free5GC and gives it a picture that is **current, small, and pseudonymous**.

1. **Privacy:** per-session, rotating 64-bit tokens; every other identifier is dropped or masked.
2. **Synchronization:** one bulk request per cycle at any number of UEs; a versioned store; errors never look like departures.
3. **Delivery:** summary, pages and deltas of bounded size instead of a full dump.
4. **Safe action:** a release hits the exact session the agent saw, or nothing.

Design and limits: [docs/L1_DESIGN.md](docs/L1_DESIGN.md) · Numbers: [docs/L1_RESULTS.md](docs/L1_RESULTS.md) (simulated core)

## Run

```bash
pip install -r requirements.txt
pytest tests                          # offline
python3 run_l1.py --sim 1000          # see what the agent sees
python3 run_l1.py --sim 20 --proof    # real identity vs what the agent gets, side by side
python3 experiments/l1_scale.py       # all tables, ~1 min
python3 run_l1.py                     # live free5GC (below)
```

Live testbed (Linux; free5GC v4.1.0 + UERANSIM v3.2.7, `nrfcfg oauth: false`), one terminal each,
in order — core, then gNB, then UEs (let them attach), then WebConsole, then the gateway:

```bash
cd free5gc  && sudo ./run.sh
cd UERANSIM && sudo ./build/nr-gnb -c config/free5gc-gnb.yaml
cd UERANSIM && sudo ./build/nr-ue  -c config/free5gc-ue.yaml -n 9 -t 2000
cd free5gc/webconsole && ./bin/webconsole -c ../config/webuicfg.yaml
python3 -u run_l1.py --serve          # gateway terminal: live status + [TOOL] logs (real SUPI on release)
```

`run_l1.py --proof` shows a UE's real identity next to the agent's token view; `--serve` streams the
gateway's state; `--out results/l1/live.json` records per-cycle evidence. The real SUPI appears only in
the gateway terminal's `[TOOL]` log and free5GC's own logs, never in any agent-facing result.

The WebConsole appends NF profiles on every request and slows down over time: restart it with the core.
That leak is another reason to poll in bulk.

## Layout

```
gateway/l1/      tokenizer · store · sync · views · freshness_check · identifier_check
gateway/         mcp_gateway (the boundary) · policy (check chains) · secret
agent/           ToolClient seam        free5gc_tools/  calls to the live core
sim/             simulated core         experiments/    scale study → results/l1/
tests/           offline tests          benchmark/      ENUM-01 (identifier-dump injection)
docs/            L1 design · threat model · results · final_report/REPORT.md (L1; latex/ is archived v1) · proposal
free5gc/ UERANSIM/   vendored testbed, never modified
```

The earlier three-layer version (L2 taint, L3 procedure checks, live evidence, all v1 docs) is at commit `03a6e45`.

## License

Own code: [MIT](LICENSE). [UERANSIM/](UERANSIM/LICENSE) is GPL-3.0, [free5gc/](free5gc/LICENSE) is Apache-2.0.
