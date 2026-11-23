# Running — Tests, Live Demo, Full Experiment

Back to the [README](../../README.md). The internals of each step are in
[END_TO_END_FLOW.md](../architecture/END_TO_END_FLOW.md).

**Testbed:** free5GC v4.1.0 + UERANSIM v3.2.7 (both vendored in this repo).
Core config needs `nrfcfg oauth: false`, so that the SMF release is a plain REST call.

```bash
pip install -r requirements.txt
```

---

## 1. Offline (no core needed)

All gateway logic has deterministic tests:

```bash
python3 tests/test_tokenizer.py      # L1
python3 tests/test_taint.py          # L2
python3 tests/test_capability.py     # L2 signed capabilities
python3 tests/test_verifier.py       # L3
python3 tests/test_policy.py         # policy pipeline (config-driven check chain)
python3 tests/test_generality.py     # generality (composability / cross-procedure / attack-blind)
python3 tests/test_e2e_scenarios.py  # predicted scenario × mode matrix
python3 tests/test_hardening.py      # detokenize scope, shared core state, fail-closed probes
python3 tests/test_adversarial.py    # adaptive attackers (fake clock)
python3 tests/test_generator.py      # synthetic-trace generator self-checks
```

The full quantified matrix can also be produced offline, against a fake core, with
the same pipeline as the live run:

```bash
python3 tools/sweep.py                                    # → benchmark/offline_evidence.jsonl
python3 tools/aggregate.py benchmark/offline_evidence.jsonl
```

## 2. Bring up the live testbed

Use three terminals and keep each one running:

```bash
cd free5gc  && sudo ./run.sh                                          # 1: core
cd UERANSIM && sudo ./build/nr-gnb -c config/free5gc-gnb.yaml         # 2: gNB
cd UERANSIM && sudo ./build/nr-ue  -c config/free5gc-ue.yaml -n 9 -t 2000   # 3: 9 UEs, 2 s apart
cd free5gc/webconsole && ./bin/webconsole -c ../config/webuicfg.yaml  # 4: WebConsole (REST API the tools use)
```

`run.sh` does not start or stop the WebConsole. Restart it together with the core: free5GC's WebConsole
appends the NRF's AMF/SMF profiles to an in-memory list on every request and never clears it, so a
long-lived instance gets slower with every request (L3's core precheck drifted from ~20 ms to ~200 ms this
way). `run_live_matrix.sh` kills and restarts it, and clears the NRF's stale `urilist`, on every bring-up.
If `bin/webconsole` is missing: `cd free5gc/webconsole && go build -o bin/webconsole ./server.go`.

DOS-02 needs **at least cap+1 sessions** for L3's cap to show (the report uses 9 UEs with `rate.max = 3`).

## 3. Single live runs

From the project root:

```bash
python3 run_attack_demo.py --scenario ENUM-01 --gateway off          # SUPI leaks
python3 run_attack_demo.py --scenario ENUM-01 --gateway on           # leak = 0 (L1)
python3 run_attack_demo.py --scenario DOS-01  --gateway off          # real sessions released, verified
python3 run_attack_demo.py --scenario DOS-01  --gateway on           # blocked by L2
python3 run_attack_demo.py --scenario DOS-02  --gateway on           # forged ticket rejected by signed L2
python3 run_attack_demo.py --scenario DOS-02  --gateway on --l2-claim-only  # legacy L2 fooled, L3 caps at 3
python3 run_attack_demo.py --scenario DOS-02  --gateway rbac         # RBAC baseline (does not stop it)
python3 run_attack_demo.py --scenario DOS-02  --gateway on --layers L1,L2   # ablation
```

- `--gateway` overrides `gateway.enabled` in [config.yaml](../../config.yaml).
  `--layers` overrides `gateway.layers`.
- **ENUM-01** only reads the subscriber DB (WebConsole), so it runs even if other NFs are flaky.
- **DOS-01 / DOS-02** need the SMF SBI live and a real active session. The demo
  **aborts in preflight** (exit 2) if the core is down. It never fakes a release.
- Each run appends one structured record to `attack_evidence.jsonl`: scenario,
  core health, active layers, verdict flags, and per-call trace.

## 4. Full live experiment matrix

```bash
# the report's setup: 140 runs (signed L2 everywhere, plus DOS-02 under claim-only L2),
# then a double-release check on a fresh core
sudo N_UES=9 REPEATS=5 PRESET=final ./tools/run_live_matrix.sh --fresh
# BENIGN-05 (authorized bulk drain, rate-cap FP), 10 runs
sudo N_UES=9 REPEATS=5 EVIDENCE=results/evidence/attack_evidence_final_benign05.jsonl \
  CELLS="BENIGN-05|--gateway on;BENIGN-05|--gateway rbac" ./tools/run_live_matrix.sh
# precheck latency: the 6 cells whose releases pass L3's core precheck, 30 runs
sudo N_UES=9 REPEATS=5 PRESET=latency ./tools/run_live_matrix.sh --fresh
# → RESULTS.md tables + results/tables/*.csv
python3 tools/aggregate.py --csv results/tables/main \
  results/evidence/attack_evidence_final.jsonl results/evidence/attack_evidence_final_benign05.jsonl
python3 tools/aggregate.py --csv results/tables/latency_rerun results/evidence/attack_evidence_latency.jsonl
```

The runner first kills any running core, gNB, UEs and WebConsole, then for every run that changed core
state brings all of them up fresh (see §2 on why the WebConsole must restart too).

- `PRESET=final` orders cells so that runs which leave the core untouched share one bring-up.
- `--l2-claim-only` (on `run_attack_demo.py`) runs L2 as the legacy claim-only check for that run,
  without editing `config.yaml`; aggregate.py reports such runs as `L1+L2(claim)` etc.
- Release calls record `release_http_status` (the SMF) and `post_probe` (every probe's HTTP status).
- `tools/double_release.py` releases the same session twice without the gateway; it needs a running core.
- Superseded evidence from earlier code versions is in `results/archive/`.

Per-cell core / gNB / UE / WebConsole logs go to `live_logs/`. If root's `python3` lacks the
dependencies, set `PYTHON=/path/to/venv/bin/python3`.

## 5. Optional: data-plane evidence

The DoS proof comes from the control plane (the SMF SM context disappears). To also
show the data plane (ping works before the attack and fails after it), run
`sudo ./tools/dataplane_nat.sh up` after the UPF starts. See [END_TO_END_FLOW.md §8.2](../architecture/END_TO_END_FLOW.md).

---

## Lab notes / troubleshooting

**Reset the testbed** (stale sessions or a half-dead core):

```bash
cd free5gc && sudo ./force_kill.sh
sudo killall -9 nr-gnb nr-ue webconsole 2>/dev/null
mongo --quiet free5gc --eval 'db.urilist.deleteMany({})'   # stale NRF registrations (core must be down)
```

**Reset MongoDB** (subscriber DB corrupted). This wipes all subscribers, so you must
re-provision them in the WebConsole afterwards:

```bash
sudo systemctl stop mongodb
sudo rm -rf /var/lib/mongodb/*
sudo chown -R mongodb:mongodb /var/lib/mongodb
sudo systemctl start mongodb
```

**Clean Python caches:** `python3 cleanup.py`
