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
python3 tests/test_verifier.py       # L3
python3 tests/test_policy.py         # policy pipeline (config-driven check chain)
python3 tests/test_generality.py     # generality (composability / cross-procedure / attack-blind)
python3 tests/test_e2e_scenarios.py  # predicted scenario × mode matrix
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
cd UERANSIM && sudo ./build/nr-ue  -c config/free5gc-ue.yaml -n 3 -t 2000   # 3: 3 UEs
```

DOS-02 needs **at least cap+1 sessions** (3 UEs with the default `rate.max = 2`) for L3's cap to show.

## 3. Single live runs

From the project root:

```bash
python3 run_attack_demo.py --scenario ENUM-01 --gateway off          # SUPI leaks
python3 run_attack_demo.py --scenario ENUM-01 --gateway on           # leak = 0 (L1)
python3 run_attack_demo.py --scenario DOS-01  --gateway off          # real sessions released, verified
python3 run_attack_demo.py --scenario DOS-01  --gateway on           # blocked by L2
python3 run_attack_demo.py --scenario DOS-02  --gateway on           # L2 fooled, L3 caps bulk
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
sudo ./tools/run_live_matrix.sh --fresh             # each cell restarts to a full N-session core
sudo N_UES=3 REPEATS=3 ./tools/run_live_matrix.sh   # repeats for tighter latency stats
python3 tools/aggregate.py --csv results/results attack_evidence.jsonl  # → RESULTS.md tables + results/*.csv
```

Per-cell core / gNB / UE logs go to `live_logs/`. If root's `python3` lacks the
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
sudo killall -9 nr-gnb nr-ue 2>/dev/null
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
