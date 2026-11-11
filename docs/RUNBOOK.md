# Testbed Runbook — free5GC + UERANSIM

The #1 cause of "UE won't register / no PDU session / duplicate SUPI / port already
in use" is **leftover processes from a previous run**. `free5gc/force_kill.sh` kills
the core NFs but **NOT** `nr-gnb` / `nr-ue`, so a stale gNB keeps squatting on the
GTP (2152) and RLS (4997) sockets. Always do a FULL reset first.

Order matters: **core → gNB → UE**. Each stays running in its own terminal.

---

## 0. One-time config sanity (already set)
- `free5gc/config/nrfcfg.yaml` → `oauth: false`  (OAuth2 off; avoids broken-cert
  token failures that make registration time out with NAS T3510).
- MongoDB must be running: `nc -z 127.0.0.1 27017 && echo mongo-up`.

---

## 1. FULL reset (kills EVERYTHING, every time)
```bash
cd ~/Desktop/Mobile_Security_Term_Project/free5gc
sudo ./force_kill.sh                       # core NFs + interface cleanup
sudo killall -9 nr-gnb nr-ue 2>/dev/null   # UERANSIM — NOT covered by force_kill
# sanity: these must print nothing
pgrep -a -f 'bin/(nrf|amf|smf|upf|udr|udm|ausf|pcf|nssf)|nr-gnb|nr-ue'
```
If `pgrep` still lists anything, kill it before continuing.

## 2. Start the core (Terminal 1 — leave running)
```bash
cd ~/Desktop/Mobile_Security_Term_Project/free5gc
sudo ./run.sh
```
Wait until the NFs are up. Verify from another terminal:
```bash
grep -i 'upf' free5gc/log/$(ls -t free5gc/log | head -1)/free5gc.log | tail -3   # UPF present
# must NOT see: "address already in use"
```

## 3. Start the gNB (Terminal 2 — leave running)
```bash
cd ~/Desktop/Mobile_Security_Term_Project/UERANSIM
sudo ./build/nr-gnb -c ./config/free5gc-gnb.yaml
```
Expect `NG Setup procedure is successful` and **no** `Address already in use`
(if you see that, a stale gNB survived — go back to step 1).

## 4. Start the UE (Terminal 3 — leave running)
```bash
cd ~/Desktop/Mobile_Security_Term_Project/UERANSIM
sudo ./build/nr-ue -c ./config/free5gc-ue.yaml
```
Success looks like:
```
[nas] Registration accept received
[nas] UE switches to state [MM-REGISTERED/NORMAL-SERVICE]
[nas] PDU Session establishment is successful PSI[1]
[app] Connection setup for PDU session[1] is successful, TUN interface[uesimtun0, 10.60.0.x]
```

## 5. Verify the session is REAL
```bash
cd ~/Desktop/Mobile_Security_Term_Project
ip addr show uesimtun0                                              # 10.60.0.x IP
./UERANSIM/build/nr-cli imsi-208930000000001 --exec 'ps-list'      # state: PS-ACTIVE
ping -I uesimtun0 -c3 8.8.8.8                                       # data plane up
python3 run_attack_demo.py --scenario IPI-01                       # -> ATTACK SUCCEEDED
```

---

## Troubleshooting (symptom → cause → fix)

| Symptom | Cause | Fix |
|---|---|---|
| gNB: `RLS/GTP ... Address already in use` | Stale `nr-gnb` still running | `sudo killall -9 nr-gnb nr-ue`, redo step 1 |
| AMF: `bind SCTP 38412: address already in use`; SMF panic | A second AMF/SMF already running (NFs started twice) | Full reset (step 1); start NFs ONLY via `run.sh` |
| UE loops on `NAS timer[3510] expired`, never `Registration accept` | OAuth2 on + broken certs → AMF can't auth via AUSF/UDM | `oauth: false` in `nrfcfg.yaml` (done), full reset |
| Registration OK but PDU session fails | UPF not running / DNN or S-NSSAI mismatch | Confirm UPF in `run.sh` output; check UE `free5gc-ue.yaml` slice/DNN vs provisioned subscriber |
| "Duplicate SUPI" in contexts | Stale in-memory AMF UE contexts from relaunching `nr-ue` | Full reset clears them; DB itself has 1 subscriber |
| `trigger_pdu_session_release` returns `noop` | No live UE session (core/UE down) | Bring up steps 2–4 first |
