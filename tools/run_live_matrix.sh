#!/usr/bin/env bash
# =============================================================================
# tools/run_live_matrix.sh — fresh-core live experiment runner
# =============================================================================
# For EVERY cell in the scenario x gateway-mode matrix, this script:
#     1. tears down any running free5GC + UERANSIM            (clean slate)
#     2. brings up a FRESH core + gNB + N UEs
#     3. waits until N UEs really have an ACTIVE PDU session
#     4. runs ONE run_attack_demo.py invocation (appends to attack_evidence.jsonl)
# So every attack starts from an identical, full N-session state — a release in
# one run can never bleed into the next.
#
# Core reuse (REUSE_CORE=1, default): if a run sent NO state-changing call to the
# core (every release was blocked, or it only read; tools/_core_untouched.py
# decides from that run's evidence record), the next cell runs on the same core
# once all N sessions are confirmed still up. The gateway and agent are a new
# process every run, so their state is always fresh. Any doubt -> fresh core.
# Evidence records carry "core_reused": true/false.  REUSE_CORE=0 = always fresh.
#
# MUST run as root (free5GC run.sh and UERANSIM nr-ue need it):
#     sudo ./tools/run_live_matrix.sh
#     sudo ./tools/run_live_matrix.sh --fresh          # back up old evidence first
#     sudo N_UES=9 REPEATS=5 ./tools/run_live_matrix.sh # the report's setup
#
#   Subset of the matrix into its own evidence file (space-separated lists):
#     sudo REPEATS=5 ATTACKS="ENUM-01 DOS-02" BENIGN="BENIGN-02 BENIGN-04" \
#          EVIDENCE=results/archive/attack_evidence_signed.jsonl ./tools/run_live_matrix.sh
#
#   Explicit cell list (overrides ATTACKS/BENIGN): CELLS="SCENARIO|args;SCENARIO|args;..."
#   PRESET=signed — only the cells the HMAC-token + signed-capability change can affect
#   (40 runs at REPEATS=5; superseded), into results/archive/attack_evidence_signed.jsonl:
#     sudo REPEATS=5 PRESET=signed ./tools/run_live_matrix.sh
#   PRESET=final — everything on the final code in one go (see PRESET_FINAL below):
#     sudo N_UES=9 REPEATS=5 PRESET=final ./tools/run_live_matrix.sh --fresh
#
# Prereqs you own (the script does NOT change them):
#   - free5GC built & provisioned with >= N subscribers (imsi-20893000000000{1..N})
#   - nrfcfg oauth: false   (so the SMF release is plain REST)
#   - the SAME python env that has PyYAML + colorama must be reachable as $PYTHON
#     (root's python3 by default — set PYTHON=/path/to/venv/bin/python3 if needed)
# =============================================================================
set -u

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FREE5GC="$ROOT/free5gc"
UERANSIM="$ROOT/UERANSIM"
LOGDIR="$ROOT/live_logs"
PYTHON="${PYTHON:-python3}"
EVIDENCE="${EVIDENCE:-}"         # default set below (depends on PRESET)

N_UES="${N_UES:-9}"              # testbed size; L3 rate cap (config max=3) bites when N_UES>3
REPEATS="${REPEATS:-3}"         # repeats per cell (>=3 so latency p50/p95 have samples)
READY_TIMEOUT="${READY_TIMEOUT:-90}"   # how long to wait for N sessions to come up
SETTLE="${SETTLE:-1}"           # wait after all N sessions report active, before the attack
SETTLE_TIMEOUT="${SETTLE_TIMEOUT:-20}"  # wait when the readiness check timed out (sessions may still be coming up)
UE_TEMPO="${UE_TEMPO:-2000}"    # ms between each UE start (nr-ue -t: avoids concurrent-PFCP drop)
SMF_HOST="127.0.0.2"; SMF_PORT="8000"
# Every NF the UE registration + PDU session path needs (SBI addresses from free5gc/config/*cfg.yaml).
# run.sh starts them in the order nrf amf smf udr pcf udm nssf ausf, so waiting for all of
# them replaces the old fixed 10 s "let the NFs come up" sleep.
CORE_SBI="127.0.0.10 127.0.0.18 127.0.0.2 127.0.0.4 127.0.0.7 127.0.0.3 127.0.0.31 127.0.0.9"
WEBCONSOLE_HOST="127.0.0.1"; WEBCONSOLE_PORT="5000"
NRF_GRACE="${NRF_GRACE:-2}"     # s after all SBI ports are open, for the NFs' NRF registration
POLL="${POLL:-0.5}"             # readiness poll interval (s)
GNB_CFG="$UERANSIM/config/free5gc-gnb.yaml"
UE_CFG="$UERANSIM/config/free5gc-ue.yaml"

# --- the matrix ------------------------------------------------------------- #
# Edit freely. Each line: "<SCENARIO> <extra args to run_attack_demo.py>".
read -r -a ATTACKS <<< "${ATTACKS:-ENUM-01 DOS-01 DOS-02 DOS-03}"
MODES=(
  "--gateway off"
  "--gateway rbac"
  "--gateway on --layers L1"
  "--gateway on --layers L1,L2"
  "--gateway on --layers L1,L3"
  "--gateway on"                       # full L1+L2+L3
)
read -r -a BENIGN <<< "${BENIGN:-BENIGN-01 BENIGN-02 BENIGN-03 BENIGN-04}"
BENIGN_MODES=("--gateway on" "--gateway rbac")

# Cells the HMAC-token (L1) + signed-capability (L2) change can affect. Modes without
# L1 cannot change for ENUM-01, modes without L2 cannot change for DOS-02, and RBAC
# has neither layer, so those cells keep their 130-run results.
PRESET_SIGNED="ENUM-01|--gateway on --layers L1;ENUM-01|--gateway on --layers L1,L2;\
ENUM-01|--gateway on --layers L1,L3;ENUM-01|--gateway on;\
DOS-02|--gateway on --layers L1,L2;DOS-02|--gateway on;\
BENIGN-02|--gateway on;BENIGN-04|--gateway on"
# PRESET=final — the whole matrix on the final code in ONE invocation (28 cells,
# 140 runs at REPEATS=5), into results/evidence/attack_evidence_final.jsonl:
#   - every cell under the default signed L2, plus the two DOS-02 cells under the
#     legacy claim-only L2 (--l2-claim-only) for the before/after comparison;
#   - cells that leave the core untouched (reads, or every release blocked) come
#     first in each repeat, so they share one core bring-up (REUSE_CORE);
#   - afterwards, on a fresh core, tools/double_release.py measures what a second
#     release of the same session does (results/evidence/double_release.jsonl).
PRESET_FINAL="ENUM-01|--gateway off;ENUM-01|--gateway rbac;ENUM-01|--gateway on --layers L1;\
ENUM-01|--gateway on --layers L1,L2;ENUM-01|--gateway on --layers L1,L3;ENUM-01|--gateway on;\
BENIGN-01|--gateway on;BENIGN-01|--gateway rbac;BENIGN-03|--gateway on;BENIGN-03|--gateway rbac;\
DOS-01|--gateway on --layers L1,L2;DOS-01|--gateway on;\
DOS-02|--gateway on --layers L1,L2;DOS-02|--gateway on;\
DOS-01|--gateway off;DOS-02|--gateway off;DOS-01|--gateway rbac;DOS-02|--gateway rbac;\
DOS-01|--gateway on --layers L1;DOS-02|--gateway on --layers L1;\
DOS-01|--gateway on --layers L1,L3;DOS-02|--gateway on --layers L1,L3;\
DOS-02|--gateway on --layers L1,L2 --l2-claim-only;DOS-02|--gateway on --l2-claim-only;\
DOS-03|--gateway off;DOS-03|--gateway rbac;DOS-03|--gateway on --layers L1;\
DOS-03|--gateway on --layers L1,L3;DOS-03|--gateway on;\
BENIGN-02|--gateway on;BENIGN-02|--gateway rbac;BENIGN-04|--gateway on;BENIGN-04|--gateway rbac"
# PRESET=latency — only the cells whose releases pass L3's core precheck (6 cells, 30 runs
# at REPEATS=5), into results/evidence/attack_evidence_latency.jsonl, each on a fresh core AND a
# fresh WebConsole. Blocking results do not depend on WebConsole speed, so nothing else
# needs a rerun.
PRESET_LATENCY="DOS-01|--gateway on --layers L1,L3;DOS-02|--gateway on --layers L1,L3;\
DOS-02|--gateway on --l2-claim-only;\
BENIGN-02|--gateway on;BENIGN-04|--gateway on;BENIGN-05|--gateway on"
if [ "${PRESET:-}" = "latency" ]; then
  CELLS="${CELLS:-$PRESET_LATENCY}"
  EVIDENCE="${EVIDENCE:-$ROOT/results/evidence/attack_evidence_latency.jsonl}"
elif [ "${PRESET:-}" = "signed" ]; then
  CELLS="${CELLS:-$PRESET_SIGNED}"
  EVIDENCE="${EVIDENCE:-$ROOT/results/archive/attack_evidence_signed.jsonl}"
elif [ "${PRESET:-}" = "final" ]; then
  CELLS="${CELLS:-$PRESET_FINAL}"
  EVIDENCE="${EVIDENCE:-$ROOT/results/evidence/attack_evidence_final.jsonl}"
  DOUBLE_RELEASE="${DOUBLE_RELEASE:-1}"
elif [ -n "${PRESET:-}" ]; then
  echo "unknown PRESET=$PRESET (known: signed, final, latency)"; exit 1
fi
EVIDENCE="${EVIDENCE:-$ROOT/attack_evidence.jsonl}"
REUSE_CORE="${REUSE_CORE:-1}"

# ---------------------------------------------------------------------------- #
c() { printf '\033[1;36m%s\033[0m\n' "$*"; }     # cyan
g() { printf '\033[1;32m%s\033[0m\n' "$*"; }     # green
y() { printf '\033[1;33m%s\033[0m\n' "$*"; }     # yellow

require_root() {
  if [ "$(id -u)" -ne 0 ]; then
    y "This script must run as root (free5GC + nr-ue need it).  Try: sudo $0"
    exit 1
  fi
}

teardown() {
  # UERANSIM first (SIGTERM lets nr-ue remove its uesimtun* interfaces cleanly)
  killall nr-gnb nr-ue  >/dev/null 2>&1
  sleep 1
  killall -9 nr-gnb nr-ue >/dev/null 2>&1
  # free5GC NFs (keeps the subscriber DB — no -db)
  ( cd "$FREE5GC" && ./force_kill.sh >/dev/null 2>&1 )
  # in case run.sh itself is still around
  [ -f "$FREE5GC/run.pid" ] && kill "$(cat "$FREE5GC/run.pid")" >/dev/null 2>&1
  killall -9 run.sh >/dev/null 2>&1
  # WebConsole is not part of run.sh / force_kill.sh, so it would otherwise live across
  # every bring-up. free5GC's WebConsole appends the NRF's AMF/SMF profiles to an
  # in-memory list on EVERY request and never clears it, so a long-lived instance gets
  # slower with the total number of requests served (this is what made the L3 core
  # precheck drift from ~20 ms to ~200 ms). Restart it with the core.
  killall webconsole >/dev/null 2>&1
  sleep 1
  killall -9 webconsole >/dev/null 2>&1
  # NFs killed with -9 never deregister, so the NRF's urilist keeps one stale entry per
  # NF per bring-up. Clear it while the NRF is down (re-created on registration).
  if [ "${CLEAN_NRF:-1}" = 1 ] && command -v mongo >/dev/null 2>&1; then
    mongo --quiet free5gc --eval 'db.urilist.deleteMany({})' >/dev/null 2>&1
  fi
  sleep 2
}

wait_port() {                                    # wait_port host port timeout
  local host="$1" port="$2" t="$3" end=$(( $(date +%s) + $3 ))
  while [ "$(date +%s)" -lt "$end" ]; do
    if (exec 3<>"/dev/tcp/$host/$port") 2>/dev/null; then exec 3>&- 3<&-; return 0; fi
    sleep "$POLL"
  done
  return 1
}

wait_log() {                                     # wait_log file pattern timeout
  local f="$1" pat="$2" end=$(( $(date +%s) + $3 ))
  while [ "$(date +%s)" -lt "$end" ]; do
    grep -q "$pat" "$f" 2>/dev/null && return 0
    sleep "$POLL"
  done
  return 1
}

bringup() {
  mkdir -p "$LOGDIR"
  c "  [1/3] starting free5GC core…"
  ( cd "$FREE5GC" && ./run.sh > "$LOGDIR/free5gc.log" 2>&1 ) &
  if ! wait_port "$SMF_HOST" "$SMF_PORT" 40; then
    y "  SMF SBI ($SMF_HOST:$SMF_PORT) did not come up — see $LOGDIR/free5gc.log"
    return 1
  fi
  local ip
  for ip in $CORE_SBI; do                          # all NFs listening, not just the SMF
    wait_port "$ip" 8000 30 || { y "  NF SBI $ip:8000 did not come up — see $LOGDIR/free5gc.log"; return 1; }
  done
  # fresh WebConsole for every core (see teardown)
  ( cd "$FREE5GC/webconsole" && ./bin/webconsole -c ../config/webuicfg.yaml > "$LOGDIR/webconsole.log" 2>&1 ) &
  wait_port "$WEBCONSOLE_HOST" "$WEBCONSOLE_PORT" 30 || y "  WebConsole not up yet (continuing) — see $LOGDIR/webconsole.log"
  sleep "$NRF_GRACE"                               # let the NFs finish registering with the NRF
  c "  [2/3] starting gNB…"
  : > "$LOGDIR/gnb.log"
  ( "$UERANSIM/build/nr-gnb" -c "$GNB_CFG" > "$LOGDIR/gnb.log" 2>&1 ) &
  wait_log "$LOGDIR/gnb.log" "NG Setup procedure is successful" 20 \
    || y "  gNB NG Setup not seen within 20s — see $LOGDIR/gnb.log (continuing)"
  c "  [3/3] starting $N_UES UE(s) (-t ${UE_TEMPO}ms apart)…"
  # -t/--tempo staggers each UE's start by UE_TEMPO ms. Without it, N UEs fire their
  # PDU Session Establishment Requests simultaneously and free5GC's SMF/UPF drops one
  # under the concurrent-PFCP burst — that UE then retransmits against a half-open
  # context forever (T3580), so we'd only ever see N-1 active sessions.
  ( "$UERANSIM/build/nr-ue" -c "$UE_CFG" -n "$N_UES" -t "$UE_TEMPO" > "$LOGDIR/ue.log" 2>&1 ) &
  # Wait until the sessions are actually up (the signal the demo gates on).
  # Non-fatal: if it times out we still settle + attempt, and the demo itself
  # honestly aborts (exit 2) if the core really is not ready. (No fixed pre-sleep: the
  # probe itself polls; the first UE needs ~1 s, the last starts (N-1)*UE_TEMPO ms later.)
  if "$PYTHON" "$ROOT/tools/_wait_sessions.py" --need "$N_UES" --timeout "$READY_TIMEOUT" --interval "$POLL"; then
    g "  sessions up; settling ${SETTLE}s before the attack…"
    sleep "$SETTLE"
  else
    y "  sessions not all up within ${READY_TIMEOUT}s; settling ${SETTLE_TIMEOUT}s then attempting anyway…"
    sleep "$SETTLE_TIMEOUT"
  fi
  return 0
}

run_cell() {                                      # run_cell SCENARIO "extra args"
  local scenario="$1"; shift
  "$PYTHON" "$ROOT/run_attack_demo.py" --scenario "$scenario" --evidence "$EVIDENCE" "$@"
}

# ---------------------------------------------------------------------------- #
main() {
  require_root
  if [ "${1:-}" = "--fresh" ] && [ -f "$EVIDENCE" ]; then
    local bak="$EVIDENCE.$(date +%s).bak"
    mv "$EVIDENCE" "$bak"; y "backed up old evidence -> $bak"
  fi

  trap 'echo; y "interrupted — tearing down"; teardown; exit 130' INT TERM
  c "  killing any running core / gNB / UEs / WebConsole first…"
  teardown

  # build the work list: explicit CELLS, else attacks x modes, then benign x benign-modes
  local -a WORK=()
  if [ -n "${CELLS:-}" ]; then
    IFS=';' read -r -a WORK <<< "$CELLS"
  else
    for s in "${ATTACKS[@]}"; do for m in "${MODES[@]}"; do WORK+=("$s|$m"); done; done
    for s in "${BENIGN[@]}"; do for m in "${BENIGN_MODES[@]}"; do WORK+=("$s|$m"); done; done
  fi
  mkdir -p "$(dirname "$EVIDENCE")"; touch "$EVIDENCE"

  local total=$(( ${#WORK[@]} * REPEATS )) i=0 ok=0 fail=0 bringups=0 core_up=0
  c "=== live matrix: ${#WORK[@]} cell(s) x $REPEATS repeat(s) = $total run(s), N_UES=$N_UES ==="
  c "    evidence: $EVIDENCE   core reuse: $([ "$REUSE_CORE" = 1 ] && echo on || echo off)"

  for rep in $(seq 1 "$REPEATS"); do
    for cell in "${WORK[@]}"; do
      i=$((i+1))
      local scenario="${cell%%|*}" args="${cell#*|}"
      c ""
      c "────────────────────────────────────────────────────────────"
      c "[$i/$total] rep $rep  scenario=$scenario  args: $args"
      local reused=false
      if [ "$core_up" = 1 ] && "$PYTHON" "$ROOT/tools/_wait_sessions.py" --need "$N_UES" --timeout 0; then
        g "  reusing the running core (previous run changed no core state; $N_UES sessions up)"
        reused=true
      else
        teardown; core_up=0
        if ! bringup; then
          y "  bring-up failed — skipping this cell"; fail=$((fail+1)); continue
        fi
        bringups=$((bringups+1))
      fi
      local before; before=$(grep -c . "$EVIDENCE")
      if MATRIX_CORE_REUSED="$reused" run_cell "$scenario" $args; then
        g "  ✓ run complete (evidence appended)"; ok=$((ok+1))
        core_up=0
        if [ "$REUSE_CORE" = 1 ] && "$PYTHON" "$ROOT/tools/_core_untouched.py" "$EVIDENCE" \
             --expect-lines $((before+1)); then
          core_up=1
        fi
      else
        y "  ✗ run_attack_demo exited non-zero (core not ready? see output above)"; fail=$((fail+1))
        core_up=0
      fi
    done
  done

  if [ "${DOUBLE_RELEASE:-0}" = 1 ]; then
    c "=== double release (Sec. V-B): fresh core, no gateway ==="
    teardown
    if bringup; then
      "$PYTHON" "$ROOT/tools/double_release.py" --out "$ROOT/results/evidence/double_release.jsonl" \
        && g "  ✓ double release recorded -> results/evidence/double_release.jsonl" \
        || y "  ✗ double release did not complete (see output above)"
    else
      y "  bring-up failed — double release skipped"
    fi
  fi

  teardown
  trap - INT TERM
  c ""
  g "=== done: $ok ok, $fail failed, of $total ($bringups fresh core bring-up(s)) ==="
  c "aggregate with:  $PYTHON tools/aggregate.py $EVIDENCE"
}

main "$@"
