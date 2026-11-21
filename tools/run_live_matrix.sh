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
# MUST run as root (free5GC run.sh and UERANSIM nr-ue need it):
#     sudo ./tools/run_live_matrix.sh
#     sudo ./tools/run_live_matrix.sh --fresh          # back up old evidence first
#     sudo N_UES=3 REPEATS=3 ./tools/run_live_matrix.sh # 3x repeats for latency stats
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
EVIDENCE="$ROOT/attack_evidence.jsonl"

N_UES="${N_UES:-3}"              # testbed size; L3 rate cap (config max=2) bites when N_UES>2
REPEATS="${REPEATS:-3}"         # repeats per cell (>=3 so latency p50/p95 have samples)
READY_TIMEOUT="${READY_TIMEOUT:-90}"   # how long to wait for N sessions to come up
SETTLE="${SETTLE:-20}"          # extra margin after sessions report active, before the attack
UE_TEMPO="${UE_TEMPO:-2000}"    # ms between each UE start (nr-ue -t: avoids concurrent-PFCP drop)
SMF_HOST="127.0.0.2"; SMF_PORT="8000"
GNB_CFG="$UERANSIM/config/free5gc-gnb.yaml"
UE_CFG="$UERANSIM/config/free5gc-ue.yaml"

# --- the matrix ------------------------------------------------------------- #
# Edit freely. Each line: "<SCENARIO> <extra args to run_attack_demo.py>".
ATTACKS=(ENUM-01 DOS-01 DOS-02)
MODES=(
  "--gateway off"
  "--gateway rbac"
  "--gateway on --layers L1"
  "--gateway on --layers L1,L2"
  "--gateway on --layers L1,L3"
  "--gateway on"                       # full L1+L2+L3
)
BENIGN=(BENIGN-01 BENIGN-02 BENIGN-03 BENIGN-04)
BENIGN_MODES=("--gateway on" "--gateway rbac")

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
  sleep 2
}

wait_port() {                                    # wait_port host port timeout
  local host="$1" port="$2" t="$3" end=$(( $(date +%s) + $3 ))
  while [ "$(date +%s)" -lt "$end" ]; do
    if (exec 3<>"/dev/tcp/$host/$port") 2>/dev/null; then exec 3>&- 3<&-; return 0; fi
    sleep 1
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
  sleep 10                                         # let the other NFs register with the NRF
  c "  [2/3] starting gNB…"
  ( "$UERANSIM/build/nr-gnb" -c "$GNB_CFG" > "$LOGDIR/gnb.log" 2>&1 ) &
  sleep 10
  c "  [3/3] starting $N_UES UE(s) (-t ${UE_TEMPO}ms apart)…"
  # -t/--tempo staggers each UE's start by UE_TEMPO ms. Without it, N UEs fire their
  # PDU Session Establishment Requests simultaneously and free5GC's SMF/UPF drops one
  # under the concurrent-PFCP burst — that UE then retransmits against a half-open
  # context forever (T3580), so we'd only ever see N-1 active sessions.
  ( "$UERANSIM/build/nr-ue" -c "$UE_CFG" -n "$N_UES" -t "$UE_TEMPO" > "$LOGDIR/ue.log" 2>&1 ) &
  # Wait until the sessions are actually up (the signal the demo gates on).
  # Non-fatal: if it times out we still settle + attempt, and the demo itself
  # honestly aborts (exit 2) if the core really is not ready.
  sleep 10
  if "$PYTHON" "$ROOT/tools/_wait_sessions.py" --need "$N_UES" --timeout "$READY_TIMEOUT"; then
    g "  sessions up; settling ${SETTLE}s before the attack…"
  else
    y "  sessions not all up within ${READY_TIMEOUT}s; settling ${SETTLE}s then attempting anyway…"
  fi
  sleep "$SETTLE"
  return 0
}

run_cell() {                                      # run_cell SCENARIO "extra args"
  local scenario="$1"; shift
  "$PYTHON" "$ROOT/run_attack_demo.py" --scenario "$scenario" "$@"
}

# ---------------------------------------------------------------------------- #
main() {
  require_root
  if [ "${1:-}" = "--fresh" ] && [ -f "$EVIDENCE" ]; then
    local bak="$EVIDENCE.$(date +%s).bak"
    mv "$EVIDENCE" "$bak"; y "backed up old evidence -> $bak"
  fi

  trap 'echo; y "interrupted — tearing down"; teardown; exit 130' INT TERM

  # build the full work list: attacks x modes, then benign x benign-modes
  local -a CELLS=()
  for s in "${ATTACKS[@]}"; do for m in "${MODES[@]}"; do CELLS+=("$s|$m"); done; done
  for s in "${BENIGN[@]}"; do for m in "${BENIGN_MODES[@]}"; do CELLS+=("$s|$m"); done; done

  local total=$(( ${#CELLS[@]} * REPEATS )) i=0 ok=0 fail=0
  c "=== live matrix: ${#CELLS[@]} cell(s) x $REPEATS repeat(s) = $total run(s), N_UES=$N_UES ==="

  for rep in $(seq 1 "$REPEATS"); do
    for cell in "${CELLS[@]}"; do
      i=$((i+1))
      local scenario="${cell%%|*}" args="${cell#*|}"
      c ""
      c "────────────────────────────────────────────────────────────"
      c "[$i/$total] rep $rep  scenario=$scenario  args: $args"
      teardown
      if ! bringup; then
        y "  bring-up failed — skipping this cell"; fail=$((fail+1)); continue
      fi
      if run_cell "$scenario" $args; then
        g "  ✓ run complete (evidence appended)"; ok=$((ok+1))
      else
        y "  ✗ run_attack_demo exited non-zero (core not ready? see output above)"; fail=$((fail+1))
      fi
    done
  done

  teardown
  trap - INT TERM
  c ""
  g "=== done: $ok ok, $fail failed, of $total ==="
  c "aggregate with:  $PYTHON tools/aggregate.py $EVIDENCE"
}

main "$@"
