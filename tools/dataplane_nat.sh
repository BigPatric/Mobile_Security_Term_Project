#!/usr/bin/env bash
# Optional data-plane NAT for the free5GC UE pool, so UEs can reach the internet
# and the demo can show data-plane evidence (ping works before an attack, fails after).
# This is free5GC data-plane NAT on the host, not VMware adapter NAT.
#
# Usage (root, after the UPF is up):
#   sudo ./tools/dataplane_nat.sh up|down|status
# Override defaults with env vars: UE_POOL=10.60.0.0/16 UPLINK_IF=enp2s0
set -euo pipefail

UE_POOL="${UE_POOL:-10.60.0.0/16}"
UPLINK_IF="${UPLINK_IF:-enp2s0}"
RULE=(POSTROUTING -s "$UE_POOL" -o "$UPLINK_IF" -j MASQUERADE)

case "${1:-}" in
  up)
    sysctl -qw net.ipv4.ip_forward=1
    iptables -t nat -C "${RULE[@]}" 2>/dev/null || iptables -t nat -A "${RULE[@]}"
    echo "NAT up: $UE_POOL -> $UPLINK_IF"
    ;;
  down)
    while iptables -t nat -C "${RULE[@]}" 2>/dev/null; do
      iptables -t nat -D "${RULE[@]}"
    done
    echo "NAT down: $UE_POOL -> $UPLINK_IF"
    ;;
  status)
    if iptables -t nat -C "${RULE[@]}" 2>/dev/null; then echo "up"; else echo "down"; fi
    ;;
  *)
    echo "usage: $0 up|down|status" >&2
    exit 2
    ;;
esac
