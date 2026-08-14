#!/usr/bin/env bash
set -euo pipefail
TESTNET_NAME=link_impairments_tcp
source "$(dirname "$0")/lib.sh"
prepare_testnet
for n in left wire right; do : >"$TESTNET_DIR/media/$n.vnet"; done
start_target impaired-link "$(vnet_target connect)" "$TESTNET_DIR/media/left.vnet" "$TESTNET_DIR/media/right.vnet" -b -latency 40 -jitter 15 -bandwidth 100000 -queue 8 -loss 1000 -corrupt 200 -fcs-fail 200 -reorder 1000 -seed 42
start_target host-a "$(vnet_target host)" "$TESTNET_DIR/media/left.vnet" 02:00:00:00:40:0a -ip4 10.40.0.10
start_target host-b "$(vnet_target host)" "$TESTNET_DIR/media/right.vnet" 02:00:00:00:40:0b -ip4 10.40.0.11
sleep 1
send_command host-a 'arp 10.40.0.11'
send_command host-a 'socket open tcp 4100'
printf 'Use impaired-link commands: info, link down, link up. Inspect retry/drop counters in its log.\n'
wait_for_user
