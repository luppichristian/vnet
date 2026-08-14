#!/usr/bin/env bash
set -euo pipefail
TESTNET_NAME=switch_vlan_stp
source "$(dirname "$0")/lib.sh"
prepare_testnet
for n in sw1 sw1-a sw1-trunk-a sw1-trunk-b sw2 sw2-b sw2-trunk-a sw2-trunk-b host-a host-b; do : >"$TESTNET_DIR/media/$n.vnet"; done
start_target sw1 "$(vnet_target switch)" "$TESTNET_DIR/media/sw1.vnet" -bridge 32768 02:00:00:00:10:01 -f access 10 "$TESTNET_DIR/media/sw1-a.vnet" trunk 10 "$TESTNET_DIR/media/sw1-trunk-a.vnet" trunk 10 "$TESTNET_DIR/media/sw1-trunk-b.vnet"
start_target sw2 "$(vnet_target switch)" "$TESTNET_DIR/media/sw2.vnet" -bridge 32768 02:00:00:00:10:02 -f access 10 "$TESTNET_DIR/media/sw2-b.vnet" trunk 10 "$TESTNET_DIR/media/sw2-trunk-a.vnet" trunk 10 "$TESTNET_DIR/media/sw2-trunk-b.vnet"
start_target host-a "$(vnet_target host)" "$TESTNET_DIR/media/host-a.vnet" 02:00:00:00:10:0a -ip4 10.10.0.10
start_target host-b "$(vnet_target host)" "$TESTNET_DIR/media/host-b.vnet" 02:00:00:00:10:0b -ip4 10.10.0.11
start_target link-host-a "$(vnet_target connect)" "$TESTNET_DIR/media/host-a.vnet" "$TESTNET_DIR/media/sw1-a.vnet" -b
start_target link-host-b "$(vnet_target connect)" "$TESTNET_DIR/media/host-b.vnet" "$TESTNET_DIR/media/sw2-b.vnet" -b
start_target link-trunk-a "$(vnet_target connect)" "$TESTNET_DIR/media/sw1-trunk-a.vnet" "$TESTNET_DIR/media/sw2-trunk-a.vnet" -b
start_target link-trunk-b "$(vnet_target connect)" "$TESTNET_DIR/media/sw1-trunk-b.vnet" "$TESTNET_DIR/media/sw2-trunk-b.vnet" -b
sleep 4
send_command sw1 info; send_command sw2 info
send_command host-a 'ping 10.10.0.11'
printf 'STP should elect one alternate/blocking redundant port; check sw1/sw2 logs.\n'
wait_for_user
