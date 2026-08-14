#!/usr/bin/env bash
set -euo pipefail
TESTNET_NAME=basic_lan
source "$(dirname "$0")/lib.sh"
prepare_testnet
for n in hub hub-a hub-b hub-watch host-a host-b watch; do : >"$TESTNET_DIR/media/$n.vnet"; done
start_target hub "$(vnet_target hub)" "$TESTNET_DIR/media/hub.vnet" -f "$TESTNET_DIR/media/hub-a.vnet" "$TESTNET_DIR/media/hub-b.vnet" "$TESTNET_DIR/media/hub-watch.vnet"
start_target host-a "$(vnet_target host)" "$TESTNET_DIR/media/host-a.vnet" 02:00:00:00:00:0a -ip4 10.0.0.10
start_target host-b "$(vnet_target host)" "$TESTNET_DIR/media/host-b.vnet" 02:00:00:00:00:0b -ip4 10.0.0.11
start_target watch "$(vnet_target watch)" "$TESTNET_DIR/media/watch.vnet"
start_target link-hub-a "$(vnet_target connect)" "$TESTNET_DIR/media/host-a.vnet" "$TESTNET_DIR/media/hub-a.vnet" -b
start_target link-hub-b "$(vnet_target connect)" "$TESTNET_DIR/media/host-b.vnet" "$TESTNET_DIR/media/hub-b.vnet" -b
start_target link-hub-watch "$(vnet_target connect)" "$TESTNET_DIR/media/watch.vnet" "$TESTNET_DIR/media/hub-watch.vnet" -b
sleep 1
send_command host-a 'arp 10.0.0.11'
send_command host-a 'ping 10.0.0.11'
send_command host-a 'udp 4000 5000 hello-udp'
send_command host-a 'tcp 4001 5001 syn'
printf 'Basic LAN commands injected; inspect host/watch logs.\n'
wait_for_user
