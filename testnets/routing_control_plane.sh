#!/usr/bin/env bash
set -euo pipefail
TESTNET_NAME=routing_control_plane
source "$(dirname "$0")/lib.sh"
prepare_testnet
for n in r1-r2 r2-r1 r2-r3 r3-r2 r1-lan host-a r3-lan host-b; do : >"$TESTNET_DIR/media/$n.vnet"; done
start_target r1 "$(vnet_target router)" -i "$TESTNET_DIR/media/r1-r2.vnet" 02:00:00:00:70:01 10.70.12.1 255.255.255.0 -i "$TESTNET_DIR/media/r1-lan.vnet" 02:00:00:00:70:11 10.70.1.1 255.255.255.0 -dynamic-routing rip
start_target r2 "$(vnet_target router)" -i "$TESTNET_DIR/media/r2-r1.vnet" 02:00:00:00:70:02 10.70.12.2 255.255.255.0 -i "$TESTNET_DIR/media/r2-r3.vnet" 02:00:00:00:70:23 10.70.23.2 255.255.255.0 -dynamic-routing rip
start_target r3 "$(vnet_target router)" -i "$TESTNET_DIR/media/r3-r2.vnet" 02:00:00:00:70:03 10.70.23.3 255.255.255.0 -i "$TESTNET_DIR/media/r3-lan.vnet" 02:00:00:00:70:31 10.70.3.1 255.255.255.0 -dynamic-routing rip
start_target host-a "$(vnet_target host)" "$TESTNET_DIR/media/host-a.vnet" 02:00:00:00:70:1a -ip4 10.70.1.10 -gateway 10.70.1.1
start_target host-b "$(vnet_target host)" "$TESTNET_DIR/media/host-b.vnet" 02:00:00:00:70:3a -ip4 10.70.3.10 -gateway 10.70.3.1
start_target link-r1-r2 "$(vnet_target connect)" "$TESTNET_DIR/media/r1-r2.vnet" "$TESTNET_DIR/media/r2-r1.vnet" -b
start_target link-r2-r3 "$(vnet_target connect)" "$TESTNET_DIR/media/r2-r3.vnet" "$TESTNET_DIR/media/r3-r2.vnet" -b
start_target link-r1-host "$(vnet_target connect)" "$TESTNET_DIR/media/r1-lan.vnet" "$TESTNET_DIR/media/host-a.vnet" -b
start_target link-r3-host "$(vnet_target connect)" "$TESTNET_DIR/media/r3-lan.vnet" "$TESTNET_DIR/media/host-b.vnet" -b
sleep 2
send_command r1 info; send_command r2 info; send_command r3 info
printf 'Use dynamic-routing ospf, route, prefix-list, bgp-prefix-list, rip-prefix-list, NAT/PAT commands to exercise control-plane variants.\n'
wait_for_user
