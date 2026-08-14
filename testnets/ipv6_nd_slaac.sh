#!/usr/bin/env bash
set -euo pipefail
TESTNET_NAME=ipv6_nd_slaac
source "$(dirname "$0")/lib.sh"
prepare_testnet
for n in hub hub-router hub-a hub-b router-lan router-uplink host-a host-b uplink-host; do : >"$TESTNET_DIR/media/$n.vnet"; done
start_target hub "$(vnet_target hub)" "$TESTNET_DIR/media/hub.vnet" -f "$TESTNET_DIR/media/hub-router.vnet" "$TESTNET_DIR/media/hub-a.vnet" "$TESTNET_DIR/media/hub-b.vnet"
start_target router "$(vnet_target router)" -i "$TESTNET_DIR/media/router-lan.vnet" 02:00:00:00:50:01 10.50.0.1 255.255.255.0 -i "$TESTNET_DIR/media/router-uplink.vnet" 02:00:00:00:50:02 10.50.1.1 255.255.255.0
start_target host-a "$(vnet_target host)" "$TESTNET_DIR/media/host-a.vnet" 02:00:00:00:50:0a -ip4 10.50.0.10
start_target host-b "$(vnet_target host)" "$TESTNET_DIR/media/host-b.vnet" 02:00:00:00:50:0b -ip4 10.50.0.11
start_target uplink-host "$(vnet_target host)" "$TESTNET_DIR/media/uplink-host.vnet" 02:00:00:00:50:1a -ip4 10.50.1.10 -gateway 10.50.1.1
start_target link-router-lan "$(vnet_target connect)" "$TESTNET_DIR/media/router-lan.vnet" "$TESTNET_DIR/media/hub-router.vnet" -b
start_target link-host-a "$(vnet_target connect)" "$TESTNET_DIR/media/host-a.vnet" "$TESTNET_DIR/media/hub-a.vnet" -b
start_target link-host-b "$(vnet_target connect)" "$TESTNET_DIR/media/host-b.vnet" "$TESTNET_DIR/media/hub-b.vnet" -b
start_target link-uplink "$(vnet_target connect)" "$TESTNET_DIR/media/router-uplink.vnet" "$TESTNET_DIR/media/uplink-host.vnet" -b
sleep 2
send_command host-a info; send_command host-b info
printf 'Check router advertisements/SLAAC in host logs, then issue ping6 using a displayed IPv6 address.\n'
wait_for_user
