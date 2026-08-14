#!/usr/bin/env bash
set -euo pipefail
TESTNET_NAME=router_ipv4
source "$(dirname "$0")/lib.sh"
prepare_testnet
for n in router-left router-right left-host right-host; do : >"$TESTNET_DIR/media/$n.vnet"; done
start_target router "$(vnet_target router)" -i "$TESTNET_DIR/media/router-left.vnet" 02:00:00:00:20:01 10.20.1.1 255.255.255.0 -i "$TESTNET_DIR/media/router-right.vnet" 02:00:00:00:20:02 10.20.2.1 255.255.255.0
start_target left-host "$(vnet_target host)" "$TESTNET_DIR/media/left-host.vnet" 02:00:00:00:20:0a -ip4 10.20.1.10 -gateway 10.20.1.1
start_target right-host "$(vnet_target host)" "$TESTNET_DIR/media/right-host.vnet" 02:00:00:00:20:0b -ip4 10.20.2.10 -gateway 10.20.2.1
start_target link-left "$(vnet_target connect)" "$TESTNET_DIR/media/left-host.vnet" "$TESTNET_DIR/media/router-left.vnet" -b
start_target link-right "$(vnet_target connect)" "$TESTNET_DIR/media/right-host.vnet" "$TESTNET_DIR/media/router-right.vnet" -b
sleep 1
send_command left-host 'ping 10.20.2.10'
send_command router info
printf 'Add routes/NAT/RARP entries interactively through router.stdin/log if desired.\n'
wait_for_user
