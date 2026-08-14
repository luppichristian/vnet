#!/usr/bin/env bash
set -euo pipefail
TESTNET_NAME=services_dhcp_dns
source "$(dirname "$0")/lib.sh"
prepare_testnet
for n in hub hub-router hub-dhcp hub-dns router-client router-services client dhcp dns; do : >"$TESTNET_DIR/media/$n.vnet"; done
start_target hub "$(vnet_target hub)" "$TESTNET_DIR/media/hub.vnet" -f "$TESTNET_DIR/media/hub-router.vnet" "$TESTNET_DIR/media/hub-dhcp.vnet" "$TESTNET_DIR/media/hub-dns.vnet"
start_target router "$(vnet_target router)" -i "$TESTNET_DIR/media/router-client.vnet" 02:00:00:00:30:01 10.30.1.1 255.255.255.0 -i "$TESTNET_DIR/media/router-services.vnet" 02:00:00:00:30:02 10.30.2.1 255.255.255.0 -dhcp-relay 1 10.30.2.2
start_target dhcp "$(vnet_target dhcp_server)" "$TESTNET_DIR/media/dhcp.vnet" 02:00:00:00:30:20 10.30.2.2
start_target dns "$(vnet_target dns_server)" "$TESTNET_DIR/media/dns.vnet" 02:00:00:00:30:21 10.30.2.3 A lab.local 10.30.2.3 CNAME alias.local lab.local
start_target client "$(vnet_target host)" "$TESTNET_DIR/media/client.vnet" 02:00:00:00:30:0a -dhcp
start_target link-client "$(vnet_target connect)" "$TESTNET_DIR/media/client.vnet" "$TESTNET_DIR/media/router-client.vnet" -b
start_target link-router-services "$(vnet_target connect)" "$TESTNET_DIR/media/router-services.vnet" "$TESTNET_DIR/media/hub-router.vnet" -b
start_target link-dhcp "$(vnet_target connect)" "$TESTNET_DIR/media/dhcp.vnet" "$TESTNET_DIR/media/hub-dhcp.vnet" -b
start_target link-dns "$(vnet_target connect)" "$TESTNET_DIR/media/dns.vnet" "$TESTNET_DIR/media/hub-dns.vnet" -b
sleep 1
send_command dhcp 'config 10.30.1.100 10.30.1.110 255.255.255.0 10.30.1.1 10.30.2.3'
send_command client dhcp
printf 'DHCP relay and DNS service are running; inspect leases and issue dns lab.local after assignment.\n'
wait_for_user
