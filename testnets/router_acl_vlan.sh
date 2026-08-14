#!/usr/bin/env bash
set -euo pipefail
TESTNET_NAME=router_acl_vlan
source "$(dirname "$0")/lib.sh"
prepare_testnet
for n in switch switch-router switch-vlan10 switch-vlan20 router-trunk router-uplink host-vlan10 host-vlan20 external; do : >"$TESTNET_DIR/media/$n.vnet"; done
start_target switch "$(vnet_target switch)" "$TESTNET_DIR/media/switch.vnet" -bridge 32768 02:00:00:00:60:10 -f trunk 10,20 "$TESTNET_DIR/media/switch-router.vnet" access 10 "$TESTNET_DIR/media/switch-vlan10.vnet" access 20 "$TESTNET_DIR/media/switch-vlan20.vnet"
start_target router "$(vnet_target router)" -i "$TESTNET_DIR/media/router-trunk.vnet" 02:00:00:00:60:01 192.168.60.1 255.255.255.0 -subif 1 10 10.60.10.1 255.255.255.0 -subif 1 20 10.60.20.1 255.255.255.0 -i "$TESTNET_DIR/media/router-uplink.vnet" 02:00:00:00:60:02 172.60.0.1 255.255.255.0 -acl-default 2 in deny -acl 2 in 10 permit 10.60.10.0 255.255.255.0 172.60.0.0 255.255.255.0 icmp any any
start_target host-vlan10 "$(vnet_target host)" "$TESTNET_DIR/media/host-vlan10.vnet" 02:00:00:00:60:1a -ip4 10.60.10.10 -gateway 10.60.10.1
start_target host-vlan20 "$(vnet_target host)" "$TESTNET_DIR/media/host-vlan20.vnet" 02:00:00:00:60:2a -ip4 10.60.20.10 -gateway 10.60.20.1
start_target external "$(vnet_target host)" "$TESTNET_DIR/media/external.vnet" 02:00:00:00:60:ee -ip4 172.60.0.10 -gateway 172.60.0.1
start_target link-router-trunk "$(vnet_target connect)" "$TESTNET_DIR/media/router-trunk.vnet" "$TESTNET_DIR/media/switch-router.vnet" -b
start_target link-vlan10 "$(vnet_target connect)" "$TESTNET_DIR/media/host-vlan10.vnet" "$TESTNET_DIR/media/switch-vlan10.vnet" -b
start_target link-vlan20 "$(vnet_target connect)" "$TESTNET_DIR/media/host-vlan20.vnet" "$TESTNET_DIR/media/switch-vlan20.vnet" -b
start_target link-uplink "$(vnet_target connect)" "$TESTNET_DIR/media/router-uplink.vnet" "$TESTNET_DIR/media/external.vnet" -b
sleep 1
send_command router info
printf 'Router-on-a-stick is configured: subinterfaces 2/3 map VLANs 10/20. ACL default deny is on uplink ingress.\n'
wait_for_user
