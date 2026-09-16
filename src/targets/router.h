/*
 * MIT License
 *
 * Copyright (c) 2026 Christian Luppi
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
#pragma once

/*
Interactive IPv4 router connecting multiple append-only VNet media.
OSI/ISO layer: Layer 3; it routes IPv4 packets and resolves each egress next hop through ARP.
*/

#include <arp.h>
#include <arp_table.h>
#include <cmd_app.h>

#include <dhcp.h>
#include <ethernet.h>
#include <futils.h>
#include <icmp.h>
#include <interface_table.h>
#include <ipv4.h>
#include <math.h>
#include <mutex.h>
#include <nat.h>
#include <rarp.h>
#include <rarp_table.h>
#include <route_table.h>
#include <tcp.h>
#include <udp.h>

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <thread.h>
#include <time.h>
#include <vnet.h>

#define ROUTER_INTERFACE_CAPACITY    16
#define ROUTER_ROUTE_CAPACITY        128
#define ROUTER_ARP_CAPACITY          256
#define ROUTER_RARP_CAPACITY         128
#define ROUTER_PENDING_CAPACITY      64
#define ROUTER_NAT_CAPACITY          128
#define ROUTER_NAT_POOL_CAPACITY     32
#define ROUTER_DHCP_RELAY_CAPACITY   16
#define ROUTER_ACL_RULE_CAPACITY     64

#define ROUTER_BUFFER_SIZE           8192
#define SLEEP_INTERVAL_MS            5
#define ROUTER_ARP_RETRY_INTERVAL_SECONDS 1
#define ROUTER_ARP_RETRY_LIMIT            3

typedef struct router_port {
  FILE* source;
  FILE* destination;
  uint8_t buffer[ROUTER_BUFFER_SIZE];
  size_t buffer_length;
  size_t injected_bytes;
} router_port_t;

typedef enum router_acl_direction {
  ROUTER_ACL_DIRECTION_INGRESS,
  ROUTER_ACL_DIRECTION_EGRESS,
} router_acl_direction_t;

typedef enum router_acl_action {
  ROUTER_ACL_ACTION_DENY,
  ROUTER_ACL_ACTION_PERMIT,
} router_acl_action_t;

typedef struct router_acl_rule {
  uint16_t sequence;
  uint16_t src_port;
  uint16_t dst_port;
  ipv4_address_t src_network;
  ipv4_address_t src_mask;
  ipv4_address_t dst_network;
  ipv4_address_t dst_mask;
  uint64_t packets;
  uint64_t bytes;
  size_t interface_index;
  uint8_t protocol;
  bool src_port_any;
  bool dst_port_any;
  bool active;
  router_acl_direction_t direction;
  router_acl_action_t action;
} router_acl_rule_t;

typedef struct router_pending_packet {
  ipv4_header_t header;
  ipv4_header_t report_header;
  uint8_t payload[ETHERNET_MAX_DATA_LEN - sizeof(ipv4_header_t)];
  uint8_t report_payload[ETHERNET_MAX_DATA_LEN - sizeof(ipv4_header_t)];
  ipv4_address_t next_hop;
  size_t egress_interface;
  size_t report_interface;
  uint16_t payload_length;
  uint16_t report_payload_length;
  uint32_t next_retry_at;
  uint8_t arp_attempts;
  bool report_next_hop_failure;
  bool active;
} router_pending_packet_t;

typedef struct router_dhcp_relay_entry {
  uint16_t transaction_id;
  mac_address_t client_mac;
  ipv4_address_t server_address;
  size_t ingress_interface;
  uint32_t updated_at;
  bool active;
} router_dhcp_relay_entry_t;

typedef struct router_context {
  interface_entry_t interface_entries[ROUTER_INTERFACE_CAPACITY];
  route_entry_t route_entries[ROUTER_ROUTE_CAPACITY];
  arp_entry_t arp_entries[ROUTER_ARP_CAPACITY];
  rarp_entry_t rarp_entries[ROUTER_RARP_CAPACITY];
  router_pending_packet_t pending_packets[ROUTER_PENDING_CAPACITY];
  router_acl_rule_t acl_rules[ROUTER_ACL_RULE_CAPACITY];
  interface_table_t interfaces;
  route_table_t routes;
  arp_table_t arp;
  rarp_table_t rarp;
  router_port_t ports[ROUTER_INTERFACE_CAPACITY];
  router_dhcp_relay_entry_t dhcp_relays[ROUTER_DHCP_RELAY_CAPACITY];
  nat_entry_t nat_entries[ROUTER_NAT_CAPACITY];

  ipv4_address_t nat_pool[ROUTER_NAT_POOL_CAPACITY];
  ipv4_address_t dhcp_relay_servers[ROUTER_INTERFACE_CAPACITY];
  nat_table_t nat;
  size_t nat_inside_interface;
  size_t nat_outside_interface;
  bool nat_enabled;
  bool dynamic_nat_enabled;
  bool dynamic_pat_enabled;
  size_t port_count;
  router_acl_action_t acl_defaults[ROUTER_INTERFACE_CAPACITY][2];
  uint64_t acl_default_packets[ROUTER_INTERFACE_CAPACITY][2];
  uint64_t acl_default_bytes[ROUTER_INTERFACE_CAPACITY][2];
  mutex_t mutex;
  cmd_app_t commands;
} router_context_t;
