#pragma once

/*
Interactive IPv4 router connecting multiple append-only VNet media.
OSI/ISO layer: Layer 3; it routes IPv4 packets and resolves each egress next hop through ARP.
*/

#include <arp.h>
#include <arp_table.h>
#include <bgp.h>
#include <cmd_app.h>

#include <dhcp.h>
#include <ethernet.h>
#include <futils.h>
#include <icmp.h>
#include <icmpv6.h>
#include <interface_table.h>
#include <ipv4.h>
#include <ipv6.h>
#include <math.h>
#include <mutex.h>
#include <nat.h>
#include <nd_table.h>
#include <ndp.h>
#include <ospf.h>
#include <prefix_list.h>
#include <rarp.h>
#include <rarp_table.h>
#include <rip.h>
#include <route_table.h>
#include <socket.h>
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
#define ROUTER_ND_CAPACITY           256
#define ROUTER_RARP_CAPACITY         128
#define ROUTER_PENDING_CAPACITY      64
#define ROUTER_BGP_PEER_CAPACITY     16
#define ROUTER_PREFIX_LIST_CAPACITY  128
#define ROUTER_NAT_CAPACITY          128
#define ROUTER_NAT_POOL_CAPACITY     32
#define ROUTER_DHCP_RELAY_CAPACITY   16
#define ROUTER_ACL_RULE_CAPACITY     64

#define ROUTER_BUFFER_SIZE           8192
#define SLEEP_INTERVAL_MS            5
#define RIP_ROUTE_TIMEOUT_SECONDS    180
#define RIP_UPDATE_INTERVAL_SECONDS  30
#define OSPF_ROUTE_TIMEOUT_SECONDS   40
#define OSPF_UPDATE_INTERVAL_SECONDS 10
#define ROUTER_ARP_RETRY_INTERVAL_SECONDS 1
#define ROUTER_ARP_RETRY_LIMIT            3
#define ROUTER_RA_INTERVAL_SECONDS        10

typedef enum router_dynamic_routing_mode {
  ROUTER_DYNAMIC_ROUTING_OFF,
  ROUTER_DYNAMIC_ROUTING_RIP,
  ROUTER_DYNAMIC_ROUTING_OSPF,
} router_dynamic_routing_mode_t;

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

typedef struct router_context router_context_t;

typedef struct router_socket_emit_argument {
  router_context_t* context;
  size_t interface_index;
} router_socket_emit_argument_t;

typedef struct router_bgp_peer {
  ipv4_address_t address;
  uint16_t local_as;
  uint16_t remote_as;
  size_t interface_index;
  socket_handle_t socket;
  uint32_t last_attempt;
  uint32_t last_received;
  uint32_t last_keepalive;
  bool active;
  bool open_sent;
  bool open_received;
  bool established;
  char outbound_prefix_list[PREFIX_LIST_NAME_LEN];
  char inbound_prefix_list[PREFIX_LIST_NAME_LEN];
} router_bgp_peer_t;

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
  nd_entry_t nd_entries[ROUTER_ND_CAPACITY];
  rarp_entry_t rarp_entries[ROUTER_RARP_CAPACITY];
  prefix_list_rule_t prefix_list_entries[ROUTER_PREFIX_LIST_CAPACITY];
  router_pending_packet_t pending_packets[ROUTER_PENDING_CAPACITY];
  router_acl_rule_t acl_rules[ROUTER_ACL_RULE_CAPACITY];
  interface_table_t interfaces;
  route_table_t routes;
  arp_table_t arp;
  nd_table_t nd;
  rarp_table_t rarp;
  prefix_list_t prefix_lists;
  router_port_t ports[ROUTER_INTERFACE_CAPACITY];
  socket_context_t sockets[ROUTER_INTERFACE_CAPACITY];
  router_socket_emit_argument_t socket_arguments[ROUTER_INTERFACE_CAPACITY];
  socket_handle_t bgp_listeners[ROUTER_INTERFACE_CAPACITY];
  router_bgp_peer_t bgp_peers[ROUTER_BGP_PEER_CAPACITY];
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
  size_t bgp_peer_count;
  router_dynamic_routing_mode_t dynamic_routing;
  uint32_t next_rip_update;
  uint32_t next_ospf_update;
  uint32_t next_ra_update;
  size_t port_count;
  router_acl_action_t acl_defaults[ROUTER_INTERFACE_CAPACITY][2];
  uint64_t acl_default_packets[ROUTER_INTERFACE_CAPACITY][2];
  uint64_t acl_default_bytes[ROUTER_INTERFACE_CAPACITY][2];
  char rip_inbound_prefix_lists[ROUTER_INTERFACE_CAPACITY][PREFIX_LIST_NAME_LEN];
  char rip_outbound_prefix_lists[ROUTER_INTERFACE_CAPACITY][PREFIX_LIST_NAME_LEN];
  mutex_t mutex;
  cmd_app_t commands;
} router_context_t;

static bool router_socket_emit(void* argument, ipv4_address_t destination, uint8_t protocol, const uint8_t* payload, uint16_t payload_length);
static router_bgp_peer_t* find_bgp_peer(router_context_t* context, size_t interface_index, ipv4_address_t address);
