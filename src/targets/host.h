#pragma once

/*
Interactive Ethernet host attached to one append-only VNet traffic file.
OSI/ISO layer: Layer 2 endpoint; optional IPv4 configuration supplies Layer 3 identity.
*/

#include <arp.h>
#include <arp_table.h>
#include <cmd_app.h>
#include <dhcp.h>
#include <dns.h>
#include <ethernet.h>
#include <futils.h>
#include <icmp.h>
#include <ipv4.h>
#include <mutex.h>
#include <rarp.h>
#include <socket.h>

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tcp.h>
#include <thread.h>
#include <udp.h>
#include <vnet.h>
#include <vnet_peer_table.h>

#define HOST_DEVICE_CAPACITY  64
#define HOST_ARP_CAPACITY     64
#define HOST_BUFFER_SIZE      8192
#define HOST_PENDING_DATA_MAX (ETHERNET_MAX_DATA_LEN - sizeof(ipv4_header_t) - sizeof(tcp_header_t))
#define SLEEP_INTERVAL_MS     5

typedef enum host_pending_type {
  HOST_PENDING_NONE,
  HOST_PENDING_PING,
  HOST_PENDING_UDP,
  HOST_PENDING_TCP,
  HOST_PENDING_DNS,
} host_pending_type_t;

typedef struct host_pending_packet {
  ipv4_address_t destination;
  ipv4_address_t next_hop;
  host_pending_type_t type;
  uint16_t src_port;
  uint16_t dst_port;
  uint32_t sequence_number;
  uint32_t acknowledgement_number;
  uint16_t flags;
  uint16_t window_size;
  uint8_t data[HOST_PENDING_DATA_MAX];
  uint16_t data_length;
  bool active;
} host_pending_packet_t;

typedef struct host_context {
  const char* path;
  mac_address_t mac;
  ipv4_address_t ip4;
  ipv4_address_t mask;
  ipv4_address_t gateway;
  bool has_ip4;
  bool has_gateway;
  ipv4_address_t dns_server;
  ipv4_address_t dhcp_server;
  bool has_dns_server;
  bool has_dhcp_server;
  uint16_t next_transaction_id;
  uint16_t dns_transaction_id;
  uint16_t dhcp_transaction_id;
  uint8_t dns_cname_hops;
  char dns_query_name[DNS_NAME_MAX + 1];
  host_pending_packet_t dns_pending_packet;
  uint16_t ping_sequence;
  FILE* source;
  mutex_t mutex;
  cmd_app_t commands;
  vnet_peer_entry_t device_entries[HOST_DEVICE_CAPACITY];
  vnet_peer_table_t devices;
  arp_entry_t arp_entries[HOST_ARP_CAPACITY];
  arp_table_t arp;
  socket_context_t sockets;
  host_pending_packet_t pending_packet;
} host_context_t;

typedef arp_entry_t host_arp_entry_t;
