#pragma once

#include <ipv4.h>

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/*
=========================================
Network Address Translation / Port Mapping
=========================================

NAT is a stateful Layer 3/4 middlebox function, not an on-the-wire packet
format. It operates after IPv4 has been decoded and before the router writes a
forwarded IPv4 packet. Source NAT replaces a private inside IPv4 address with
an outside address. Network Address and Port Translation (NAPT) additionally
allocates an outside UDP or TCP port, allowing multiple inside endpoints to
share one outside address.

  Inside packet:  IPv4 inside address:inside port -> remote address:remote port
  Outside packet: IPv4 outside address:outside port -> remote address:remote port

A reply is admitted only when its transport protocol, translated destination
port, remote IPv4 address, and remote port match an active mapping. NAT then
restores the inside destination address and port before normal route lookup.

This module owns mapping selection and transport reserialization. The router
owns interface policy, ARP resolution, packet queues, and IPv4 forwarding. NAT
supports UDP and base-header TCP only because those are the transport packet
formats modeled by this simulator. It does not model ICMP translation, NAT64,
fragment reassembly, timers, hairpinning, port forwarding, or protocol helpers.
*/

#define NAT_EPHEMERAL_PORT_MIN 49152

/* One stateful NAPT binding between an inside endpoint and one remote endpoint. */
typedef struct nat_entry {
  ipv4_address_t inside_address;
  ipv4_address_t remote_address;
  uint16_t inside_port;
  uint16_t outside_port;
  uint16_t remote_port;
  uint8_t protocol;
  bool active;
} nat_entry_t;

/* Caller-owned storage for a stateful NAT binding table. */
typedef struct nat_table {
  nat_entry_t* entries;
  size_t capacity;
  uint16_t next_port;
} nat_table_t;

/* Binds caller-owned entries to an empty NAT table and begins allocation at first_port. */
void nat_table_init(nat_table_t* table, nat_entry_t* entries, size_t capacity, uint16_t first_port);

/* Finds an existing inside-to-outside binding for one transport flow. */
nat_entry_t* nat_table_find_outbound(nat_table_t* table, uint8_t protocol, ipv4_address_t inside_address, uint16_t inside_port, ipv4_address_t remote_address, uint16_t remote_port);

/* Finds an outside-to-inside binding for one reply flow. */
nat_entry_t* nat_table_find_inbound(nat_table_t* table, uint8_t protocol, uint16_t outside_port, ipv4_address_t remote_address, uint16_t remote_port);

/* Reuses or allocates a binding; returns NULL when the table has no free entry. */
nat_entry_t* nat_table_open(nat_table_t* table, uint8_t protocol, ipv4_address_t inside_address, uint16_t inside_port, ipv4_address_t remote_address, uint16_t remote_port);

/* Rewrites a UDP or base-header TCP payload and regenerates its transport checksum. */
bool nat_rewrite_transport(const ipv4_packet_view_t* packet, ipv4_address_t source_address, ipv4_address_t destination_address, uint16_t source_port, uint16_t destination_port, uint8_t* payload, size_t capacity, uint16_t* payload_length);
