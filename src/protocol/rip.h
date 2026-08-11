#pragma once

#include <ipv4.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/*
========================================
Routing Information Protocol, Version 2
========================================
RIP v2 is an IPv4 interior gateway protocol that lets neighboring routers
exchange reachable IPv4 prefixes. It is carried in UDP: source and destination
port 520, IPv4 Protocol 17. Periodic Response messages advertise routes, while
Request messages ask a neighbor for its current routing information.

OSI/ISO layer: RIP is a routing control-plane protocol. Its messages use the
Layer 4 UDP transport, but its purpose is to populate the Layer 3 forwarding
information used by routers. RIP messages never replace the forwarding plane:
a router still selects an egress interface and resolves its next hop through
ARP before forwarding ordinary IPv4 traffic.

RIP v2 normally multicasts updates to IPv4 group 224.0.0.9. On Ethernet that
group maps to 01:00:5E:00:00:09. The group is link-local: a router receives it
on one interface and does not forward that Ethernet or IPv4 multicast packet to
another interface.

A Route Table Entry contains an IPv4 network prefix, its subnet mask, an
optional next hop, and a hop-count metric. Metric 1 means directly reachable;
metrics increase once at every receiving router. Metric 16 means infinity and
withdraws a route. RIP v2 supports CIDR through the explicit subnet mask field.

This compiler-local simulator shares its native multi-octet representation
between sender and receiver, as its other protocol modules do. These structures
therefore model RIP's semantic fields and fixed sizes, not a portable Internet
wire serializer.
*/

#define RIP_UDP_PORT 520
#define RIP_VERSION 2
#define RIP_COMMAND_REQUEST 1
#define RIP_COMMAND_RESPONSE 2
#define RIP_ADDRESS_FAMILY_IPV4 2
#define RIP_METRIC_MIN 1
#define RIP_METRIC_INFINITY 16
#define RIP_MULTICAST_ADDRESS IPV4_ADDRESS(224, 0, 0, 9)
#define RIP_MAX_ENTRIES_PER_PACKET 25

#pragma pack(push, 1)

typedef struct rip_header {
  /* Request asks a peer for routes; Response carries one or more route entries. */
  uint8_t command;

  /* This module accepts and writes RIP version 2 only. */
  uint8_t version;

  /* Required to be zero in RIP v2. */
  uint16_t zero;
} rip_header_t;

typedef struct rip_route_entry {
  /* IPv4 route entries use address family identifier 2. */
  uint16_t address_family;

  /* Optional routing-domain tag; this simulator writes and accepts zero. */
  uint16_t route_tag;

  /* CIDR destination network. Host bits must be zero under subnet_mask. */
  ipv4_address_t destination;

  /* Contiguous IPv4 subnet mask for destination. */
  ipv4_address_t subnet_mask;

  /* Optional next hop; zero directs the receiver to use the advertising router. */
  ipv4_address_t next_hop;

  /* Hop count from 1 through 16, where 16 means unreachable. */
  uint32_t metric;
} rip_route_entry_t;

#pragma pack(pop)

_Static_assert(sizeof(rip_header_t) == 4, "RIP header size must remain fixed");
_Static_assert(sizeof(rip_route_entry_t) == 20, "RIP route entry size must remain fixed");

/* Parsed RIP packet whose entries refer into the caller-owned packet buffer. */
typedef struct rip_packet_view {
  rip_header_t header;
  const rip_route_entry_t* entries;
  size_t entry_count;
} rip_packet_view_t;

/* Returns true when an IPv4 Ethernet destination is RIP's multicast group. */
bool rip_is_multicast_address(ipv4_address_t address);

/* Writes one RIP v2 Request or Response payload containing up to 25 valid entries. */
bool rip_write_packet(uint8_t command, const rip_route_entry_t* entries, size_t entry_count, uint8_t* bytes, size_t capacity, size_t* byte_count);

/* Validates and decodes one RIP v2 Request or Response payload. */
bool rip_parse_packet(const uint8_t* bytes, size_t byte_count, rip_packet_view_t* packet);
