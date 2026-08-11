#pragma once

#include <ipv4.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/*
======================================
Open Shortest Path First, Version 2
======================================
OSPFv2 is a link-state interior gateway protocol carried directly inside IPv4:
its IPv4 Protocol field is 89, not UDP or TCP. On broadcast Ethernet networks,
routers normally send Hello and Link State Update traffic to AllSPFRouters,
224.0.0.5, whose Ethernet multicast address is 01:00:5E:00:00:05.

This module models the OSPF packet header and a bounded educational Router-LSA
advertisement. Each advertisement states the router's directly attached IPv4
prefixes and per-link costs. The router target uses received advertisements to
install one-hop OSPF routes.

Full OSPF adjacency state, designated-router election, reliable flooding, a
persistent LSDB, and Dijkstra SPF are intentionally omitted: VNet media are
explicit local append-only links, and this router needs only direct-neighbor
prefix exchange to model its configured virtual topology. Add those mechanisms
only if the virtual system later gains multi-hop link-state topology semantics.

OSI/ISO layer: OSPF is a Layer 3 routing control-plane protocol. It is carried
inside IPv4 but does not forward user packets itself. Forwarding continues to
use the router's selected egress interface and ARP-resolved next hop.

As with this compiler-local simulator's other protocol modules, multi-octet
values use a shared native representation. The structures preserve OSPF's
semantic fields and bounded message sequence, rather than portable wire order.
*/

#define OSPF_IPV4_PROTOCOL 89
#define OSPF_VERSION 2
#define OSPF_PACKET_TYPE_LINK_STATE_UPDATE 4
#define OSPF_AREA_BACKBONE 0
#define OSPF_ALL_SPF_ROUTERS IPV4_ADDRESS(224, 0, 0, 5)
#define OSPF_MAX_LINKS_PER_PACKET 32

#pragma pack(push, 1)

typedef struct ospf_header {
  uint8_t version;       /* OSPF version; this module accepts version 2. */
  uint8_t packet_type;   /* Link State Update is type 4. */
  uint16_t packet_length; /* Complete OSPF packet including this header. */
  ipv4_address_t router_id; /* Stable IPv4-form router identifier. */
  uint32_t area_id;      /* OSPF area; this model uses only backbone area zero. */
  uint16_t checksum;     /* One's-complement checksum of the complete modeled packet. */
  uint16_t authentication_type; /* Zero: no authentication in this model. */
  uint8_t authentication[8]; /* Authentication data; required to remain zero here. */
} ospf_header_t;

typedef struct ospf_router_link {
  ipv4_address_t network; /* Directly attached CIDR network; host bits are zero. */
  ipv4_address_t mask;    /* Contiguous subnet mask for network. */
  uint16_t metric;        /* Positive interface cost advertised by this router. */
  uint16_t reserved;      /* Required to remain zero. */
} ospf_router_link_t;

#pragma pack(pop)

_Static_assert(sizeof(ospf_header_t) == 24, "OSPF header size must remain fixed");
_Static_assert(sizeof(ospf_router_link_t) == 12, "OSPF router link size must remain fixed");

typedef struct ospf_packet_view {
  ospf_header_t header;
  const ospf_router_link_t* links;
  size_t link_count;
} ospf_packet_view_t;

/* Returns true when address is OSPF's AllSPFRouters multicast group. */
bool ospf_is_all_spf_routers(ipv4_address_t address);

/* Writes one validated Router-LSA-like Link State Update advertisement. */
bool ospf_write_router_update(ipv4_address_t router_id, const ospf_router_link_t* links, size_t link_count, uint8_t* bytes, size_t capacity, size_t* byte_count);

/* Validates and decodes one Router-LSA-like Link State Update advertisement. */
bool ospf_parse_router_update(const uint8_t* bytes, size_t byte_count, ospf_packet_view_t* packet);
