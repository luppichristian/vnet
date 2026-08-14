#pragma once

#include <icmpv6.h>

/*
==============================
Neighbor Discovery for IPv6
==============================

Neighbor Discovery uses ICMPv6 for local-link control in IPv6. This module
models the four core messages needed for this simulator's dual-stack targets:

  Router Solicitation     (type 133)
  Router Advertisement    (type 134)
  Neighbor Solicitation   (type 135)
  Neighbor Advertisement  (type 136)

It also models the two link-layer address options and the Prefix Information
option used by SLAAC. All messages here are carried directly inside IPv6 and
are normally sent with hop limit 255 so receivers can trust they originated on
the local link.
*/

#define NDP_HOP_LIMIT_REQUIRED       255
#define NDP_OPTION_SOURCE_LINK_LAYER 1
#define NDP_OPTION_TARGET_LINK_LAYER 2
#define NDP_OPTION_PREFIX_INFORMATION 3
#define NDP_ROUTER_FLAG_MANAGED      0x80
#define NDP_ROUTER_FLAG_OTHER        0x40
#define NDP_ROUTER_FLAG_ON_LINK      0x80
#define NDP_ROUTER_FLAG_AUTONOMOUS   0x40
#define NDP_NEIGHBOR_FLAG_ROUTER     0x80000000u
#define NDP_NEIGHBOR_FLAG_SOLICITED  0x40000000u
#define NDP_NEIGHBOR_FLAG_OVERRIDE   0x20000000u

#pragma pack(push, 1)

typedef struct ndp_option_header {
  uint8_t type;
  uint8_t length;
} ndp_option_header_t;

typedef struct ndp_router_solicitation_wire {
  icmpv6_header_t header;
  uint32_t reserved;
} ndp_router_solicitation_wire_t;

typedef struct ndp_router_advertisement_wire {
  icmpv6_header_t header;
  uint8_t current_hop_limit;
  uint8_t flags;
  uint16_t router_lifetime;
  uint32_t reachable_time;
  uint32_t retrans_timer;
} ndp_router_advertisement_wire_t;

typedef struct ndp_neighbor_solicitation_wire {
  icmpv6_header_t header;
  uint32_t reserved;
  ipv6_address_t target_address;
} ndp_neighbor_solicitation_wire_t;

typedef struct ndp_neighbor_advertisement_wire {
  icmpv6_header_t header;
  uint32_t flags;
  ipv6_address_t target_address;
} ndp_neighbor_advertisement_wire_t;

typedef struct ndp_prefix_information_wire {
  ndp_option_header_t option;
  uint8_t prefix_length;
  uint8_t flags;
  uint32_t valid_lifetime;
  uint32_t preferred_lifetime;
  uint32_t reserved;
  ipv6_address_t prefix;
} ndp_prefix_information_wire_t;

#pragma pack(pop)

typedef struct ndp_router_solicitation_data {
  mac_address_t dst_mac_addr;
  mac_address_t src_mac_addr;
  ipv6_address_t src_addr;
  ipv6_address_t dst_addr;
  bool include_source_link_layer;
} ndp_router_solicitation_data_t;

typedef struct ndp_router_advertisement_data {
  mac_address_t dst_mac_addr;
  mac_address_t src_mac_addr;
  ipv6_address_t src_addr;
  ipv6_address_t dst_addr;
  uint8_t current_hop_limit;
  uint8_t flags;
  uint16_t router_lifetime;
  uint32_t reachable_time;
  uint32_t retrans_timer;
  bool include_source_link_layer;
  bool include_prefix_information;
  ipv6_address_t prefix;
  uint8_t prefix_length;
  bool on_link;
  bool autonomous;
  uint32_t valid_lifetime;
  uint32_t preferred_lifetime;
} ndp_router_advertisement_data_t;

typedef struct ndp_neighbor_solicitation_data {
  mac_address_t dst_mac_addr;
  mac_address_t src_mac_addr;
  ipv6_address_t src_addr;
  ipv6_address_t dst_addr;
  ipv6_address_t target_address;
  bool include_source_link_layer;
} ndp_neighbor_solicitation_data_t;

typedef struct ndp_neighbor_advertisement_data {
  mac_address_t dst_mac_addr;
  mac_address_t src_mac_addr;
  ipv6_address_t src_addr;
  ipv6_address_t dst_addr;
  ipv6_address_t target_address;
  uint32_t flags;
  bool include_target_link_layer;
} ndp_neighbor_advertisement_data_t;

typedef struct ndp_router_solicitation {
  bool has_source_link_layer;
  mac_address_t source_link_layer;
} ndp_router_solicitation_t;

typedef struct ndp_router_advertisement {
  uint8_t current_hop_limit;
  uint8_t flags;
  uint16_t router_lifetime;
  uint32_t reachable_time;
  uint32_t retrans_timer;
  bool has_source_link_layer;
  mac_address_t source_link_layer;
  bool has_prefix_information;
  ipv6_address_t prefix;
  uint8_t prefix_length;
  bool on_link;
  bool autonomous;
  uint32_t valid_lifetime;
  uint32_t preferred_lifetime;
} ndp_router_advertisement_t;

typedef struct ndp_neighbor_solicitation {
  ipv6_address_t target_address;
  bool has_source_link_layer;
  mac_address_t source_link_layer;
} ndp_neighbor_solicitation_t;

typedef struct ndp_neighbor_advertisement {
  uint32_t flags;
  ipv6_address_t target_address;
  bool has_target_link_layer;
  mac_address_t target_link_layer;
} ndp_neighbor_advertisement_t;

/* Writes one ICMPv6 Router Solicitation in an IPv6 Ethernet II frame. */
bool ndp_write_router_solicitation(FILE* destination, const ndp_router_solicitation_data_t* request);

/* Writes one ICMPv6 Router Advertisement in an IPv6 Ethernet II frame. */
bool ndp_write_router_advertisement(FILE* destination, const ndp_router_advertisement_data_t* advertisement);

/* Writes one ICMPv6 Neighbor Solicitation in an IPv6 Ethernet II frame. */
bool ndp_write_neighbor_solicitation(FILE* destination, const ndp_neighbor_solicitation_data_t* solicitation);

/* Writes one ICMPv6 Neighbor Advertisement in an IPv6 Ethernet II frame. */
bool ndp_write_neighbor_advertisement(FILE* destination, const ndp_neighbor_advertisement_data_t* advertisement);

/* Validates and decodes one Router Solicitation. */
bool ndp_parse_router_solicitation(const uint8_t* bytes, size_t byte_count, const ipv6_address_t* source, const ipv6_address_t* destination, ndp_router_solicitation_t* solicitation);

/* Validates and decodes one Router Advertisement. */
bool ndp_parse_router_advertisement(const uint8_t* bytes, size_t byte_count, const ipv6_address_t* source, const ipv6_address_t* destination, ndp_router_advertisement_t* advertisement);

/* Validates and decodes one Neighbor Solicitation. */
bool ndp_parse_neighbor_solicitation(const uint8_t* bytes, size_t byte_count, const ipv6_address_t* source, const ipv6_address_t* destination, ndp_neighbor_solicitation_t* solicitation);

/* Validates and decodes one Neighbor Advertisement. */
bool ndp_parse_neighbor_advertisement(const uint8_t* bytes, size_t byte_count, const ipv6_address_t* source, const ipv6_address_t* destination, ndp_neighbor_advertisement_t* advertisement);
