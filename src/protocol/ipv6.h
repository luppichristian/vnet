#pragma once

#include <ethernet.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

/*
====================
IPv6 Datagram Format
====================

An IPv6 packet is the network-layer payload carried by an Ethernet II frame
whose EtherType is 0x86DD:

  Ethernet II data field: IPv6 header | next-header payload | Ethernet padding

OSI/ISO layer: IPv6 is a Layer 3 (network-layer) protocol. It supplies 128-bit
logical addresses, hop-by-hop forwarding, and multicast-driven local-link
control such as Neighbor Discovery.

This simulator models the fixed 40-octet IPv6 base header. It does not yet
implement extension headers or fragmentation; next_header therefore names the
immediate upper-layer payload, such as ICMPv6. Multi-octet fields retain this
compiler-local simulator's native representation, matching the project's other
protocol modules.

IPv6 has no broadcast address. Ethernet delivery therefore uses:

  Unicast:   one receiver's MAC address.
  Multicast: one Ethernet group MAC beginning 33:33, derived from the final
             32 bits of the IPv6 multicast destination.

Common link-local IPv6 multicast groups used here are:

  FF02::1  all nodes on one LAN
  FF02::2  all routers on one LAN
*/

#define IPV6_DEFAULT_HOP_LIMIT 64
#define IPV6_VERSION_FIELD     6u
#define IPV6_NEXT_HEADER_ICMPV6 58

typedef struct ipv6_address {
  uint8_t bytes[16];
} ipv6_address_t;

/* Parses one textual IPv6 address, including :: zero compression. */
bool ipv6_parse_address(const char* text, ipv6_address_t* address);

/* Returns true only when every octet is zero. */
bool ipv6_address_is_unspecified(const ipv6_address_t* address);

/* Returns true for FE80::/10. */
bool ipv6_address_is_link_local(const ipv6_address_t* address);

/* Returns true for addresses whose first octet is 0xFF. */
bool ipv6_address_is_multicast(const ipv6_address_t* address);

/* Returns true when both 128-bit addresses are identical. */
bool ipv6_address_equal(const ipv6_address_t* left, const ipv6_address_t* right);

/* Returns true when address belongs to prefix/prefix_length. */
bool ipv6_address_in_prefix(const ipv6_address_t* address, const ipv6_address_t* prefix, uint8_t prefix_length);

/* Copies one IPv6 address into caller-owned storage. */
void ipv6_address_copy(ipv6_address_t* destination, const ipv6_address_t* source);

/* Writes a compressed lowercase textual IPv6 address. */
void ipv6_address_print(FILE* destination, const ipv6_address_t* address);

/* Derives one modified-EUI-64 interface identifier from an Ethernet MAC address. */
void ipv6_interface_identifier_from_mac(const mac_address_t mac, uint8_t interface_identifier[8]);

/* Derives FE80::/64 plus the modified-EUI-64 interface identifier for mac. */
void ipv6_link_local_from_mac(const mac_address_t mac, ipv6_address_t* address);

/* Builds one SLAAC address by combining prefix/prefix_length with mac's interface identifier. */
bool ipv6_slaac_address_from_prefix(const ipv6_address_t* prefix, uint8_t prefix_length, const mac_address_t mac, ipv6_address_t* address);

/* Builds one simulator-local ULA /64 prefix from an IPv4 connected network. */
void ipv6_ula_prefix_from_ipv4_network(uint32_t network, ipv6_address_t* prefix);

/* Maps one IPv6 multicast address to its Ethernet 33:33 group MAC. */
void ipv6_multicast_mac(const ipv6_address_t* address, mac_address_t mac);

/* Builds one solicited-node multicast address for target. */
void ipv6_solicited_node_multicast(const ipv6_address_t* target, ipv6_address_t* multicast);

/* Maps target's solicited-node multicast group to Ethernet. */
void ipv6_solicited_node_multicast_mac(const ipv6_address_t* target, mac_address_t mac);

#pragma pack(push, 1)

typedef struct ipv6_header {
  uint32_t version_traffic_class_flow_label;
  uint16_t payload_length;
  uint8_t next_header;
  uint8_t hop_limit;
  ipv6_address_t src_addr;
  ipv6_address_t dst_addr;
} ipv6_header_t;

#pragma pack(pop)

typedef struct ipv6_packet_data {
  mac_address_t dst_mac_addr;
  mac_address_t src_mac_addr;
  ipv6_address_t src_addr;
  ipv6_address_t dst_addr;
  uint8_t next_header;
  uint8_t hop_limit;
  const void* data;
  uint16_t data_length;
} ipv6_packet_data_t;

typedef struct ipv6_packet_view {
  ipv6_header_t header;
  const uint8_t* payload;
  uint16_t payload_length;
} ipv6_packet_view_t;

/* Writes one Ethernet II frame carrying one base-header IPv6 packet. */
bool ipv6_write_ethernet_packet(FILE* destination, const ipv6_packet_data_t* packet_data);

/* Validates and decodes one base-header IPv6 packet from a byte buffer. */
bool ipv6_parse_packet(const uint8_t* bytes, size_t byte_count, ipv6_packet_view_t* packet);
