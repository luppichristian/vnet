#pragma once

#include <ethernet.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

/*
====================
IPv4 Datagram Format
====================

An IPv4 datagram is the network-layer payload carried by an Ethernet II frame
whose EtherType is 0x0800. It consists of a header followed by the bytes of its
transport-layer payload:

  Ethernet II data field: IPv4 header | IPv4 payload | Ethernet padding

OSI/ISO layer: IPv4 is a Layer 3 (network-layer) protocol. It supplies logical
addresses and enables routers to forward packets between different networks.

IPv4 delivery modes are selected by the destination IPv4 address:

  Unicast:   one host address; routers forward it towards that one destination.
  Broadcast: every host on one IPv4 network. 255.255.255.255 is the limited
             broadcast address; a subnet's all-host-bits-one address is a
             directed broadcast. Routers do not forward limited broadcasts.
  Multicast: 224.0.0.0 through 239.255.255.255 identify receiver groups rather
             than one host. Hosts join a group to receive its packets.

On Ethernet, an IPv4 unicast normally uses a unicast MAC address; IPv4
broadcast uses the Ethernet broadcast MAC address; IPv4 multicast maps to an
Ethernet multicast MAC address.

The header begins with a version and a header length. IPv4 permits optional
header fields, so IHL is measured in four-octet words rather than bytes. This
first simulator version deliberately supports only the ordinary 20-octet base
header: IPv4 version 4, IHL 5, no options, and no fragmentation.

The IPv4 total-length field includes both the IPv4 header and its payload. It
does not include Ethernet's preamble, MAC header, FCS, or any Ethernet padding.
Therefore a receiver uses total_length to distinguish an IPv4 payload from
zero-padding that Ethernet added to reach its 46-octet minimum data field.

Real IPv4 transmits multi-octet fields in network byte order. As with the
Ethernet model, this file simulation keeps the native representation shared by
its writer and reader instead of adding an endianness layer. C bit-field layout
is implementation-defined, so this simulator requires its writer and reader to
use the same compiler and platform.
*/
#define IPV4_DEFAULT_TTL   64
#define IPV4_PROTOCOL_TEST 253

typedef uint32_t ipv4_address_t;

/* Construct an ipv4 */
#define IPV4_ADDRESS(a, b, c, d) \
  ((uint32_t)(a) | ((uint32_t)(b) << 8) | ((uint32_t)(c) << 16) | ((uint32_t)(d) << 24))

/* Parses a dotted-decimal IPv4 address into this simulator's native address representation. */
bool ipv4_parse_address(const char* text, ipv4_address_t* address);

/* Returns true when an IPv4 subnet mask has contiguous leading one bits. */
bool ipv4_mask_is_contiguous(ipv4_address_t mask);

/* Returns true when two IPv4 addresses belong to the same subnet under mask. */
bool ipv4_addresses_share_subnet(ipv4_address_t first, ipv4_address_t second, ipv4_address_t mask);

/* Writes a dotted-decimal IPv4 address to the caller-owned stream. */
void ipv4_address_print(FILE* destination, ipv4_address_t address);

#pragma pack(push, 1)

typedef struct ipv4_header {
  /* IPv4 is the only version implemented by this simulator. */
  uint8_t version : 4; /* IPv4 version: 4. */

  /* IHL counts 32-bit words, so 5 means this fixed header occupies 20 octets. */
  uint8_t ihl : 4; /* Header length in four-octet words: 5 for this base header. */

  /*
  Differentiated Services Code Point selects a per-hop forwarding treatment.
  Routers may use it for quality-of-service policies such as prioritising
  latency-sensitive traffic or reserving bandwidth. Zero is default best effort.
  */
  uint8_t dscp : 6;

  /*
  Explicit Congestion Notification lets routers signal congestion by marking a
  packet instead of dropping it. A transport protocol such as TCP can then slow
  down. Zero means this simulator's packets do not negotiate ECN.
  */
  uint8_t ecn : 2;

  /* Header plus IPv4 payload, in octets; it excludes Ethernet fields and padding. */
  uint16_t total_length; /* Header plus IPv4 payload, in octets. */

  /*
  All fragments from the same original datagram share this sender-chosen value.
  A receiver uses it with source, destination, and protocol to reassemble them.
  */
  uint16_t fragment_id; /* Sender-selected datagram identifier for fragment reassembly. */

  /* Reserved for future use and required to remain zero. */
  uint16_t reserved : 1;

  /* When set, routers must drop rather than fragment an oversized datagram. */
  uint16_t dont_fragment : 1;

  /* Set on every fragment except the last; always zero while fragmentation is unsupported. */
  uint16_t more_fragments : 1;

  /* Fragment position in units of eight octets; zero for an unfragmented datagram. */
  uint16_t fragment_offset : 13;

  /* Limits how many routers may forward this packet and prevents routing loops. */
  uint8_t ttl; /* Hop limit, decremented by every router. */

  /* Identifies the next-layer payload, for example ICMP, TCP, UDP, or this test protocol. */
  uint8_t protocol; /* Identifier for the encapsulated upper-layer protocol. */

  /* Recomputed whenever a router decrements TTL; it protects only this IPv4 header. */
  uint16_t header_checksum; /* One's-complement checksum of this header only, with this field initially zero. */

  /* The logical network-layer sender; routers normally leave this unchanged. */
  ipv4_address_t src_addr; /* Sender IPv4 address. */

  /* The final intended host; routers use it to choose the next hop. */
  ipv4_address_t dst_addr; /* Intended receiver IPv4 address. */
} ipv4_header_t;

#pragma pack(pop)

/* Data needed to write one IPv4 datagram inside an Ethernet II frame. */
typedef struct ipv4_packet_data {
  mac_address_t dst_mac_addr;
  mac_address_t src_mac_addr;
  ipv4_address_t src_addr;
  ipv4_address_t dst_addr;
  uint8_t protocol;
  const void* data;
  uint16_t data_length;
} ipv4_packet_data_t;

/* Parsed IPv4 packet whose payload pointer refers into the caller-owned byte buffer. */
typedef struct ipv4_packet_view {
  ipv4_header_t header;
  const uint8_t* payload;
  uint16_t payload_length;
} ipv4_packet_view_t;

/* Writes an Ethernet II frame carrying one base-header IPv4 datagram. */
bool ipv4_write_ethernet_packet(FILE* destination, const ipv4_packet_data_t* packet_data);

/* Validates and decodes one supported base-header IPv4 packet from a byte buffer. */
bool ipv4_parse_packet(const uint8_t* bytes, size_t byte_count, ipv4_packet_view_t* packet);
