#pragma once

#include <stddef.h>
#include <stdint.h>

/*
====================
IPv4 Datagram Format
====================

An IPv4 datagram is the network-layer payload carried by an Ethernet II frame
whose EtherType is 0x0800. It consists of a header followed by the bytes of its
transport-layer payload:

  Ethernet II data field: IPv4 header | IPv4 payload | Ethernet padding

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

/*
IPv4 protects only its header with a one's-complement checksum. A sender sets
header_checksum to zero, calculates this function over the complete header,
then stores the returned value in header_checksum. A receiver calculates over
the complete received header, including header_checksum; a valid header returns
zero. Payload integrity is handled by upper protocols and Ethernet FCS covers
the complete local frame.
*/
static inline uint16_t ipv4_checksum(const void* data, size_t data_size) {
  const uint8_t* bytes = (const uint8_t*)data;
  uint32_t sum = 0;

  for (size_t i = 0; i < data_size; i += 2) {
    const uint16_t word = bytes[i] | (uint16_t)(i + 1 < data_size ? bytes[i + 1] << 8 : 0);
    sum += word;
    sum = (sum & 0xFFFFu) + (sum >> 16);
  }

  return (uint16_t)~sum;
}
