#pragma once

#include <stddef.h>
#include <stdint.h>

/*
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
its writer and reader instead of adding an endianness layer.
*/
#define IPV4_VERSION_IHL         0x45
#define IPV4_DEFAULT_TTL         64
#define IPV4_PROTOCOL_TEST       253
#define IPV4_DONT_FRAGMENT       0x4000
#define IPV4_ADDRESS(a, b, c, d) ((uint32_t)(a) | ((uint32_t)(b) << 8) | ((uint32_t)(c) << 16) | ((uint32_t)(d) << 24))

typedef uint32_t ipv4_address_t;

#pragma pack(push, 1)

typedef struct ipv4_header {
  uint8_t version_ihl;                /* High nibble: version 4. Low nibble: header length in four-octet words. */
  uint8_t dscp_ecn;                   /* Service class and congestion notification; zero in this simulation. */
  uint16_t total_length;              /* Header plus IPv4 payload, in octets. */
  uint16_t identification;            /* Sender-selected datagram identifier for fragment reassembly. */
  uint16_t flags_fragment_offset;     /* DF/MF flags and fragment position; DF is set and fragmentation is unsupported. */
  uint8_t ttl;                        /* Hop limit, decremented by every router. */
  uint8_t protocol;                   /* Identifier for the encapsulated upper-layer protocol. */
  uint16_t header_checksum;           /* One's-complement checksum of this header only, with this field initially zero. */
  ipv4_address_t source_address;      /* Sender IPv4 address. */
  ipv4_address_t destination_address; /* Intended receiver IPv4 address. */
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
