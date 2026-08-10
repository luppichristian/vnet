#pragma once

#include <ethernet.h>
#include <ipv4.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

/*
=========================
User Datagram Protocol
=========================

UDP is an OSI/ISO Layer 4 transport protocol carried inside IPv4 datagrams whose
Protocol field is 17. It provides port-based multiplexing and a checksum, but
no connection setup, sequencing, acknowledgement, retransmission, or flow
control. One UDP datagram is delivered independently of the others:

  Ethernet II data: IPv4 header | UDP header | UDP data | Ethernet padding
                         20 octets     8 octets

IPv4 selects the receiving host; UDP source and destination ports select the
sending and receiving application endpoints on those hosts. UDP uses the
unicast, broadcast, or multicast delivery mode of its enclosing IPv4 packet;
it does not define Layer 2 delivery itself. The IPv4 and Ethernet headers carry
those respective addresses.

The UDP length includes its eight-octet header and UDP data, but excludes the
IPv4 header and Ethernet padding. The optional IPv4 UDP checksum covers an
IPv4 pseudo-header plus the complete UDP datagram. This simulator writes it for
every packet; a received checksum of zero is accepted because IPv4 permits it
to mean that the sender omitted checksum validation.

Like the rest of this compiler-local simulation, multi-octet values use the
shared native representation instead of portable network-byte-order encoding.
*/

#define UDP_IPV4_PROTOCOL 17

#pragma pack(push, 1)

typedef struct udp_header {
  /* Sending application endpoint; zero means no source port. */
  uint16_t src_port;

  /* Receiving application endpoint at the IPv4 destination. */
  uint16_t dst_port;

  /* Header plus UDP data, in octets; it excludes IPv4 and Ethernet fields. */
  uint16_t length;

  /* One's-complement checksum of the IPv4 pseudo-header and this datagram; zero may mean omitted under IPv4. */
  uint16_t checksum;
} udp_header_t;

#pragma pack(pop)

_Static_assert(sizeof(udp_header_t) == 8, "UDP header size must remain fixed");

/* Data needed to write one UDP datagram in an IPv4 Ethernet II frame. */
typedef struct udp_packet_data {
  mac_address_t dst_mac_addr;
  mac_address_t src_mac_addr;
  ipv4_address_t src_addr;
  ipv4_address_t dst_addr;
  uint16_t src_port;
  uint16_t dst_port;
  const void* data;
  uint16_t data_length;
} udp_packet_data_t;

/* Parsed UDP datagram whose data pointer refers into the caller-owned IPv4 payload. */
typedef struct udp_packet_view {
  udp_header_t header;
  const uint8_t* data;
  uint16_t data_length;
} udp_packet_view_t;

/* Writes one checksummed UDP datagram inside an IPv4 Ethernet II frame. */
bool udp_write_ethernet_packet(FILE* destination, const udp_packet_data_t* packet_data);

/* Validates and decodes one UDP datagram using its enclosing IPv4 source and destination addresses. */
bool udp_parse_packet(const uint8_t* bytes, size_t byte_count, ipv4_address_t src_addr, ipv4_address_t dst_addr, udp_packet_view_t* packet);
