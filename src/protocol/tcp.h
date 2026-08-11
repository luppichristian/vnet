#pragma once

#include <ethernet.h>
#include <ipv4.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

/*
=================================
Transmission Control Protocol
=================================

TCP is an OSI/ISO Layer 4 transport protocol carried inside IPv4 datagrams whose
Protocol field is 6. IPv4 addresses select the hosts and TCP ports select their
application endpoints. TCP normally uses unicast IPv4 delivery; it does not
operate over IPv4 broadcast or multicast because its connection state,
acknowledgements, and congestion control are endpoint-specific.

  Ethernet II data: IPv4 header | TCP header | TCP data | Ethernet padding
                         20 octets    20+ octets

A TCP segment establishes a byte-stream connection with SYN/ACK exchange,
sequence and acknowledgement numbers, retransmission, receive-window flow
control, and checksum protection. This simulator serializes, validates, and
inspects one base 20-octet TCP header plus optional data. It exposes the header
flags, sequence/acknowledgement numbers, and window, but does not maintain a
TCP connection state machine, retransmission queue, options, or congestion
control.

The TCP checksum is mandatory. It covers an IPv4 pseudo-header and the complete
TCP segment, including any options and data, but not the enclosing IPv4 header
or Ethernet fields. This compiler-local simulator shares native multi-octet and
bit-field representation between writer and reader; C bit-field allocation is
therefore implementation-defined and not a portable wire serializer.
*/

#define TCP_IPV4_PROTOCOL 6

#define TCP_FLAG_FIN 0x001u
#define TCP_FLAG_SYN 0x002u
#define TCP_FLAG_RST 0x004u
#define TCP_FLAG_PSH 0x008u
#define TCP_FLAG_ACK 0x010u
#define TCP_FLAG_URG 0x020u
#define TCP_FLAG_ECE 0x040u
#define TCP_FLAG_CWR 0x080u
#define TCP_FLAG_NS  0x100u

#pragma pack(push, 1)

typedef struct tcp_header {
  /* Sending application endpoint. */
  uint16_t src_port;

  /* Receiving application endpoint at the IPv4 destination. */
  uint16_t dst_port;

  /* Sequence number of this segment's first data octet, or SYN/FIN sequence space. */
  uint32_t sequence_number;

  /* Next sequence number expected from the peer when ACK is set. */
  uint32_t acknowledgement_number;

  /* Header size in four-octet words; this simulator writes and accepts 5 (20 octets). */
  uint8_t data_offset : 4;

  /* Reserved bits, required to be zero. */
  uint8_t reserved : 3;

  /* Nonce sum flag used with ECN; retained for header inspection. */
  uint8_t ns : 1;

  /* Connection-control flags. */
  uint8_t fin : 1;
  uint8_t syn : 1;
  uint8_t rst : 1;
  uint8_t psh : 1;
  uint8_t ack : 1;
  uint8_t urg : 1;
  uint8_t ece : 1;
  uint8_t cwr : 1;

  /* Number of data octets the sender is currently willing to receive. */
  uint16_t window_size;

  /* Mandatory one's-complement checksum of the IPv4 pseudo-header and complete segment. */
  uint16_t checksum;

  /* Urgent-data offset when URG is set; otherwise zero in this simulator. */
  uint16_t urgent_pointer;
} tcp_header_t;

#pragma pack(pop)

_Static_assert(sizeof(tcp_header_t) == 20, "TCP base header size must remain fixed");

/* Data needed to write one base-header TCP segment in an IPv4 Ethernet II frame. */
typedef struct tcp_packet_data {
  mac_address_t dst_mac_addr;
  mac_address_t src_mac_addr;
  ipv4_address_t src_addr;
  ipv4_address_t dst_addr;
  uint16_t src_port;
  uint16_t dst_port;
  uint32_t sequence_number;
  uint32_t acknowledgement_number;
  uint16_t flags;
  uint16_t window_size;
  const void* data;
  uint16_t data_length;
} tcp_packet_data_t;

/* Parsed TCP segment whose data pointer refers into the caller-owned IPv4 payload. */
typedef struct tcp_packet_view {
  tcp_header_t header;
  const uint8_t* data;
  uint16_t data_length;
} tcp_packet_view_t;

/* Writes one checksummed, base-header TCP segment inside an IPv4 Ethernet II frame. */
bool tcp_write_ethernet_packet(FILE* destination, const tcp_packet_data_t* packet_data);

/* Validates and decodes one base-header TCP segment using its enclosing IPv4 addresses. */
bool tcp_parse_packet(const uint8_t* bytes, size_t byte_count, ipv4_address_t src_addr, ipv4_address_t dst_addr, tcp_packet_view_t* packet);
