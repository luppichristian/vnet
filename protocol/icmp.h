#pragma once

#include <stddef.h>
#include <stdint.h>

/*
==================================
Internet Control Message Protocol
==================================

ICMP is carried directly inside an IPv4 datagram: the IPv4 Protocol field is
1, rather than TCP or UDP. Routers and hosts use ICMP for network control and
error reporting, including destination unreachable, time exceeded, redirect,
and echo messages. It is not an Ethernet protocol, so Ethernet II still uses
EtherType 0x0800 for the enclosing IPv4 packet.

This header models an ICMP Echo message, used by ping-like reachability tests:

  Ethernet II data: IPv4 header | ICMP Echo header | optional ICMP data |
                      20 octets       8 octets

An echo request uses type 8 and asks a destination to return an echo reply with
type 0. Echo messages use code 0. Identifier and sequence number let a sender
match replies to its own requests and distinguish individual requests.

The ICMP checksum protects the entire ICMP message, including optional data. It
does not include the enclosing IPv4 header or Ethernet fields. This simulator
keeps native multi-octet values shared by its writer and reader, as with the
other protocol headers.
*/

#define ICMP_IPV4_PROTOCOL     1
#define ICMP_TYPE_ECHO_REPLY   0
#define ICMP_TYPE_ECHO_REQUEST 8
#define ICMP_CODE_ECHO         0

#pragma pack(push, 1)

typedef struct icmp_echo_header {
  /* Echo request is 8; echo reply is 0. Other ICMP message types use other layouts. */
  uint8_t type;

  /* Echo messages use zero; other message types further classify their meaning here. */
  uint8_t code;

  /* One's-complement checksum of this header plus any following ICMP data. */
  uint16_t checksum;

  /* Sender-chosen value used to associate an echo reply with its request. */
  uint16_t identifier;

  /* Incremented by the sender for successive echo requests using one identifier. */
  uint16_t sequence_number;
} icmp_echo_header_t;

#pragma pack(pop)

/*
The sender clears checksum, computes this value over the entire ICMP message,
and stores it in checksum. A receiver recomputes it over the received message;
a valid message returns zero.
*/
static inline uint16_t icmp_checksum(const void* data, size_t data_size) {
  const uint8_t* bytes = (const uint8_t*)data;
  uint32_t sum = 0;

  for (size_t i = 0; i < data_size; i += 2) {
    const uint16_t word = bytes[i] | (uint16_t)(i + 1 < data_size ? bytes[i + 1] << 8 : 0);
    sum += word;
    sum = (sum & 0xFFFFu) + (sum >> 16);
  }

  return (uint16_t)~sum;
}
