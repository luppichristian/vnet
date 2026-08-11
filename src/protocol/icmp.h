#pragma once

#include <ethernet.h>
#include <ipv4.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

/*
==================================
Internet Control Message Protocol
==================================

ICMP is carried directly inside an IPv4 datagram: the IPv4 Protocol field is
1, rather than TCP or UDP. Routers and hosts use ICMP for network control and
error reporting, including destination unreachable, time exceeded, redirect,
and echo messages. It is not an Ethernet protocol, so Ethernet II still uses
EtherType 0x0800 for the enclosing IPv4 packet.

OSI/ISO layer: ICMP is a Layer 3 (network-layer) control protocol carried by
IPv4. It reports conditions encountered while forwarding IPv4 packets and is
not a transport-layer protocol such as TCP or UDP.

ICMP follows the delivery mode of its enclosing IPv4 packet:

  Unicast:   the ordinary case, including this simulator's echo request to one
             destination.
  Broadcast: an ICMP Echo Request may be addressed to a broadcast address, but
             hosts must not send Echo Replies to broadcast requests because that
             could amplify traffic.
  Multicast: ICMP can be sent to an IPv4 multicast group, but ICMP error
             messages are not generated in response to multicast traffic; this
             also avoids unwanted reply/error amplification.

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

/* Data needed to write one ICMP Echo Request inside an IPv4 Ethernet II frame. */
typedef struct icmp_echo_request_data {
  mac_address_t dst_mac_addr;
  mac_address_t src_mac_addr;
  ipv4_address_t src_addr;
  ipv4_address_t dst_addr;
  uint16_t identifier;
  uint16_t sequence_number;
  const void* data;
  uint16_t data_length;
} icmp_echo_request_data_t;

/* Writes one ICMP Echo Request in an IPv4 Ethernet II frame. */
bool icmp_write_ethernet_echo_request(FILE* destination, const icmp_echo_request_data_t* request_data);

/* Writes one ICMP Echo Reply in an IPv4 Ethernet II frame. */
bool icmp_write_ethernet_echo_reply(FILE* destination, const icmp_echo_request_data_t* request_data);

/* Validates and decodes one ICMP Echo Request or Echo Reply from a byte buffer. */
bool icmp_parse_echo_packet(const uint8_t* bytes, size_t byte_count, icmp_echo_header_t* header, const uint8_t** data, size_t* data_length);
