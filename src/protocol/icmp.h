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

This header models two minimal ICMP message families used by the simulator:

  Echo:  ping-style reachability tests between hosts.
  Error: router-generated forwarding errors for a few common IPv4 failures.

The modeled forwarding errors are intentionally small and explicit:

  Destination Unreachable, type 3:
    code 0  network unreachable, used here when no route exists.
    code 1  host unreachable, used here when the selected egress path exists
            but cannot deliver, such as a down interface or an unresolved
            next hop after the router's local ARP retry budget is exhausted.

  Time Exceeded, type 11:
    code 0  TTL expired in transit.

ICMP error messages quote the original IPv4 header plus the first eight octets
of that packet's payload, which is the conventional minimum needed for the
sender to identify the failed traffic.

This simulator suppresses ICMP forwarding errors for packets that do not
identify one returnable unicast source, including broadcast or multicast
traffic, invalid IPv4 sources, and incoming ICMP error messages.

The wire layouts used here are:

  Echo inside IPv4:  ICMP Echo header | optional ICMP data
                         8 octets

  Error inside IPv4: ICMP Error header | quoted IPv4 header | first 8 payload octets
                         8 octets            20 octets              up to 8 octets

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
#define ICMP_TYPE_DESTINATION_UNREACHABLE 3
#define ICMP_TYPE_ECHO_REQUEST 8
#define ICMP_TYPE_TIME_EXCEEDED 11
#define ICMP_CODE_ECHO         0
#define ICMP_CODE_NETWORK_UNREACHABLE 0
#define ICMP_CODE_HOST_UNREACHABLE    1
#define ICMP_CODE_TTL_EXPIRED         0
#define ICMP_ERROR_QUOTE_DATA_LEN     8

#pragma pack(push, 1)

typedef struct icmp_header {
  uint8_t type;
  uint8_t code;
  uint16_t checksum;
} icmp_header_t;

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

typedef struct icmp_error_header {
  uint8_t type;
  uint8_t code;
  uint16_t checksum;
  uint32_t unused;
} icmp_error_header_t;

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

/* Serializes one modeled ICMP error payload for inclusion in an IPv4 packet. */
bool icmp_write_error_payload(
    uint8_t* destination,
    size_t destination_size,
    const ipv4_header_t* quoted_header,
    const uint8_t* quoted_payload,
    uint16_t quoted_payload_length,
    uint8_t type,
    uint8_t code,
    uint16_t* payload_length);

/* Returns true when type is one of ICMP's error-reporting message classes. */
bool icmp_type_is_error(uint8_t type);

/* Returns true when bytes begin with a checksummed ICMP error message. */
bool icmp_packet_is_error(const uint8_t* bytes, size_t byte_count);

/* Validates and decodes one ICMP Echo Request or Echo Reply from a byte buffer. */
bool icmp_parse_echo_packet(const uint8_t* bytes, size_t byte_count, icmp_echo_header_t* header, const uint8_t** data, size_t* data_length);
