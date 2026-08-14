#pragma once

#include <ipv6.h>

/*
===================================
Internet Control Message Protocol 6
===================================

ICMPv6 is carried directly inside IPv6 packets whose next_header value is 58.
It includes both control/error reporting and Neighbor Discovery. This module
models the checksum rules common to all ICMPv6 messages plus a minimal Echo
Request and Echo Reply pair for IPv6 reachability tests.
*/

#define ICMPV6_TYPE_DESTINATION_UNREACHABLE 1
#define ICMPV6_TYPE_PACKET_TOO_BIG          2
#define ICMPV6_TYPE_TIME_EXCEEDED           3
#define ICMPV6_TYPE_PARAMETER_PROBLEM       4
#define ICMPV6_TYPE_ECHO_REQUEST            128
#define ICMPV6_TYPE_ECHO_REPLY              129
#define ICMPV6_TYPE_ROUTER_SOLICITATION     133
#define ICMPV6_TYPE_ROUTER_ADVERTISEMENT    134
#define ICMPV6_TYPE_NEIGHBOR_SOLICITATION   135
#define ICMPV6_TYPE_NEIGHBOR_ADVERTISEMENT  136

#pragma pack(push, 1)

typedef struct icmpv6_header {
  uint8_t type;
  uint8_t code;
  uint16_t checksum;
} icmpv6_header_t;

typedef struct icmpv6_echo_header {
  uint8_t type;
  uint8_t code;
  uint16_t checksum;
  uint16_t identifier;
  uint16_t sequence_number;
} icmpv6_echo_header_t;

#pragma pack(pop)

typedef struct icmpv6_echo_packet_data {
  mac_address_t dst_mac_addr;
  mac_address_t src_mac_addr;
  ipv6_address_t src_addr;
  ipv6_address_t dst_addr;
  uint16_t identifier;
  uint16_t sequence_number;
  const void* data;
  uint16_t data_length;
  uint8_t hop_limit;
} icmpv6_echo_packet_data_t;

/* Returns the ICMPv6 checksum over one IPv6 pseudo-header plus the supplied message bytes. */
uint16_t icmpv6_checksum(const ipv6_address_t* source, const ipv6_address_t* destination, const void* message, uint16_t message_length);

/* Validates one ICMPv6 header and checksum. */
bool icmpv6_parse_header(const uint8_t* bytes, size_t byte_count, const ipv6_address_t* source, const ipv6_address_t* destination, icmpv6_header_t* header);

/* Writes one ICMPv6 Echo Request inside an IPv6 Ethernet II frame. */
bool icmpv6_write_ethernet_echo_request(FILE* destination, const icmpv6_echo_packet_data_t* request_data);

/* Writes one ICMPv6 Echo Reply inside an IPv6 Ethernet II frame. */
bool icmpv6_write_ethernet_echo_reply(FILE* destination, const icmpv6_echo_packet_data_t* request_data);

/* Validates and decodes one ICMPv6 Echo Request or Reply. */
bool icmpv6_parse_echo_packet(const uint8_t* bytes, size_t byte_count, const ipv6_address_t* source, const ipv6_address_t* destination, icmpv6_echo_header_t* header, const uint8_t** data, size_t* data_length);
