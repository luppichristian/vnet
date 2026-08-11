#pragma once

#include <ipv4.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/*
======================================
Border Gateway Protocol Version 4
======================================
BGP is an inter-domain path-vector routing protocol carried by a reliable TCP
byte stream on port 179. This VNet module owns BGP message validation and
serialization only. Router session state and TCP ownership remain above it and
use the public socket.h API exclusively.

The initial VNet BGP model implements configured eBGP peers, OPEN/KEEPALIVE
session establishment, and one IPv4 unicast UPDATE route per message. UPDATEs
carry the mandatory ORIGIN, AS_PATH, and NEXT_HOP attributes. It intentionally
omits route reflection, confederations, capabilities, policy language, and
multi-prefix UPDATE packing until simulated topologies need them.
*/

#define BGP_TCP_PORT 179
#define BGP_VERSION 4
#define BGP_MARKER_LENGTH 16
#define BGP_HEADER_LENGTH 19
#define BGP_MESSAGE_OPEN 1
#define BGP_MESSAGE_UPDATE 2
#define BGP_MESSAGE_NOTIFICATION 3
#define BGP_MESSAGE_KEEPALIVE 4
#define BGP_HOLD_TIME_SECONDS 90
#define BGP_KEEPALIVE_SECONDS 30
#define BGP_MAX_MESSAGE_LENGTH 4096

#pragma pack(push, 1)
typedef struct bgp_header {
  uint8_t marker[BGP_MARKER_LENGTH];
  uint16_t length;
  uint8_t type;
} bgp_header_t;

typedef struct bgp_open {
  bgp_header_t header;
  uint8_t version;
  uint16_t autonomous_system;
  uint16_t hold_time;
  ipv4_address_t identifier;
  uint8_t optional_parameter_length;
} bgp_open_t;
#pragma pack(pop)

_Static_assert(sizeof(bgp_header_t) == BGP_HEADER_LENGTH, "BGP header must remain fixed");

/* A view refers to bytes owned by the caller's TCP receive buffer. */
typedef struct bgp_message_view {
  bgp_header_t header;
  const uint8_t* payload;
  uint16_t payload_length;
} bgp_message_view_t;

/* Decoded mandatory attributes of this model's single-prefix IPv4 UPDATE. */
typedef struct bgp_update {
  ipv4_address_t network;
  ipv4_address_t mask;
  ipv4_address_t next_hop;
  uint16_t autonomous_system;
} bgp_update_t;

/* Writes one BGP OPEN or KEEPALIVE message into a contiguous TCP stream buffer. */
bool bgp_write_open(uint16_t autonomous_system, ipv4_address_t identifier, uint8_t* bytes, size_t capacity, uint16_t* length);
bool bgp_write_keepalive(uint8_t* bytes, size_t capacity, uint16_t* length);

/* Writes an IPv4 unicast UPDATE with mandatory eBGP path attributes. */
bool bgp_write_update(ipv4_address_t network, ipv4_address_t mask, ipv4_address_t next_hop, uint16_t autonomous_system, uint8_t* bytes, size_t capacity, uint16_t* length);

/* Validates one complete BGP message at the beginning of bytes. */
bool bgp_parse_message(const uint8_t* bytes, size_t byte_count, bgp_message_view_t* message);

/* Decodes one supported non-withdrawal IPv4 UPDATE and its mandatory attributes. */
bool bgp_parse_update(const bgp_message_view_t* message, bgp_update_t* update);
