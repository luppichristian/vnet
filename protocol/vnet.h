#pragma once

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

/*
====================================
Virtual Network Control Frame Format
====================================

VNet is this simulator's local control protocol for annotating the raw traffic
file shared by its network utilities. It does not encapsulate or alter the
bytes forwarded by connect; it records when connect starts and stops forwarding
one source file into one destination file:

  VNet frame (1030 octets): magic | version | type | source path | destination path

OSI/ISO layer: VNet is not a real network protocol and does not belong to an
OSI layer. It is simulator control information written directly to the same
append-only file that represents the raw medium. A reader can use it to explain
why traffic begins or ends arriving from a particular source.

VNet does not model unicast, broadcast, or multicast. connect writes each
control frame directly to its selected destination file. Source and destination
paths are metadata for the simulator, not network addresses. They let another
connection recognize that a control frame has already arrived at its intended
file and must not forward it again.

This first version uses native multi-octet values and a packed header, matching
the rest of this compiler-local file simulation. Its writer and reader must use
the same platform and compiler configuration.
*/

#define VNET_FRAME_MAGIC      0x564E4554u
#define VNET_PROTOCOL_VERSION 1

/* Both paths include a terminating zero and may contain at most 511 visible characters. */
#define VNET_PATH_LEN 512

typedef enum vnet_frame_type {
  /* connect has begun forwarding the named source file into this destination. */
  VNET_FRAME_CONNECTION_START = 1,

  /* connect has stopped forwarding the named source file into this destination. */
  VNET_FRAME_CONNECTION_END = 2,
} vnet_frame_type_t;

#pragma pack(push, 1)

typedef struct vnet_frame_header {
  /* Identifies this sequence as a VNet control frame. */
  uint32_t magic;

  /* Version of this VNet header and payload format. */
  uint8_t version;

  /* Connection-start or connection-end control event. */
  uint8_t type;

  /* File from which connect reads the traffic for this connection event. */
  char source_path[VNET_PATH_LEN];

  /* File to which connect writes the traffic and this control frame. */
  char destination_path[VNET_PATH_LEN];
} vnet_frame_header_t;

#pragma pack(pop)

_Static_assert(sizeof(vnet_frame_header_t) == 1030, "VNet frame size must remain fixed");

/* Returns true when frame has this simulator's magic, version, type, and terminated paths. */
bool vnet_frame_is_valid(const vnet_frame_header_t* frame);

/* Returns true when bytes contain the VNet magic prefix. */
bool vnet_frame_has_prefix(const uint8_t* bytes, size_t byte_count);

/* Validates and decodes one complete VNet frame from a byte buffer. */
bool vnet_parse_frame(const uint8_t* bytes, size_t byte_count, vnet_frame_header_t* frame);

/* Appends one connection lifecycle frame to destination and flushes it for other targets. */
bool vnet_frame_write(FILE* destination, vnet_frame_type_t type, const char* source_path, const char* destination_path);

/*
Forwards raw bytes through an append-mode destination until source_end. Complete
VNet frames addressed to source_path are consumed locally and excluded from
forwarded_bytes.
*/
bool vnet_forward_bytes(FILE* source, FILE* destination, const char* source_path, long source_end, size_t* forwarded_bytes);
