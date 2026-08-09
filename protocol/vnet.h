#pragma once

#include <stdint.h>

/*
====================================
Virtual Network Control Frame Format
====================================

VNet is this simulator's local control protocol for annotating the raw traffic
file shared by its network utilities. It does not encapsulate or alter the
bytes forwarded by connect; it records when connect starts and stops forwarding
one source file into one destination file:

  VNet header (8 octets) | source-file path (payload_length octets)

OSI/ISO layer: VNet is not a real network protocol and does not belong to an
OSI layer. It is simulator control information written directly to the same
append-only file that represents the raw medium. A reader can use it to explain
why traffic begins or ends arriving from a particular source.

VNet does not model unicast, broadcast, or multicast. connect writes each
control frame directly to its selected destination file. The source-file path
is metadata for the simulator, not a network address and not a null-terminated
C string inside the frame.

This first version uses native multi-octet values and a packed header, matching
the rest of this compiler-local file simulation. Its writer and reader must use
the same platform and compiler configuration.
*/

#define VNET_FRAME_MAGIC      0x564E4554u
#define VNET_PROTOCOL_VERSION 1

/* The maximum source-file path length stored after one VNet header. */
#define VNET_MAX_SOURCE_PATH_LEN UINT16_MAX

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

  /* Number of following source-file path octets; the path has no terminating zero. */
  uint16_t payload_length;
} vnet_frame_header_t;

#pragma pack(pop)
