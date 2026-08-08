#pragma once

#include <stdint.h>

/*
======================
Ethernet Frame Formats
======================

This header models the bits emitted by IEEE 802.3 and Ethernet II senders in
this common order:

  Physical synchronization: preamble (7 octets), SFD (1 octet)
  MAC frame: destination MAC (6), source MAC (6), type/length (2), data + padding (46-1500), FCS (4)

OSI/ISO layer: the Ethernet MAC frame is a Layer 2 (data-link-layer) protocol.
The preamble and SFD assist Layer 1 (physical-layer) synchronization before the
Layer 2 frame begins.

Ethernet delivery is selected by destination MAC address:

  Unicast:   one station's individual MAC address; its first-octet I/G bit is 0.
  Broadcast: FF:FF:FF:FF:FF:FF; every station on the local Ethernet receives it.
  Multicast: a group MAC address; its first-octet I/G bit is 1 but it is not the
             all-FF broadcast address. Only stations subscribed to that group
             should accept it.

Ethernet broadcast and multicast remain on the local Layer 2 network; routers
do not forward them as Ethernet frames to another LAN.

The preamble and SFD are physical-layer synchronization fields, so they are
not counted in the 64-1518-byte MAC-frame size. Each uint8_t in this simulator
stores one complete octet, exactly as hardware does before serializing it onto
the medium. Ethernet transmits the least-significant bit of every octet first:
0x55 is therefore transmitted as 10101010 and 0xD5 as 10101011.

Writing one uint8_t value of 0 or 1 for every bit would make the file eight
times larger and would not be Ethernet's packed wire representation. The reader
instead prints every stored octet bit-by-bit in real transmission order.
*/

/* Seven alternating-bit synchronization octets; emitted as 10101010 each. */
#define ETHERNET_PREAMBLE_LEN  7
#define ETHERNET_PREAMBLE_BYTE (uint8_t)(0x55)

/* Marks the end of synchronization; emitted as 10101011. */
#define ETHERNET_SFD (uint8_t)(0xD5)

/* A six-octet Ethernet MAC address. Destination is emitted before source. */
typedef uint8_t mac_address_t[6];

/* The IEEE 802.3 length field excludes padding, which reaches the 46-octet minimum. */
#define ETHERNET_MIN_DATA_LEN 46
#define ETHERNET_MAX_DATA_LEN 1500

/* Values through 1500 identify IEEE 802.3; 1501-1535 are reserved. */
#define ETHERNET_ETHERTYPE_MIN  1536
#define ETHERNET_ETHERTYPE_IPV4 0x0800
#define ETHERNET_ETHERTYPE_ARP  0x0806
#define ETHERNET_ETHERTYPE_IPV6 0x86DD

typedef enum ethernet_frame_format {
  ETHERNET_FRAME_FORMAT_IEEE_802_3,
  ETHERNET_FRAME_FORMAT_II,
} ethernet_frame_format_t;

#pragma pack(push, 1)

/* Wire representation: physical synchronization followed by the MAC header. */
typedef struct ethernet_header {
  uint8_t preamble[ETHERNET_PREAMBLE_LEN]; /* Seven 0x55 octets. */
  uint8_t sfd;                             /* One 0xD5 octet. */
  mac_address_t dst_mac;                   /* Receiving station(s). */
  mac_address_t src_mac;                   /* Sending station. */
  uint16_t type_or_length;                 /* Entire 16-bit field: length for IEEE 802.3 or EtherType for Ethernet II, not bit-packed subfields. */
} ethernet_header_t;

/* FCS follows the MAC frame and protects everything from dst_mac through padding. */
typedef struct ethernet_footer {
  uint32_t crc; /* Real Ethernet transmits the FCS least-significant byte first. */
} ethernet_footer_t;

#pragma pack(pop)

/* Standard CRC-32 (IEEE 802.3), reflected, poly 0xEDB88320 */
static inline uint32_t crc32(const void* data, size_t data_size) {
  const uint8_t* bytes = (const uint8_t*)data;
  uint32_t crc = 0xFFFFFFFFu;

  for (size_t i = 0; i < data_size; ++i) {
    crc ^= bytes[i];
    for (int bit = 0; bit < 8; ++bit) {
      uint32_t mask = -(crc & 1u);
      crc = (crc >> 1) ^ (0xEDB88320u & mask);
    }
  }

  return ~crc;
}
