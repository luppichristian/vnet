#pragma once

#include <ethernet.h>
#include <ipv4.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

/*
=================================================
Reverse Address Resolution Protocol Packet Format
=================================================
RARP gives a station its network-layer address from a known link-layer address.
A diskless or otherwise unconfigured client broadcasts a request containing its
Ethernet MAC address. A RARP server consults its MAC-to-IPv4 mapping and returns
the assigned IPv4 address in a unicast reply.

OSI/ISO layer: RARP sits at the boundary between Layer 2 (data link) and Layer 3
(network). Like ARP, it uses Ethernet delivery and is limited to one local link;
it does not cross routers. RARP is the reverse of ARP: ARP maps a known IPv4
address to a MAC address, while RARP maps a known MAC address to an IPv4 address.

RARP delivery modes on Ethernet are normally:

  Broadcast: a client request uses FF:FF:FF:FF:FF:FF so any RARP server on the
             local link can answer it. Both hardware-address fields name the
             requesting client; both protocol-address fields are zero because
             the client does not yet know its IPv4 address.
  Unicast:   a RARP server replies directly to the client MAC address and places
             the assigned IPv4 address in the target-protocol-address field.
  Multicast: ordinary Ethernet/IPv4 RARP does not use multicast groups.

This header models the Ethernet/IPv4 RARP variant carried by an Ethernet II
frame whose EtherType is 0x8035:

  Ethernet II data field:
    hardware type (2) | protocol type (2) | hardware length (1) |
    protocol length (1) | operation (2) | sender MAC (6) | sender IPv4 (4) |
    target MAC (6) | target IPv4 (4)

The packet is 28 octets. Ethernet pads it to its 46-octet minimum data field,
but the padding is not part of the RARP packet. RARP has no checksum; Ethernet's
FCS protects the complete Ethernet frame instead.
*/

#define RARP_HARDWARE_TYPE_ETHERNET 1
#define RARP_OPERATION_REQUEST      3
#define RARP_OPERATION_REPLY        4

#pragma pack(push, 1)

typedef struct rarp_packet {
  /* Identifies the link-layer address family. Ethernet is type 1. */
  uint16_t hardware_type;

  /* Identifies the network-layer address family. IPv4 uses EtherType 0x0800. */
  uint16_t protocol_type;

  /* Number of octets in each hardware address. Ethernet MAC addresses occupy six octets. */
  uint8_t hardware_address_length;

  /* Number of octets in each protocol address. IPv4 addresses occupy four octets. */
  uint8_t protocol_address_length;

  /* Request asks for an IPv4 assignment; reply supplies the configured address. */
  uint16_t operation;

  /* Hardware and protocol addresses belonging to the station sending this RARP packet. */
  mac_address_t sender_hardware_address;
  ipv4_address_t sender_protocol_address;

  /*
  RARP request: both hardware addresses name the client and both protocol
  addresses are zero. RARP reply: these fields identify the client and carry
  its assigned IPv4 address in target_protocol_address.
  */
  mac_address_t target_hardware_address;
  ipv4_address_t target_protocol_address;
} rarp_packet_t;

#pragma pack(pop)

/* Data needed to write one broadcast Ethernet/IPv4 RARP request. */
typedef struct rarp_request_data {
  /* Client seeking an IPv4 assignment; it fills both RARP hardware-address fields. */
  mac_address_t client_hardware_address;
} rarp_request_data_t;

/* Data needed to write one unicast Ethernet/IPv4 RARP reply. */
typedef struct rarp_reply_data {
  /* RARP server that owns the MAC-to-IPv4 configuration mapping. */
  mac_address_t server_hardware_address;
  ipv4_address_t server_protocol_address;

  /* Client MAC from the request and the IPv4 address assigned to that client. */
  mac_address_t client_hardware_address;
  ipv4_address_t client_protocol_address;
} rarp_reply_data_t;

/* Writes one broadcast Ethernet II RARP request. */
bool rarp_write_ethernet_request(FILE* destination, const rarp_request_data_t* request_data);

/* Writes one unicast Ethernet II RARP reply. */
bool rarp_write_ethernet_reply(FILE* destination, const rarp_reply_data_t* reply_data);

/* Validates and decodes one Ethernet/IPv4 RARP request or reply from a byte buffer. */
bool rarp_parse_packet(const uint8_t* bytes, size_t byte_count, rarp_packet_t* packet);
