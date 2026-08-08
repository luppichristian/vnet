#pragma once

#include <ethernet.h>
#include <ipv4.h>
#include <stdint.h>

/*
=========================================
Address Resolution Protocol Packet Format
=========================================

ARP resolves a network-layer address to a link-layer address on one local
network. Before sending an IPv4 packet to a host on its LAN, a station needs the
host's Ethernet MAC address. It broadcasts an ARP request asking "who has this
IPv4 address?" The owner replies with its MAC address, which the sender may
cache for subsequent Ethernet frames.

OSI/ISO layer: ARP sits at the boundary between Layer 2 (data link) and Layer 3
(network). It is often informally called a "Layer 2.5" protocol because it uses
Ethernet delivery to resolve an IPv4 address; it is not routed beyond the local
link.

ARP delivery modes on Ethernet are normally:

  Broadcast: an ARP request uses FF:FF:FF:FF:FF:FF because the requester does
             not yet know the target MAC address. Its target-hardware field is
             all zeroes.
  Unicast:   the owner generally sends the ARP reply directly to the requester's
             MAC address. A host may also issue a unicast ARP request when it
             already has a possible mapping to verify.
  Multicast: ordinary Ethernet/IPv4 ARP does not use multicast groups.

This header models the Ethernet/IPv4 ARP variant carried by an Ethernet II
frame whose EtherType is 0x0806:

  Ethernet II data field:
    hardware type (2) | protocol type (2) | hardware length (1) |
    protocol length (1) | operation (2) | sender MAC (6) | sender IPv4 (4) |
    target MAC (6) | target IPv4 (4)

The packet is 28 octets. Ethernet pads it to its 46-octet minimum data field,
but the padding is not part of the ARP packet. ARP has no checksum; Ethernet's
FCS protects the complete Ethernet frame instead.
*/

#define ARP_HARDWARE_TYPE_ETHERNET 1
#define ARP_OPERATION_REQUEST      1
#define ARP_OPERATION_REPLY        2

#pragma pack(push, 1)

typedef struct arp_packet {
  /* Identifies the link-layer address family. Ethernet is type 1. */
  uint16_t hardware_type;

  /* Identifies the network-layer address family. IPv4 uses EtherType 0x0800. */
  uint16_t protocol_type;

  /* Number of octets in each hardware address. Ethernet MAC addresses occupy six octets. */
  uint8_t hardware_address_length;

  /* Number of octets in each protocol address. IPv4 addresses occupy four octets. */
  uint8_t protocol_address_length;

  /* Request asks for an address mapping; reply supplies one. */
  uint16_t operation;

  /* Hardware and protocol addresses belonging to the station sending this ARP packet. */
  mac_address_t sender_hardware_address;
  ipv4_address_t sender_protocol_address;

  /*
  Requested mapping. An ARP request does not yet know target_hardware_address,
  so it fills it with zeroes while target_protocol_address identifies the host.
  */
  mac_address_t target_hardware_address;
  ipv4_address_t target_protocol_address;
} arp_packet_t;

#pragma pack(pop)
