# Ethernet

## Role

Ethernet is VNet's Layer-2 envelope. It makes local delivery visible: an endpoint chooses a destination MAC, a switch learns source MAC-to-port mappings, and a router removes the ingress frame before transmitting the IP packet in a new egress frame.

## Modeled frame

| Order | Field | VNet behavior |
|---:|---|---|
| 1 | Preamble (7) and SFD (1) | emitted and parsed so captures show physical synchronization bytes |
| 2 | Destination/source MAC | six octets each; unicast, broadcast, and group checks are explicit |
| 3 | Type/length | values ≤1500 are IEEE 802.3 length; ≥1536 are Ethernet II EtherTypes |
| 4 | Optional 802.1Q tag | carries priority, drop eligibility, and VLAN ID 1–4094 |
| 5 | Data/padding | client payload is padded to Ethernet's 46-octet minimum |
| 6 | FCS | CRC validates the MAC frame |

The implementation in `src/protocol/ethernet.{h,c}` serializes a complete frame and parses/validates it back into an `ethernet_frame_view_t`. It supports IPv4 (`0x0800`), ARP (`0x0806`), RARP (`0x8035`), IPv6 (`0x86DD`), and VLAN (`0x8100`).

## Why it is implemented

IP addresses alone do not put packets on a LAN. Ethernet exposes the distinction between an IP end destination and an on-link next hop, enables ARP/NDP experiments, and gives the switch a concrete forwarding key.

## Real world and model

Real Ethernet sends bits through a PHY and NIC; VNet stores packed octets in a file. It preserves the byte-level preamble/SFD/frame/FCS structure but not electrical signaling, collision detection, autonegotiation, or real NIC offloads. `watch` prints each stored octet in Ethernet transmission bit order (least-significant bit first).

## Where to study it

Use `watch <file>` to inspect a frame, `switch` to observe FDB/VLAN/STP behavior, and `host` or `router` to create traffic. See [ARP](arp.md), [IPv4](ipv4.md), and [VNet](vnet.md).