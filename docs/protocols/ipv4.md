# IPv4

## Role

IPv4 is the main Layer-3 packet format in VNet. Hosts decide whether the destination is local or requires the configured gateway; routers select a connected, static, or dynamically learned route and resolve the egress next hop with ARP.

## Modeled header and handling

| Concern | VNet behavior |
|---|---|
| Addressing | parses dotted-decimal addresses; tests subnet, broadcast, multicast, loopback, and unspecified cases |
| Header | packed IPv4 header with version, IHL, total length, identification, flags/fragment offset, TTL, protocol, checksum, source, destination |
| Validation | parser validates header shape/length and header checksum |
| Forwarding | router decrements TTL, performs longest-match table lookup, and recomputes the header checksum |
| Payload protocol | ICMP, TCP, UDP, RIP, and OSPF are dispatched by the protocol field |

`ipv4_write_ethernet_packet` encapsulates the packet in Ethernet II; `ipv4_parse_packet` returns a view into caller-owned bytes. The data model is in `src/protocol/ipv4.{h,c}`.

## Why it is implemented

The project studies IP-based networking, so IPv4 is the boundary between local Ethernet delivery and routed delivery. It allows a student to see that a router preserves the L3 destination while changing L2 addressing on each hop.

## Real world and model

Production stacks must handle options, fragmentation/reassembly, PMTUD, ICMP policy, socket integration, and many edge cases. VNet focuses on a compact header/payload path and inspectable route/ARP state. It is a protocol-learning implementation, not an RFC-complete IPv4 stack.

## Exercises

Start two routed LANs as shown in [Simulating networks](../simulating_networks.md), ping across them, and capture both media. Inspect the router's `info` and `route` state before and after adding a route or changing an interface state.