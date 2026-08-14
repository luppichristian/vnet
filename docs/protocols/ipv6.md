# IPv6

## Role

IPv6 adds a parallel Layer-3 path to the IPv4-oriented labs. VNet models the fixed IPv6 header, address classification, multicast address-to-MAC mapping, link-local address generation from MAC addresses, and SLAAC-style address construction from an advertised prefix.

## Modeled behavior

| Element | VNet behavior |
|---|---|
| Address | 16-byte `ipv6_address_t`; parser and formatter operate on textual IPv6 addresses |
| Fixed header | version, traffic class/flow label, payload length, next header, hop limit, source, destination |
| Local address | derives link-local interface identity from the Ethernet MAC |
| SLAAC input | forms an address from a prefix, prefix length, and MAC-derived identifier |
| Multicast | builds solicited-node multicast addresses and their Ethernet multicast MACs |
| Carriage | serializes in Ethernet II with EtherType `0x86DD` |

## Why it is implemented

IPv6 makes clear that address resolution is not universally ARP. The paired [NDP](ndp.md) and [ICMPv6](icmpv6.md) modules let students follow router solicitation/advertisement and neighbor solicitation/advertisement.

## Real world and model

The real IPv6 ecosystem includes extension headers, duplicate-address detection, address lifetimes, privacy addresses, routing protocol variants, and extensive multicast behavior. VNet implements the parts required for visible endpoint/router discovery and echo exchanges, while retaining a compact fixed-header model.

## Where it is used

`host` creates link-local state, solicits routers, and can run `ping6`; `router` handles IPv6/NDP and emits router advertisements. Use `info` and `watch` beside a small router/host topology to relate configuration state to frames.