# ICMPv6

ICMPv6 carries both IPv6 diagnostics and essential control traffic. Unlike IPv4, IPv6 neighbor/router discovery is built on ICMPv6 rather than a separate ARP protocol.

| VNet feature | Purpose |
|---|---|
| Echo Request/Reply | `ping6` reachability test |
| Pseudo-header checksum | binds the checksum to IPv6 source, destination, length, and next-header context |
| Parser | validates an ICMPv6 header and echo packet view |
| NDP carriage | transports router and neighbor discovery messages from [NDP](ndp.md) |

The implementation in `src/protocol/icmpv6.{h,c}` uses IPv6 address context for parsing/checksums. `host` sends echo traffic after neighbor discovery; `router` processes and emits the ICMPv6 control traffic it needs.

Real ICMPv6 includes multicast listener discovery, Packet Too Big, redirect, and policy requirements that are critical to IPv6 operation. VNet keeps a small but structurally accurate path for checksum-aware echo and NDP messages.