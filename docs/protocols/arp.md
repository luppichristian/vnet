# ARP

ARP resolves an on-link IPv4 address to an Ethernet MAC address. It is needed because IPv4 forwarding chooses an IP next hop, while Ethernet transmission needs a MAC destination.

| Step | VNet model |
|---|---|
| Request | broadcast Ethernet ARP request names the wanted IPv4 address |
| Reply | owner returns a unicast mapping to the requester |
| Cache | `arp_table` stores learned IPv4/MAC mappings in target-owned caller storage |
| Deferred send | hosts/routers queue the IP work until ARP resolves it |

`src/protocol/arp.{h,c}` defines a packed ARP packet, request/reply writers, and parser. `host` and `router` use it; the DNS server also answers ARP for its configured address. Router pending packets retry ARP and can report failure.

Real ARP has cache aging, probing/security controls, and many operational edge cases. VNet concentrates on request/reply and observable cache state. Run `arp <ip>` or `ping <ip>` on a host, inspect `info`, and decode the media with `watch`. See [Ethernet](ethernet.md) and [IPv4](ipv4.md).