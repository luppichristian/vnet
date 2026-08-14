# RIP

RIP is VNet's distance-vector dynamic-routing option. It teaches periodic route exchange and metric-based route installation without requiring a manually entered static route for every remote LAN.

| Element | VNet model |
|---|---|
| Packet | command and a list of IPv4 network/mask/next-hop/metric entries |
| Destination | recognizes the RIP multicast IPv4 address |
| Router behavior | sends requests/updates, expires RIP routes, refreshes every 30 seconds |
| Policy | per-interface inbound/outbound IPv4 prefix lists apply at the route-installation/advertisement boundary |

`src/protocol/rip.{h,c}` serializes and parses packets. Select it with router startup `-dynamic-routing rip` or the `dynamic-routing rip` command, then inspect `router info`. The route table records dynamic source and expiration information.

Production RIP has additional compatibility, split-horizon/poisoning, authentication, timer, and failure behavior. VNet keeps the route-vector representation and policy boundary visible; use it to compare periodic distance-vector learning with [OSPF](ospf.md) and [BGP](bgp.md).