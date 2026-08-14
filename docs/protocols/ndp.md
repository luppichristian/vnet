# Neighbor Discovery Protocol (NDP)

NDP is the IPv6 local-link discovery suite carried in ICMPv6. In VNet it replaces the IPv4 ARP mental model and introduces router discovery plus prefix-driven address configuration.

| Message | VNet use |
|---|---|
| Router Solicitation | host asks routers to advertise configuration |
| Router Advertisement | router supplies a prefix/default-router information for host state |
| Neighbor Solicitation | asks for a target IPv6 neighbor's link-layer address |
| Neighbor Advertisement | supplies the target's MAC mapping |
| Prefix Information option | lets the host construct SLAAC-style global addressing |

`src/protocol/ndp.{h,c}` models packed wire records and source link-layer/prefix options. `nd_table` retains IPv6-to-MAC entries. `host` automatically begins with a router solicitation and can perform `ping6`; `router` periodically advertises.

The real protocol also specifies duplicate address detection, reachable timers, redirects, and nuanced option validation. VNet focuses on the exchanges that explain how an IPv6 node finds a router and a neighbor without ARP.