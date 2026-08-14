# BGP

BGP adds an inter-domain-style control plane to the router. It is intentionally layered over VNet's public TCP socket API, demonstrating that a routing protocol exchanges control messages over a reliable transport instead of directly owning link-layer I/O.

| Message | VNet model |
|---|---|
| OPEN | local autonomous-system number and IPv4 identifier |
| KEEPALIVE | advances/maintains a compact peer session |
| UPDATE | network, mask, next hop, autonomous system |
| Peer | active/passive role, interface, remote address, local/remote AS, session timing |

Configure a router peer with `-bgp <active|passive> <interface> <peer-ip> <local-as> <peer-as>`. The router opens/listens on TCP port 179 as needed. `bgp-prefix-list <peer> <in|out> <name|none>` attaches policy at peer boundaries.

Real BGP is a path-vector protocol with extensive attributes, policy, route selection, timers, error handling, capability negotiation, and security/operational concerns. VNet models OPEN/KEEPALIVE/UPDATE and policy attachment so students can observe sessions and advertised prefixes without claiming RFC-complete BGP.