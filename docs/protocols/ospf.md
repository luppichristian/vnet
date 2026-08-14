# OSPF

OSPF is VNet's compact link-state routing option. Router updates describe router links, allowing the route table to gain OSPF-sourced reachability and later expire it if refreshes stop.

| Element | VNet model |
|---|---|
| Packet | OSPF-like header and router-link records |
| Group destination | recognizes the all-SPF-routers IPv4 multicast destination |
| Timing | router refreshes updates every 10 seconds and expires OSPF routes after 40 seconds |
| Selection | enable with `-dynamic-routing ospf` or `dynamic-routing ospf` |

The wire representation is in `src/protocol/ospf.{h,c}` and is consumed by `router`. It intentionally concentrates on visible link advertisements and route lifecycle.

Real OSPF has adjacency state machines, LSDB flooding, designated router election, areas, LSA families, SPF calculation details, authentication, and many operational safeguards. The VNet model should be read as a learning bridge from static routing to link-state ideas, not a deployable OSPF implementation.