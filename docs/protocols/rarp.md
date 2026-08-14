# RARP

Reverse ARP is a historical LAN protocol that asks for an IPv4 address using a known MAC address. It is included because it makes the inverse mapping and bootstrapping problem visible alongside ARP.

| Aspect | VNet model |
|---|---|
| Request | host broadcasts a RARP request for its MAC |
| Answer | router consults its configured RARP table and sends a reply |
| State | `rarp_table` maps MAC addresses to static IPv4 addresses |

The packed request/reply format and parser are in `src/protocol/rarp.{h,c}`. Start the router with `-rarp <client-mac> <ip-address>`, or use its `rarp-table set` command; run `rarp` at the host.

Real RARP was superseded by BOOTP and DHCP because it conveyed very little configuration and depended on the local LAN. VNet retains it as a focused contrast: use [DHCP](dhcp.md) when the goal is dynamic address *plus* mask/gateway/DNS configuration.