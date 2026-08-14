# `router` target

`router` is VNet's multi-interface Layer-3 appliance. It decapsulates ingress Ethernet, applies IPv4 policy and forwarding decisions, resolves the egress next hop through ARP, and re-encapsulates the packet on the selected medium. It also owns IPv6/NDP, routing control-plane, ACL, NAT/PAT, RARP, DHCP-relay, and virtual-socket state.

## Startup

```text
router -i <file> <mac> <ip> <mask> [-i <file> <mac> <ip> <mask> ...]
       [-subif <parent-interface> <vlan-id> <ip> <mask> ...]
       [-r <network> <mask> <next-hop|direct> <interface> <metric> ...]
       [-dynamic-routing <off|rip|ospf>]
       [-bgp <active|passive> <interface> <peer-ip> <local-as> <peer-as> ...]
       [-dhcp-relay <interface> <server-ip> ...]
       [-nat <inside-interface> <outside-interface>] [-dynamic-nat <outside-ip> ...]
       [-dynamic-pat] [-static-nat <inside-ip> <outside-ip> ...]
       [-static-pat <tcp|udp> <inside-ip> <inside-port> <outside-ip> <outside-port> ...]
       [-rarp <client-mac> <ip> ...]
       [-acl-default …] [-acl …]
```

At least two base interfaces are required. Connected routes are created automatically from every interface. A subinterface attaches an IPv4 identity to a parent file/VLAN and emits/accepts 802.1Q traffic.

## Internal state

| Table/state | Purpose |
|---|---|
| interface + route tables | interface identity/admin state and longest-prefix forwarding |
| ARP/ND/RARP tables | link-layer resolution and static reverse assignments |
| pending packets | queue packets while ARP retries; preserve a reportable failure context |
| prefix lists | named ordered permit/deny IPv4 prefixes, with prefix-length bounds |
| BGP peers / socket contexts | TCP-port-179 peer state and transport boundary |
| NAT table/pool | static/dynamic NAT and PAT bindings |
| ACL rules/counters | per-interface ingress/egress permit/deny decisions |

## Commands

| Command | Purpose |
|---|---|
| `info` | all router state, interfaces, route sources, policies, and tables |
| `interface <up|down> <number>` | administrative interface state |
| `route add …` / `route delete <number>` | static forwarding entries |
| `arp <interface> <ip>`, `arp-delete …` | neighbor resolution/state |
| `acl default|add|delete …` | per-interface IPv4 filtering |
| `dynamic-routing <off|rip|ospf>` | select dynamic routing engine |
| `prefix-list …`, `bgp-prefix-list …`, `rip-prefix-list …` | policy definitions and attachments |
| `dhcp-relay <interface> <server-ip|none>` | relay configuration |
| `rarp-table set|delete …` | static RARP assignment |

A real router has hardware forwarding, richer protocol state machines, complete IPv6 forwarding/policy, robust NAT timeouts, and extensive operational safeguards. VNet retains the visible pipeline and bounded tables so students can relate each policy/configuration decision to captured frames and `info` output.