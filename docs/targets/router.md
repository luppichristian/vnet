# `router` target

`router` is VNet's multi-interface IPv4 Layer-3 appliance. It decapsulates ingress Ethernet, applies policy and forwarding decisions, resolves the egress next hop through ARP, and re-encapsulates packets on the selected medium. Forwarding uses only connected and explicitly configured static routes.

## Startup

```text
router -i <file> <mac> <ip> <mask> [-i <file> <mac> <ip> <mask> ...]
       [-subif <parent-interface> <vlan-id> <ip> <mask> ...]
       [-r <network> <mask> <next-hop|direct> <interface> <metric> ...]
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
| ARP/RARP tables | link-layer resolution and static reverse assignments |
| pending packets | queue packets while ARP retries; preserve a reportable failure context |
| NAT table/pool | static/dynamic NAT and PAT bindings |
| ACL rules/counters | per-interface ingress/egress permit/deny decisions |

## Commands

| Command | Purpose |
|---|---|
| `info` | all router state, interfaces, static routes, policies, and tables |
| `interface <up|down> <number>` | administrative interface state |
| `route add …` / `route delete <number>` | static forwarding entries |
| `arp <interface> <ip>`, `arp-delete …` | neighbor resolution/state |
| `acl default|add|delete …` | per-interface IPv4 filtering |
| `dhcp-relay <interface> <server-ip|none>` | relay configuration |
| `rarp-table set|delete …` | static RARP assignment |

A real router has hardware forwarding, richer policy, robust NAT timeouts, and extensive operational safeguards. VNet retains the visible pipeline and bounded tables so students can relate each policy/configuration decision to captured frames and `info` output.
