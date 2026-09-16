# Simulating networks

VNet models a network medium as an append-only file. Every target tails its input media, parses complete records, and appends generated traffic. This lets a topology remain inspectable without using host networking APIs.

## Core workflow

1. Create a file for each shared Ethernet medium.
2. Start endpoints, routers, or services with their attachment file and explicit MAC/IPv4 configuration.
3. Use `watch` on a medium to inspect frames and protocol nesting.
4. Enter target commands such as `ping`, `route`, `arp`, or `socket` to produce traffic.

## Target roles

| Target | Role | Typical activity | Configuration focus |
|---|---|---|---|
| `link` | Point-to-point medium bridge | connect two traffic files | source/destination media |
| `hub` | Repeats traffic between files | observe shared collision-domain behavior | attachment files |
| `switch` | Learning Ethernet switch | study FDB/VLAN forwarding | ports and VLAN policy |
| `host` | Ethernet/IPv4 endpoint | Generate ARP, DHCP, DNS, ICMP, UDP, and TCP traffic | startup IPv4/DNS/DHCP settings; `config`, `ping`, `udp`, `socket` |
| `router` | Multi-interface IPv4 router | Study forwarding, ARP, static routes, ACLs, NAT/PAT, and VLAN subinterfaces | interfaces, static routes, policies, NAT, DHCP relay |
| `dhcp_server` | DHCPv4 service | offer and acknowledge IPv4 configuration | pool and server address |
| `dns_server` | Authoritative DNS service | answer A/CNAME queries | records and server address |
| `watch` | Passive protocol reader | decode appended records and frames | medium path |

## Example: switched IPv4 LAN

This topology puts two hosts and a DNS server on one switched VLAN. Use distinct files for endpoint attachment and a distinct switch-medium file.

```text
host A ── a.bin ┐
host B ── b.bin ├─ switch ─ lan.bin ─ dns_server
                │
watch ──────────┘
```

Start the switch and the endpoints with the corresponding media files. After ARP learns the destination MAC, `ping` provides a compact IPv4/ICMP exchange to inspect with `watch`.

## Example: static routed LANs

Attach each router interface and host to its own medium. The router automatically installs connected routes. Add one explicit static route for each remote network, specifying the destination network, contiguous mask, next hop, interface, and metric. Longest-prefix match selects the most specific matching route; equal prefixes select the lower metric.

Static routing keeps the forwarding decision visible and deterministic: no control-plane protocol changes the table after startup unless a user explicitly adds or removes a static entry.
