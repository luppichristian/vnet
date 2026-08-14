# Protocol hierarchy

VNet is organized as an inspectable protocol stack rather than a general-purpose network stack. Targets compose the same serializers, parsers, tables, and small socket API in different ways.

## Encapsulation overview

```mermaid
flowchart TB
  APP[Application actions\nDNS / DHCP / ping / socket send] --> L4[Transport\nUDP or simplified TCP]
  APP --> ICMP[Control\nICMP or ICMPv6]
  L4 --> IP4[IPv4]
  L4 --> IP6[IPv6]
  ICMP --> IP4
  ICMP --> IP6
  IP4 --> ETH[Ethernet II / 802.3\noptional 802.1Q]
  IP6 --> ETH
  ARP[ARP / RARP] --> ETH
  NDP[NDP] --> ICMP6[ICMPv6] --> IP6
  ETH --> MEDIUM[Append-only traffic file]
  CTRL[VNet lifecycle control] --> MEDIUM
```

The graph shows encapsulation, not a claim that every protocol is always present. ARP/RARP are Ethernet payloads, NDP is carried in ICMPv6/IPv6, and VNet is local simulator metadata placed directly in the media file rather than a real network-layer protocol.

## Dependency graph

```mermaid
flowchart LR
  E[ethernet] --> ARP[arp]
  E --> RARP[rarp]
  E --> I4[ipv4]
  E --> I6[ipv6]
  I4 --> ICMP[icmp]
  I4 --> UDP[udp]
  I4 --> TCP[tcp]
  I4 --> RIP[rip]
  I4 --> OSPF[ospf]
  TCP --> BGP[bgp]
  UDP --> DHCP[dhcp]
  UDP --> DNS[dns]
  I6 --> ICMP6[icmpv6]
  ICMP6 --> NDP[ndp]
  V[VNet control] --> F[traffic-file forwarding]
  ARP --> T1[ARP table]
  NDP --> T2[ND table]
  I4 --> T3[route/interface/NAT tables]
  E --> T4[FDB table]
```

`bgp` deliberately uses the public `socket.h` interface through the router rather than depending on a private TCP implementation. The socket layer selects TCP or UDP internally.

## Protocols linked to targets

| Protocol | Primary purpose in VNet | Targets using it |
|---|---|---|
| [VNet](protocols/vnet.md) | connection lifecycle records for file topology | `link`, `hub`, `switch`, `watch` |
| [Ethernet](protocols/ethernet.md) | Layer-2 framing, MAC delivery, VLAN tags, FCS | all endpoints, `switch`, `router`, `watch` |
| [ARP](protocols/arp.md) | IPv4-to-MAC resolution | `host`, `router`, `dns_server`, `watch` |
| [RARP](protocols/rarp.md) | configured MAC-to-IPv4 answer | `host`, `router`, `watch` |
| [IPv4](protocols/ipv4.md) | packet delivery and router forwarding | `host`, `router`, DHCP/DNS servers, `watch` |
| [IPv6](protocols/ipv6.md) | IPv6 addressing and packet carriage | `host`, `router` |
| [ICMP](protocols/icmp.md) | echo and IPv4 error feedback | `host`, `router`, `watch` |
| [ICMPv6](protocols/icmpv6.md) | IPv6 echo and NDP carriage | `host`, `router` |
| [NDP](protocols/ndp.md) | IPv6 neighbor/router discovery and SLAAC inputs | `host`, `router` |
| [UDP](protocols/udp.md) | datagrams for DHCP, DNS, and host traffic | `host`, `router`, DHCP/DNS servers, `watch` |
| [TCP](protocols/tcp.md) | basic connection/data exchange and BGP transport | `host`, `router` |
| [DHCP](protocols/dhcp.md) | dynamic IPv4 configuration | `host`, `dhcp_server`, `router` relay |
| [DNS](protocols/dns.md) | authoritative A/CNAME name lookup | `host`, `dns_server` |
| [RIP](protocols/rip.md) | periodic distance-vector routing | `router` |
| [OSPF](protocols/ospf.md) | compact link-state router updates | `router` |
| [BGP](protocols/bgp.md) | inter-domain-like peer updates over TCP | `router` |

## Targets by layer

```mermaid
flowchart TB
  subgraph L1[Layer 1 / simulated medium]
    C[link]
    H[hub]
  end
  subgraph L2[Layer 2]
    SW[switch]
    HOST[host]
    SVC[DHCP and DNS servers]
  end
  subgraph L3[Layer 3]
    R[router]
    HOST
    SVC
  end
  subgraph Observe[Observation]
    W[watch]
  end
  C --- H --- SW
  SW --- HOST
  SW --- SVC
  HOST --- R
  SVC --- R
  W -. decode any media .-> C
```

A real network device often performs several layers at once: a router must receive Ethernet, resolve a next-hop MAC, make an IP forwarding decision, and construct a new Ethernet frame. This diagram assigns each *target's teaching focus*, not an exclusive implementation layer.

## Implemented scope and intentional limits

| Area | Modeled | Deliberately simplified or omitted |
|---|---|---|
| Ethernet | preamble/SFD, II/802.3 distinction, padding, FCS, 802.1Q | physical signaling and NIC driver behavior |
| Switching | FDB learning, access/trunk VLAN policies, compact STP subset | full RSTP/MSTP, native/hybrid VLANs |
| IPv4/IPv6 | addressing, checksums, TTL/hop limit, local delivery | complete extension/option ecosystems and reassembly behavior |
| Routing | connected/static routes, RIP, OSPF-style updates, BGP peers, ACL/NAT | production control-plane convergence and policy breadth |
| Transport | UDP checksums; TCP base header, stateful virtual sockets | congestion control, retransmission, full TCP option/sequence semantics |
| Services | DHCPv4 offers/acks, authoritative A/CNAME DNS | DHCP lease timers and full option set; recursive DNS |

The limitation column is essential when using VNet to learn: a simplified model makes a mechanism visible, but should not be mistaken for all requirements of a production protocol implementation.
