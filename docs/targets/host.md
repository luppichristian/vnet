# `host` target

`host` is an interactive Ethernet endpoint. It is the main traffic generator and receiver for labs: it owns MAC/IPv4 configuration, ARP neighbor state, pending packets awaiting resolution, and a virtual TCP/UDP socket context.

## Startup

```text
host <file> <mac-address> [-ip4 <address> [-mask <address>] [-gateway <address>] [-dns <address>] [-dhcp <address>]
```

| Option | Effect |
|---|---|
| `<file>` / `<mac-address>` | append-only attachment medium and endpoint Layer-2 identity |
| `-ip4`, `-mask`, `-gateway` | IPv4 address, local subnet, and off-link next hop |
| `-dns` | DNS server address for `dns` queries |
| `-dhcp <address>` | DHCP server setting; then use `dhcp` to request configuration |

It opens the file at EOF, starts a receive thread, initializes ARP and socket tables, and accepts Ethernet frames for its unicast MAC as well as relevant broadcast/multicast traffic. It dispatches ARP, RARP, IPv4, ICMP, UDP, TCP, DHCP, and DNS work.

## Commands

| Command | Purpose |
|---|---|
| `info` | configuration plus peers, ARP, sockets, and pending state |
| `config` | change IPv4/mask/gateway/DNS/DHCP settings |
| `arp`, `arp-delete` | resolve or remove an IPv4 neighbor |
| `rarp`, `dhcp` | request IPv4 configuration through legacy RARP or DHCPv4 |
| `dns <name>` | query configured authoritative DNS server |
| `ping <ip>` | ICMP echo after ARP resolution |
| `udp …`, `tcp …` | construct a direct transport packet |
| `socket …` | `info`, `udp-open`, `tcp-listen`, `tcp-connect`, `udp-send`, `send`, `accept`, `receive`, `close` |

## Learning focus and limits

The target is deliberately explicit: traffic requiring a next-hop MAC is held until ARP completes. A real host delegates much of this to its kernel/NIC and implements richer TCP, address lifetimes, and security behavior. Here the state is visible through `info` and frames through `watch`.

Use it with [`router`](router.md), [`dhcp_server`](dhcp_server.md), and [`dns_server`](dns_server.md).
