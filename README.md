# VNet

[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux-blue)](https://github.com/luppichristian/vnet)
[![Language](https://img.shields.io/badge/language-C17-00599C)](https://github.com/luppichristian/vnet)
[![Build](https://img.shields.io/badge/build-bbs-orange)](https://github.com/luppichristian/bbs)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)

VNet is an inspectable native simulator for learning how IP networks work. Instead of hiding traffic behind an operating-system socket stack, it represents a medium as an append-only file: targets append frames to transmit and tail new bytes to receive. That makes every address-resolution, forwarding, VLAN, routing, and application exchange available to inspect.

## What VNet models

- Ethernet II and IEEE 802.3 framing, FCS validation, MAC delivery, and 802.1Q VLAN tags
- IPv4 and IPv6 packet handling with ARP, RARP, ICMP, ICMPv6, and Neighbor Discovery
- Endpoint traffic through virtual UDP/TCP sockets, ping, DHCPv4, and authoritative DNS A/CNAME records
- Layer-1/2 topologies through configurable links, hubs, learning switches, VLAN policies, and a compact spanning-tree subset
- Router forwarding with connected/static routes, RIP, OSPF-style updates, BGP peers, ACLs, NAT/PAT, DHCP relay, and VLAN subinterfaces
- A passive `watch` target that dissects VNet lifecycle records and nested protocol frames

The simulator is intentionally educational rather than RFC-complete. It retains protocol headers, tables, checksums, and state transitions that explain a network exchange while leaving hardware, kernel integration, and many production edge cases out of scope.

## Quick start

VNet uses [bbs](https://github.com/luppichristian/bbs) for C17 builds. From the repository root:

```bash
bbs build
```

Create a media file, then start a host and a watcher in separate terminals:

```bash
: > lan.bin
bbs run -t host -a lan.bin 02:00:00:00:00:01 -ip4 192.0.2.10 -mask 255.255.255.0
bbs run -t watch -a lan.bin
```

The host has an interactive command loop. Use `help` to discover commands and `info` to view current configuration and tables. Add a second host to the same medium, then use `ping`, `udp`, or the virtual-socket commands to generate traffic and inspect the resulting frames with `watch`.

## Documentation

The documentation is organized for students who want to relate a packet capture to the implementation:

| Guide | Covers |
|---|---|
| [Simulating networks](docs/simulating_networks.md) | file media, complete topology examples, services, and experiments |
| [Protocol hierarchy](docs/protocol_hierarchy.md) | stack placement, protocol dependencies, and target ownership |
| [`docs/protocols`](docs/protocols/) | Ethernet through BGP, including scope versus real implementations |
| [`docs/targets`](docs/targets/) | hosts, links, hubs, switches, routers, services, and the watcher |

## License

VNet is licensed under the [MIT License](LICENSE).
