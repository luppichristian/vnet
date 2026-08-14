# `hub` target

`hub` creates one shared Layer-1-like medium for several attachment files. It repeats bytes from every ingress port to every *other* port without inspecting MAC addresses or Ethernet protocol fields.

## Startup

```text
hub <file> -f <other files>
```

`<file>` is the hub-medium file; each file after `-f` is one port. All paths must be distinct. The target opens a reader for each port and an independent reader of the hub medium for each port, then writes bilateral VNet connection-start records.

## How it works

Each loop snapshots the ends of every source before forwarding. It stages port-to-hub traffic, then hub-to-port traffic, and advances opposite cursors over bytes it injected. That two-phase discipline prevents a port from reading its own echoed output in the same iteration.

| Layer concern | Hub behavior |
|---|---|
| MAC addresses | opaque; no filtering or learning |
| Ethernet frames | opaque; raw bytes are repeated |
| Delivery | every ingress reaches every other connected port |
| Simulator control | VNet lifecycle frames addressed locally are consumed |

Use `info` to list the hub and port files. In real Ethernet, hubs repeat electrical signals and form one collision domain; modern switched Ethernet has mostly replaced them. VNet's file-based hub models the repetition property, not collisions, half-duplex timing, or signal encoding.