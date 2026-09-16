# TCP

TCP gives VNet a stateful transport contrast to UDP. The model contains a base TCP header, flags, sequence/acknowledgement fields, window size, checksum, and a compact virtual socket state machine.

| Surface | VNet behavior |
|---|---|
| Segment | serializes/parses source/destination ports, sequence/acknowledgement, flags, window, checksum, payload |
| Host command | `tcp <src_port> <dst_port> <dst_ip> -d <data> [-seq …] [-ack …] [-window …] [-flags …]` |
| Virtual sockets | `tcp-listen`, `tcp-connect`, `accept`, `send`, `receive`, `close` via public `socket.h` |
| Router | router owns TCP socket contexts through the public socket API |

The parser and serializer live in `src/protocol/tcp.{h,c}`; `src/socket_api/socket_tcp.c` is the private implementation selected by `socket.c`.

Real TCP has sophisticated retransmission, congestion/flow control, options, segmentation, and robust state transitions. VNet is intentionally a base-header and local-socket learning model, suitable for seeing port demultiplexing and a simplified connection flow—not for measuring production TCP behavior.