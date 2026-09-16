# TCP

TCP gives VNet a stateful transport contrast to UDP. The model contains a base TCP header, flags, sequence/acknowledgement fields, window size, checksum, and a compact virtual socket state machine.

| Surface | VNet behavior |
|---|---|
| Segment | serializes/parses source/destination ports, sequence/acknowledgement, flags, window, checksum, payload |
| Host command | `tcp <src_port> <dst_port> <dst_ip> -d <data> [-seq …] [-ack …] [-window …] [-flags …]` |
| Virtual sockets | `tcp-listen`, `tcp-connect`, `accept`, `send`, `receive`, `close` via public `socket.h` |
| Reliability | one unacknowledged segment is retained, retransmitted after a fixed timeout, and abandoned after three retries |
| Flow control | each segment advertises free space in the 1400-byte receive buffer; `receive` emits a window-update ACK |
| Congestion control | a compact congestion window starts at 512 bytes, grows on acknowledged data, and resets after retransmission loss |

The parser and serializer live in `src/protocol/tcp.{h,c}`; `src/socket_api/socket_tcp.c` is the private implementation selected by `socket.c`.

The host advances socket timers from its receive loop. The socket status display includes the peer-advertised window, congestion window, and slow-start threshold so their relationship is inspectable.

This remains a deliberately compact model: only one segment may be in flight, application sends are not segmented or queued, receive data must arrive in order, and the timeout is fixed rather than RTT-derived. There are no TCP options, selective acknowledgements, delayed ACKs, fast retransmit/recovery, ECN behavior, persist timers, or TIME-WAIT. It is suitable for observing the interaction of acknowledgements, receive windows, loss recovery, and a simplified slow-start/congestion-avoidance rule—not for measuring production TCP behavior.