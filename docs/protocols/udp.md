# UDP

UDP provides connectionless IPv4 transport in VNet. It carries DHCP and DNS as well as host-generated datagrams, showing that applications identify endpoints with ports in addition to IP addresses.

| Field/behavior | VNet model |
|---|---|
| Header | source port, destination port, length, checksum |
| Checksum | serialization and parsing receive IPv4 source/destination context |
| Encapsulation | UDP payload is carried in IPv4, then Ethernet II |
| Delivery | the socket API routes parsed datagrams to a bound virtual UDP socket |

`src/protocol/udp.{h,c}` exposes serializer, Ethernet packet writer, and parser. The host command `udp <src_port> <dst_port> <dst_ip> -d <data>` creates a datagram; the socket command supports `udp-open` and `udp-send`.

UDP in real networks has no delivery, ordering, or congestion guarantees; applications supply those if needed. VNet preserves that simple datagram boundary but uses bounded local buffers and a simulator socket context rather than OS UDP sockets.