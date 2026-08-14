# ICMP

ICMP is IPv4 control and diagnostic traffic. VNet uses it for Echo Request/Reply (`ping`) and for router-generated error payloads, which makes reachability and forwarding failures observable without an application protocol.

| Feature | VNet model |
|---|---|
| Echo | identifier, sequence, and data are serialized and verified for request/reply |
| Errors | error header/payload builder represents IPv4 control failures |
| Checksums | ICMP checksum is generated/validated as part of packet parsing |
| Carriage | ICMP is IPv4 protocol traffic inside Ethernet II |

`src/protocol/icmp.{h,c}` offers packet writers, parser helpers, and error classification. The host command `ping <ip>` resolves ARP first; the router can generate relevant feedback while handling forwarding.

A production host handles many ICMP types, rate limits, filtering rules, PMTU behavior, and security policies. The simulator implements a teachable subset—enough to separate "the packet was sent" from "the network reported an IP-level outcome."