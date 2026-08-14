# DNS

DNS converts a name into an address. VNet implements a small authoritative DNS service so name lookup becomes a visible UDP/IP/Ethernet exchange instead of a hidden library call.

| Capability | VNet model |
|---|---|
| Records | A (IPv4 address) and CNAME (alias target) |
| Query/response | transaction ID, query/response type, record representation |
| Server | configured address/MAC, bounded record table, case-insensitive blacklist |
| Client | `host` command `dns <name>` sends to its configured DNS server |

The format is in `src/protocol/dns.{h,c}`; `dns_server` validates Ethernet, IPv4, UDP port 53, and DNS query input before replying. Configure records at startup or through `record`; `blacklist add|delete <name>` forces a simulated name-error response before lookup.

This is not a recursive resolver: there are no root/TLD referrals, caching, DNSSEC, TCP fallback, or public Internet names. That intentional limit lets a student isolate authoritative lookup and the relationship between application data, UDP ports, IP, and ARP.