# `dns_server` target

`dns_server` is an interactive authoritative A/CNAME DNS appliance attached to one Ethernet LAN. It owns its record and blacklist tables and responds only after receiving a unicast Ethernet/IPv4/UDP DNS query for its configured address.

## Startup

```text
dns_server <file> <mac-address> <ip-address> <A|CNAME> <name> <address|target> [...records]
```

Every initial record is a three-argument group. An A record uses an IPv4 address; a CNAME record uses another name.

## State and commands

| Command | Purpose |
|---|---|
| `info` | address/MAC, authoritative records, blacklist |
| `record add <A|CNAME> <name> <address|target>` | add or replace a record |
| `record delete <A|CNAME> <name>` | remove a record |
| `blacklist add <name>` / `blacklist delete <name>` | block/allow an exact case-insensitive name |

The implementation validates Ethernet II, IPv4, UDP, destination port 53, and a DNS query before composing its response. A blacklist check occurs before record lookup, so a blocked record yields the same simulated name-error result as an unknown name rather than leaking the record.

A real authoritative server supports zones, many RR types, compression, DNSSEC, TCP, transfers, and operational controls; a recursive resolver additionally follows delegations/caches results. VNet purposely narrows the surface to make A/CNAME answers and UDP/IP encapsulation easy to study. Configure the host with `-dns <server-ip>` and use `dns <name>`.