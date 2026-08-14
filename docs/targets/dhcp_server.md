# `dhcp_server` target

`dhcp_server` is a configurable DHCPv4 appliance on one Ethernet LAN. It owns address-pool and lease/reservation state; the router only relays DHCP when configured, rather than embedding server state.

## Startup

```text
dhcp_server <file> <mac-address> <server-ip>
```

The target tails the attachment media, accepts IPv4/UDP traffic for server port 67, parses DHCP messages, and replies to DISCOVER/REQUEST exchanges using its configured pool/options.

## State and commands

| State | Meaning |
|---|---|
| server MAC/IP | the service's Ethernet and IPv4 identity |
| pool | inclusive first/last client address range |
| supplied options | subnet mask, default gateway, DNS server |
| lease table | bounded MAC/address mappings; entries can be reserved |

```text
info
config <first-ip> <last-ip> <mask> <gateway> <dns>
lease list
lease reserve <mac> <ip>
lease delete <ip>
```

The response is carried as UDP 67→68 inside IPv4/Ethernet, preserving the request transaction ID and client MAC identity. A DHCP client normally broadcasts until it has usable configuration.

Real DHCP includes lease timers, renew/rebind, option negotiation, persistence, relay-agent fields, failover, and security controls. VNet focuses on the address-selection and option-delivery flow students need to observe. Pair it with `host -dhcp <server-ip>` and `host`'s `dhcp` command; decode with `watch`.