# DHCP Target Refactor Plan

> **For Hermes:** Implement this plan incrementally with focused protocol and target verification.

**Goal:** Replace the one-client DHCP target with configurable, inspectable DHCP services that hosts discover on their LAN and routers can provide per interface.

**Architecture:** Keep DHCP as a first-class protocol/service module. A reusable DHCP service owns pools, options, and leases; the standalone `dhcp_server` target embeds it as a dedicated appliance, while `router` embeds the same service on selected LAN interfaces. Hosts remain DHCP clients and accept server-supplied configuration.

---

## Decisions

- **Router support:** yes. DHCP should be enabled per router interface because an interface owns the LAN, gateway identity, and broadcast domain. A router DHCP service must only answer requests received on its enabled interface; DHCP relay is separate future work.
- **Dedicated target:** retain `dhcp_server` as the simple dedicated-appliance target. It should use the shared service rather than duplicate DHCP logic.
- **Server authority:** when DHCP is enabled and an ACK is accepted, the server owns IPv4 address, mask, gateway, and DNS values for that lease. The host must not override those values during the exchange.
- **Host discovery:** remove the required hard-coded DHCP-server address. A DHCP-enabled host broadcasts DISCOVER, selects a valid OFFER, broadcasts REQUEST identifying that server, and accepts only the matching ACK/NAK.
- **Initial scope:** configurable pool range, subnet mask, gateway, DNS server, and static reservations. Lease expiry, renewal/rebinding, relay, persistence, and multiple-offer policy stay out of this pass unless required by the fixed protocol message.

## Refactor

1. **Extract a reusable DHCP service.**
   - Create a DHCP service/table module under `src/tables/` (or an equivalent first-class module consistent with existing tables).
   - Own server state, address-pool bounds, default options, reservation lookup, active leases, and allocation/release helpers.
   - Validate that pool and supplied gateway belong to the configured subnet; exclude server/interface addresses and reserved addresses from dynamic allocation.
   - Expand the DHCP fixed message only where needed to distinguish requested addresses and preserve the current discover/offer/request/ack contract.

2. **Make `dhcp_server` a configurable appliance.**
   - Replace its single `client_mac`/`client_address` fields and mandatory static lease CLI arguments with shared service state.
   - Add commands to show server configuration and all leases, configure pool/options, add/remove reservations, and remove/reclaim leases.
   - Keep startup configuration limited to network attachment, server MAC/IP, and optional initial service settings; configuration changes belong to interactive commands.

3. **Embed DHCP in `router`.**
   - Add DHCP service state per router interface, not one router-global pool.
   - Add commands to enable/disable DHCP on an interface, configure its range/mask/gateway/DNS, view its leases, and manage reservations/leases.
   - Dispatch DHCP UDP traffic locally before normal IPv4 routing. Emit OFFER/ACK on the ingress interface as LAN broadcasts/unicasts; never forward DHCP traffic between router interfaces.

4. **Refactor the host DHCP client.**
   - Replace `-dhcp <server-ip>` and the current hard prerequisite with a DHCP-client enable/disable setting.
   - Make `dhcp` start discovery only when enabled and the host has no manually configured IPv4 address.
   - Track one transaction and selected offer/server; verify MAC, transaction ID, selected server, and offered address before applying an ACK.
   - Treat manual `config ip4|mask|gateway|dns` changes as static configuration and clear/disable any active DHCP lease state. DHCP ACKs atomically replace the full IPv4 configuration.

5. **Update target help and protocol documentation.**
   - Document DHCP as a local-LAN service, router per-interface ownership, appliance-vs-router target roles, and the host configuration precedence rules.

## Likely Files

- Modify: `src/protocol/dhcp.h`, `src/protocol/dhcp.c`
- Create: shared DHCP service/table header and implementation under `src/tables/`
- Modify: `src/targets/dhcp_server.h`, `src/targets/dhcp_server.c`
- Modify: `src/targets/router.h`, `src/targets/router.c`
- Modify: `src/targets/host.h`, `src/targets/host.c`
- Modify: `project.bbs` only if the new shared module does not already match `src/tables/*.c`

## Validation

- Build all affected targets with `bbs build -t host`, `bbs build -t dhcp_server`, and `bbs build -t router`.
- Prove a host obtains address, mask, gateway, and DNS through discovery without a configured server IP.
- Prove two dynamic clients receive distinct addresses; a reservation receives its fixed address; a released lease can be reclaimed.
- Prove a router DHCP service answers only on its enabled interface and DHCP traffic is not routed to another interface.
- Prove manual host static configuration and DHCP lease application follow the defined precedence rules.
