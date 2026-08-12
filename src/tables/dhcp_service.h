#pragma once

#include <dhcp.h>

#include <stdbool.h>
#include <stddef.h>

/*
====================
DHCP Lease Service
====================
A DHCP service owns one Layer-2 network's IPv4 pool, DHCP options, reservations,
and active leases. Targets supply storage and decide which local interface receives
DHCP broadcasts; this module does not read or write network files.
*/
typedef struct dhcp_lease {
  mac_address_t client_mac;
  ipv4_address_t address;
  bool reserved;
} dhcp_lease_t;

typedef struct dhcp_service {
  dhcp_lease_t* leases;
  size_t capacity;
  size_t count;
  ipv4_address_t server_address;
  ipv4_address_t first_address;
  ipv4_address_t last_address;
  ipv4_address_t mask;
  ipv4_address_t gateway;
  ipv4_address_t dns_server;
  bool enabled;
} dhcp_service_t;

/* Binds caller-owned lease storage to a disabled DHCP service. */
void dhcp_service_init(dhcp_service_t* service, dhcp_lease_t* leases, size_t capacity);

/* Configures one enabled service. Pool, server, and nonzero gateway must share the subnet. */
bool dhcp_service_configure(dhcp_service_t* service, ipv4_address_t server_address, ipv4_address_t first_address, ipv4_address_t last_address, ipv4_address_t mask, ipv4_address_t gateway, ipv4_address_t dns_server);

/* Finds an active lease or reservation by client MAC or address. */
dhcp_lease_t* dhcp_service_find_client(dhcp_service_t* service, const mac_address_t client_mac);
dhcp_lease_t* dhcp_service_find_address(dhcp_service_t* service, ipv4_address_t address);

/* Chooses or retains a client address and writes the corresponding OFFER. */
bool dhcp_service_offer(dhcp_service_t* service, const dhcp_message_t* discover, dhcp_message_t* offer);

/* Confirms a selected offer and writes ACK; otherwise writes NAK for that server. */
bool dhcp_service_acknowledge(dhcp_service_t* service, const dhcp_message_t* request, dhcp_message_t* response);

/* Adds/replaces a static MAC reservation inside the configured pool. */
bool dhcp_service_reserve(dhcp_service_t* service, const mac_address_t client_mac, ipv4_address_t address);

/* Removes one lease or reservation selected by address. */
bool dhcp_service_remove(dhcp_service_t* service, ipv4_address_t address);
