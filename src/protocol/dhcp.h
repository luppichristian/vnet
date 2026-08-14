#pragma once

#include <ethernet.h>
#include <ipv4.h>

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/*
===============================================
Dynamic Host Configuration Protocol Version 4
===============================================
DHCP is an application-layer configuration protocol carried by UDP. A host
without an address broadcasts a DISCOVER from UDP port 68 to server port 67;
a server offers an address, the host requests it, and the server acknowledges
the lease. Before assignment, the IPv4 source address is zero and delivery uses
Ethernet and IPv4 broadcast. Routers need relay-agent behaviour to carry those
broadcasts across interfaces; the VNet router target can now relay them while
the DHCP message format itself remains the same fixed record.

  Ethernet II data: IPv4 header | UDP header | DHCP VNet message

The real DHCPv4 BOOTP header has variable options. This simulator keeps the
same four-step state transition and the address/mask/router/DNS configuration,
but uses a fixed compiler-local record instead of BOOTP options. It omits
lease timers, renewal/rebinding, BOOTP relay-agent options, client identifiers,
option negotiation, decline/release, and persistent lease storage.
*/

#define DHCP_SERVER_UDP_PORT 67
#define DHCP_CLIENT_UDP_PORT 68

#define DHCP_MESSAGE_DISCOVER 1
#define DHCP_MESSAGE_OFFER    2
#define DHCP_MESSAGE_REQUEST  3
#define DHCP_MESSAGE_ACK      5
#define DHCP_MESSAGE_NAK      6

#pragma pack(push, 1)

typedef struct dhcp_message {
  /* DHCP DISCOVER, OFFER, REQUEST, ACK, or NAK. */
  uint8_t type;

  /* Reserved so fixed records preserve natural protocol-field grouping. */
  uint8_t reserved;

  /* Client-selected value copied by every response in the exchange. */
  uint16_t transaction_id;

  /* Link-layer identity used by the server to choose or confirm a lease. */
  mac_address_t client_mac;

  /* Offered/requested client IPv4 address; zero in DISCOVER. */
  ipv4_address_t client_address;

  /* Address of the DHCP server producing OFFER, ACK, or NAK. */
  ipv4_address_t server_address;

  /* IPv4 configuration supplied with an OFFER or ACK. */
  ipv4_address_t subnet_mask;
  ipv4_address_t gateway;
  ipv4_address_t dns_server;
} dhcp_message_t;

#pragma pack(pop)

_Static_assert(sizeof(dhcp_message_t) == 30, "DHCP VNet message size must remain fixed");

/* Builds one DHCP DISCOVER or REQUEST. REQUEST names the offered server and address. */
bool dhcp_write_client_message(uint8_t type, uint16_t transaction_id, const mac_address_t client_mac, ipv4_address_t client_address, ipv4_address_t server_address, dhcp_message_t* message);

/* Builds one server OFFER, ACK, or NAK and includes the configured IPv4 parameters. */
bool dhcp_write_server_message(uint8_t type, uint16_t transaction_id, const mac_address_t client_mac, ipv4_address_t client_address, ipv4_address_t server_address, ipv4_address_t subnet_mask, ipv4_address_t gateway, ipv4_address_t dns_server, dhcp_message_t* message);

/* Validates and decodes one complete VNet DHCP message. */
bool dhcp_parse_message(const uint8_t* bytes, size_t byte_count, dhcp_message_t* message);
