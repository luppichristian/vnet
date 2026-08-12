#include "dhcp_service.h"

#include <string.h>

static bool address_is_usable(const dhcp_service_t* service, ipv4_address_t address) {
  return address >= service->first_address && address <= service->last_address && address != service->server_address;
}

void dhcp_service_init(dhcp_service_t* service, dhcp_lease_t* leases, size_t capacity) {
  *service = (dhcp_service_t) {.leases = leases, .capacity = capacity};
}

bool dhcp_service_configure(dhcp_service_t* service, ipv4_address_t server_address, ipv4_address_t first_address, ipv4_address_t last_address, ipv4_address_t mask, ipv4_address_t gateway, ipv4_address_t dns_server) {
  if (!service || !server_address || first_address > last_address || !ipv4_mask_is_contiguous(mask) || !ipv4_addresses_share_subnet(server_address, first_address, mask) || !ipv4_addresses_share_subnet(server_address, last_address, mask) || (gateway && !ipv4_addresses_share_subnet(server_address, gateway, mask))) return false;
  service->server_address = server_address;
  service->first_address = first_address;
  service->last_address = last_address;
  service->mask = mask;
  service->gateway = gateway;
  service->dns_server = dns_server;
  service->enabled = true;
  return true;
}

dhcp_lease_t* dhcp_service_find_client(dhcp_service_t* service, const mac_address_t client_mac) {
  for (size_t i = 0; i < service->count; ++i) if (memcmp(service->leases[i].client_mac, client_mac, sizeof(service->leases[i].client_mac)) == 0) return &service->leases[i];
  return NULL;
}

dhcp_lease_t* dhcp_service_find_address(dhcp_service_t* service, ipv4_address_t address) {
  for (size_t i = 0; i < service->count; ++i) if (service->leases[i].address == address) return &service->leases[i];
  return NULL;
}

static dhcp_lease_t* allocate(dhcp_service_t* service, const mac_address_t mac) {
  dhcp_lease_t* lease = dhcp_service_find_client(service, mac);
  if (lease) return lease;
  for (ipv4_address_t address = service->first_address; address <= service->last_address; ++address) {
    if (!address_is_usable(service, address) || dhcp_service_find_address(service, address)) continue;
    if (service->count == service->capacity) return NULL;
    lease = &service->leases[service->count++];
    *lease = (dhcp_lease_t) {.address = address};
    memcpy(lease->client_mac, mac, sizeof(lease->client_mac));
    return lease;
  }
  return NULL;
}

bool dhcp_service_offer(dhcp_service_t* service, const dhcp_message_t* discover, dhcp_message_t* offer) {
  if (!service || !service->enabled || !discover || discover->type != DHCP_MESSAGE_DISCOVER) return false;
  dhcp_lease_t* lease = allocate(service, discover->client_mac);
  return lease && dhcp_write_server_message(DHCP_MESSAGE_OFFER, discover->transaction_id, discover->client_mac, lease->address, service->server_address, service->mask, service->gateway, service->dns_server, offer);
}

bool dhcp_service_acknowledge(dhcp_service_t* service, const dhcp_message_t* request, dhcp_message_t* response) {
  if (!service || !service->enabled || !request || request->type != DHCP_MESSAGE_REQUEST || request->server_address != service->server_address) return false;
  dhcp_lease_t* lease = dhcp_service_find_client(service, request->client_mac);
  const uint8_t type = lease && lease->address == request->client_address ? DHCP_MESSAGE_ACK : DHCP_MESSAGE_NAK;
  return dhcp_write_server_message(type, request->transaction_id, request->client_mac, type == DHCP_MESSAGE_ACK ? lease->address : 0, service->server_address, service->mask, service->gateway, service->dns_server, response);
}

bool dhcp_service_reserve(dhcp_service_t* service, const mac_address_t client_mac, ipv4_address_t address) {
  if (!service || !service->enabled || !address_is_usable(service, address)) return false;
  dhcp_lease_t* other = dhcp_service_find_address(service, address);
  dhcp_lease_t* lease = dhcp_service_find_client(service, client_mac);
  if (other && other != lease) return false;
  if (!lease) { if (service->count == service->capacity) return false; lease = &service->leases[service->count++]; memcpy(lease->client_mac, client_mac, sizeof(lease->client_mac)); }
  lease->address = address; lease->reserved = true; return true;
}

bool dhcp_service_remove(dhcp_service_t* service, ipv4_address_t address) {
  dhcp_lease_t* lease = dhcp_service_find_address(service, address);
  if (!lease) return false;
  *lease = service->leases[--service->count];
  return true;
}
