#include <dhcp.h>

#include <string.h>

static bool dhcp_client_type_is_valid(uint8_t type) {
  return type == DHCP_MESSAGE_DISCOVER || type == DHCP_MESSAGE_REQUEST;
}

static bool dhcp_server_type_is_valid(uint8_t type) {
  return type == DHCP_MESSAGE_OFFER || type == DHCP_MESSAGE_ACK || type == DHCP_MESSAGE_NAK;
}

bool dhcp_write_client_message(uint8_t type, uint16_t transaction_id, const mac_address_t client_mac, ipv4_address_t client_address, ipv4_address_t server_address, dhcp_message_t* message) {
  if (!message || !client_mac || !dhcp_client_type_is_valid(type) || (type == DHCP_MESSAGE_DISCOVER && (client_address || server_address)) || (type == DHCP_MESSAGE_REQUEST && (!client_address || !server_address))) return false;
  *message = (dhcp_message_t) {
      .type = type,
      .transaction_id = transaction_id,
      .client_address = client_address,
      .server_address = server_address,
  };
  memcpy(message->client_mac, client_mac, sizeof(message->client_mac));
  return true;
}

bool dhcp_write_server_message(uint8_t type, uint16_t transaction_id, const mac_address_t client_mac, ipv4_address_t client_address, ipv4_address_t server_address, ipv4_address_t subnet_mask, ipv4_address_t gateway, ipv4_address_t dns_server, dhcp_message_t* message) {
  if (!message || !client_mac || !dhcp_server_type_is_valid(type) || !server_address || (type != DHCP_MESSAGE_NAK && (!client_address || !ipv4_mask_is_contiguous(subnet_mask)))) return false;
  *message = (dhcp_message_t) {
      .type = type,
      .transaction_id = transaction_id,
      .client_address = client_address,
      .server_address = server_address,
      .subnet_mask = subnet_mask,
      .gateway = gateway,
      .dns_server = dns_server,
  };
  memcpy(message->client_mac, client_mac, sizeof(message->client_mac));
  return true;
}

bool dhcp_parse_message(const uint8_t* bytes, size_t byte_count, dhcp_message_t* message) {
  if (!bytes || !message || byte_count != sizeof(*message)) return false;
  memcpy(message, bytes, sizeof(*message));
  if (message->reserved != 0 || (!dhcp_client_type_is_valid(message->type) && !dhcp_server_type_is_valid(message->type))) return false;
  if (message->type == DHCP_MESSAGE_DISCOVER) return !message->client_address && !message->server_address;
  if (message->type == DHCP_MESSAGE_REQUEST) return message->client_address && message->server_address;
  if (message->type == DHCP_MESSAGE_NAK) return message->server_address != 0;
  return message->client_address && message->server_address && ipv4_mask_is_contiguous(message->subnet_mask);
}
