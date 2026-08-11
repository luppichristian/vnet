#include <dns.h>

#include <string.h>

static bool dns_name_is_valid(const char* name) {
  return name && *name && strlen(name) <= DNS_NAME_MAX;
}

bool dns_write_query(uint16_t transaction_id, const char* name, dns_message_t* message) {
  if (!message || !dns_name_is_valid(name)) return false;
  *message = (dns_message_t) {
      .transaction_id = transaction_id,
      .type = DNS_MESSAGE_QUERY,
  };
  memcpy(message->name, name, strlen(name) + 1);
  return true;
}

bool dns_write_response(uint16_t transaction_id, const char* name, ipv4_address_t address, dns_message_t* message) {
  if (!message || !dns_name_is_valid(name)) return false;
  *message = (dns_message_t) {
      .transaction_id = transaction_id,
      .type = DNS_MESSAGE_RESPONSE,
      .response_code = address ? DNS_RESPONSE_OK : DNS_RESPONSE_NAME_ERROR,
      .address = address,
  };
  memcpy(message->name, name, strlen(name) + 1);
  return true;
}

bool dns_parse_message(const uint8_t* bytes, size_t byte_count, dns_message_t* message) {
  if (!bytes || !message || byte_count != sizeof(*message)) return false;
  memcpy(message, bytes, sizeof(*message));
  return (message->type == DNS_MESSAGE_QUERY || message->type == DNS_MESSAGE_RESPONSE) && (message->type == DNS_MESSAGE_QUERY ? message->response_code == DNS_RESPONSE_OK && message->address == 0 : (message->response_code == DNS_RESPONSE_OK || message->response_code == DNS_RESPONSE_NAME_ERROR) && (message->response_code == DNS_RESPONSE_OK ? message->address != 0 : message->address == 0)) && memchr(message->name, '\0', sizeof(message->name)) && dns_name_is_valid(message->name);
}
