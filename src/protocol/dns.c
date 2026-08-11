#include <dns.h>

#include <string.h>

static bool dns_name_is_valid(const char* name) {
  return name && *name && strlen(name) <= DNS_NAME_MAX;
}

static bool dns_record_type_is_supported(uint16_t type) {
  return type == DNS_RECORD_A || type == DNS_RECORD_CNAME;
}

static bool dns_record_is_valid(const dns_record_t* record) {
  if (!record || !dns_record_type_is_supported(record->type) || !dns_name_is_valid(record->name)) return false;
  if (record->type == DNS_RECORD_A) return record->data.address != 0;
  return memchr(record->data.name, '\0', sizeof(record->data.name)) && dns_name_is_valid(record->data.name);
}

bool dns_record_write_a(const char* name, ipv4_address_t address, dns_record_t* record) {
  if (!record || !dns_name_is_valid(name) || address == 0) return false;
  *record = (dns_record_t) {
      .type = DNS_RECORD_A,
      .data.address = address,
  };
  memcpy(record->name, name, strlen(name) + 1);
  return true;
}

bool dns_record_write_cname(const char* name, const char* target, dns_record_t* record) {
  if (!record || !dns_name_is_valid(name) || !dns_name_is_valid(target)) return false;
  *record = (dns_record_t) {
      .type = DNS_RECORD_CNAME,
  };
  memcpy(record->name, name, strlen(name) + 1);
  memcpy(record->data.name, target, strlen(target) + 1);
  return true;
}

bool dns_write_query(uint16_t transaction_id, uint16_t record_type, const char* name, dns_message_t* message) {
  if (!message || !dns_record_type_is_supported(record_type) || !dns_name_is_valid(name)) return false;
  *message = (dns_message_t) {
      .transaction_id = transaction_id,
      .type = DNS_MESSAGE_QUERY,
      .record.type = record_type,
  };
  memcpy(message->record.name, name, strlen(name) + 1);
  return true;
}

bool dns_write_response(uint16_t transaction_id, const char* name, const dns_record_t* record, dns_message_t* message) {
  if (!message || !dns_name_is_valid(name) || (record && !dns_record_is_valid(record))) return false;
  *message = (dns_message_t) {
      .transaction_id = transaction_id,
      .type = DNS_MESSAGE_RESPONSE,
      .response_code = record ? DNS_RESPONSE_OK : DNS_RESPONSE_NAME_ERROR,
  };
  if (record) {
    message->record = *record;
  } else {
    memcpy(message->record.name, name, strlen(name) + 1);
  }
  return true;
}

bool dns_parse_message(const uint8_t* bytes, size_t byte_count, dns_message_t* message) {
  if (!bytes || !message || byte_count != sizeof(*message)) return false;
  memcpy(message, bytes, sizeof(*message));
  if (!memchr(message->record.name, '\0', sizeof(message->record.name)) || !dns_name_is_valid(message->record.name)) return false;
  if (message->type == DNS_MESSAGE_QUERY) return message->response_code == DNS_RESPONSE_OK && dns_record_type_is_supported(message->record.type) && message->record.data.address == 0;
  if (message->type == DNS_MESSAGE_RESPONSE && message->response_code == DNS_RESPONSE_OK) return dns_record_is_valid(&message->record);
  return message->type == DNS_MESSAGE_RESPONSE && message->response_code == DNS_RESPONSE_NAME_ERROR && message->record.type == DNS_RECORD_NONE && message->record.data.address == 0;
}
