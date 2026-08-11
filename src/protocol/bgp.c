#include <bgp.h>

#include <string.h>

#define BGP_ATTRIBUTE_FLAG_TRANSITIVE 0x40
#define BGP_ATTRIBUTE_ORIGIN 1
#define BGP_ATTRIBUTE_AS_PATH 2
#define BGP_ATTRIBUTE_NEXT_HOP 3
#define BGP_AS_SEQUENCE 2

static bool bgp_write_header(uint8_t type, uint16_t length, uint8_t* bytes, size_t capacity) {
  if (!bytes || capacity < length || length < BGP_HEADER_LENGTH || length > BGP_MAX_MESSAGE_LENGTH) return false;
  bgp_header_t header = {.length = length, .type = type};
  memset(header.marker, 0xFF, sizeof(header.marker));
  memcpy(bytes, &header, sizeof(header));
  return true;
}

static bool bgp_mask_prefix_length(ipv4_address_t mask, uint8_t* length) {
  if (!length || !ipv4_mask_is_contiguous(mask)) return false;
  uint8_t result = 0;
  while (mask) {
    result += mask & 1u;
    mask >>= 1;
  }
  *length = result;
  return true;
}

static void bgp_write_prefix(uint8_t* bytes, ipv4_address_t address, uint8_t length) {
  *bytes++ = length;
  for (uint8_t i = 0; i < (uint8_t)((length + 7) / 8); ++i) bytes[i] = (uint8_t)(address >> (i * 8));
}

static bool bgp_parse_prefix(const uint8_t* bytes, size_t length, ipv4_address_t* address, ipv4_address_t* mask, size_t* consumed) {
  if (!bytes || !address || !mask || !consumed || !length || bytes[0] > 32) return false;
  const uint8_t prefix_length = bytes[0];
  const size_t octets = (prefix_length + 7) / 8;
  if (length < 1 + octets) return false;
  *address = 0;
  for (size_t i = 0; i < octets; ++i) *address |= (ipv4_address_t)bytes[1 + i] << (i * 8);
  *mask = prefix_length == 0 ? 0 : UINT32_MAX >> (32 - prefix_length);
  *address &= *mask;
  *consumed = 1 + octets;
  return true;
}

bool bgp_write_open(uint16_t autonomous_system, ipv4_address_t identifier, uint8_t* bytes, size_t capacity, uint16_t* length) {
  if (!length || capacity < sizeof(bgp_open_t) || !bgp_write_header(BGP_MESSAGE_OPEN, sizeof(bgp_open_t), bytes, capacity)) return false;
  bgp_open_t message = {.version = BGP_VERSION, .autonomous_system = autonomous_system, .hold_time = BGP_HOLD_TIME_SECONDS, .identifier = identifier};
  memcpy(message.header.marker, bytes, BGP_MARKER_LENGTH);
  message.header.length = sizeof(message);
  message.header.type = BGP_MESSAGE_OPEN;
  memcpy(bytes, &message, sizeof(message));
  *length = sizeof(message);
  return true;
}

bool bgp_write_keepalive(uint8_t* bytes, size_t capacity, uint16_t* length) {
  if (!length || !bgp_write_header(BGP_MESSAGE_KEEPALIVE, BGP_HEADER_LENGTH, bytes, capacity)) return false;
  *length = BGP_HEADER_LENGTH;
  return true;
}

bool bgp_write_update(ipv4_address_t network, ipv4_address_t mask, ipv4_address_t next_hop, uint16_t autonomous_system, uint8_t* bytes, size_t capacity, uint16_t* length) {
  uint8_t prefix_length = 0;
  if (!length || !next_hop || !autonomous_system || (network & mask) != network || !bgp_mask_prefix_length(mask, &prefix_length)) return false;
  const uint16_t message_length = (uint16_t)(BGP_HEADER_LENGTH + 2 + 2 + 4 + 7 + 7 + 1 + (prefix_length + 7) / 8);
  if (!bgp_write_header(BGP_MESSAGE_UPDATE, message_length, bytes, capacity)) return false;
  uint8_t* cursor = bytes + BGP_HEADER_LENGTH;
  const uint16_t withdrawn_length = 0;
  const uint16_t attribute_length = 18;
  memcpy(cursor, &withdrawn_length, sizeof(withdrawn_length));
  cursor += sizeof(withdrawn_length);
  memcpy(cursor, &attribute_length, sizeof(attribute_length));
  cursor += sizeof(attribute_length);
  *cursor++ = BGP_ATTRIBUTE_FLAG_TRANSITIVE;
  *cursor++ = BGP_ATTRIBUTE_ORIGIN;
  *cursor++ = 1;
  *cursor++ = 0;
  *cursor++ = BGP_ATTRIBUTE_FLAG_TRANSITIVE;
  *cursor++ = BGP_ATTRIBUTE_AS_PATH;
  *cursor++ = 4;
  *cursor++ = BGP_AS_SEQUENCE;
  *cursor++ = 1;
  *(uint16_t*)cursor = autonomous_system;
  cursor += 2;
  *cursor++ = BGP_ATTRIBUTE_FLAG_TRANSITIVE;
  *cursor++ = BGP_ATTRIBUTE_NEXT_HOP;
  *cursor++ = sizeof(next_hop);
  memcpy(cursor, &next_hop, sizeof(next_hop));
  cursor += sizeof(next_hop);
  bgp_write_prefix(cursor, network, prefix_length);
  *length = message_length;
  return true;
}

bool bgp_parse_message(const uint8_t* bytes, size_t byte_count, bgp_message_view_t* message) {
  if (!bytes || !message || byte_count < sizeof(bgp_header_t)) return false;
  bgp_header_t header = {0};
  memcpy(&header, bytes, sizeof(header));
  if (memcmp(header.marker, "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF", BGP_MARKER_LENGTH) != 0 || header.length < BGP_HEADER_LENGTH || header.length > BGP_MAX_MESSAGE_LENGTH || header.length > byte_count || header.type < BGP_MESSAGE_OPEN || header.type > BGP_MESSAGE_KEEPALIVE) return false;
  if (header.type == BGP_MESSAGE_KEEPALIVE && header.length != BGP_HEADER_LENGTH) return false;
  if (header.type == BGP_MESSAGE_OPEN && (header.length != sizeof(bgp_open_t) || ((const bgp_open_t*)bytes)->version != BGP_VERSION || ((const bgp_open_t*)bytes)->optional_parameter_length != 0)) return false;
  *message = (bgp_message_view_t){.header = header, .payload = bytes + sizeof(header), .payload_length = (uint16_t)(header.length - sizeof(header))};
  return true;
}

bool bgp_parse_update(const bgp_message_view_t* message, bgp_update_t* update) {
  if (!message || !update || message->header.type != BGP_MESSAGE_UPDATE || message->payload_length < 4) return false;
  const uint8_t* cursor = message->payload;
  uint16_t withdrawn_length = 0;
  memcpy(&withdrawn_length, cursor, sizeof(withdrawn_length));
  cursor += sizeof(withdrawn_length);
  if (withdrawn_length || (size_t)(cursor - message->payload) + sizeof(uint16_t) > message->payload_length) return false;
  uint16_t attribute_length = 0;
  memcpy(&attribute_length, cursor, sizeof(attribute_length));
  cursor += sizeof(attribute_length);
  if ((size_t)(cursor - message->payload) + attribute_length >= message->payload_length) return false;
  const uint8_t* attributes_end = cursor + attribute_length;
  bool origin = false;
  bool as_path = false;
  bool next_hop = false;
  *update = (bgp_update_t){0};
  while (cursor < attributes_end) {
    if ((size_t)(attributes_end - cursor) < 3) return false;
    const uint8_t flags = *cursor++;
    const uint8_t type = *cursor++;
    const uint8_t attribute_size = *cursor++;
    if ((size_t)(attributes_end - cursor) < attribute_size) return false;
    if (type == BGP_ATTRIBUTE_ORIGIN) {
      if (flags != BGP_ATTRIBUTE_FLAG_TRANSITIVE || attribute_size != 1 || cursor[0] != 0) return false;
      origin = true;
    } else if (type == BGP_ATTRIBUTE_AS_PATH) {
      if (flags != BGP_ATTRIBUTE_FLAG_TRANSITIVE || attribute_size != 4 || cursor[0] != BGP_AS_SEQUENCE || cursor[1] != 1) return false;
      memcpy(&update->autonomous_system, cursor + 2, sizeof(update->autonomous_system));
      as_path = true;
    } else if (type == BGP_ATTRIBUTE_NEXT_HOP) {
      if (flags != BGP_ATTRIBUTE_FLAG_TRANSITIVE || attribute_size != sizeof(update->next_hop)) return false;
      memcpy(&update->next_hop, cursor, sizeof(update->next_hop));
      next_hop = true;
    }
    cursor += attribute_size;
  }
  size_t consumed = 0;
  if (!origin || !as_path || !next_hop || !bgp_parse_prefix(cursor, (size_t)(message->payload + message->payload_length - cursor), &update->network, &update->mask, &consumed) || cursor + consumed != message->payload + message->payload_length) return false;
  return true;
}
