#include <ipv6.h>

#include <ipv4.h>

#include <string.h>

static int hex_value(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

static bool parse_group(const char* begin, const char* end, uint16_t* value) {
  if (!begin || !end || begin == end || (size_t)(end - begin) > 4) return false;
  uint16_t parsed = 0;
  for (const char* cursor = begin; cursor < end; ++cursor) {
    const int digit = hex_value(*cursor);
    if (digit < 0) return false;
    parsed = (uint16_t)((parsed << 4) | (uint16_t)digit);
  }
  *value = parsed;
  return true;
}

static bool parse_groups(const char* begin, const char* end, uint16_t* groups, size_t* count) {
  *count = 0;
  if (begin == end) return true;
  const char* cursor = begin;
  while (cursor < end) {
    const char* next = cursor;
    while (next < end && *next != ':') ++next;
    if (*count == 8 || !parse_group(cursor, next, &groups[(*count)++])) return false;
    if (next == end) break;
    cursor = next + 1;
    if (cursor == end) return false;
  }
  return true;
}

bool ipv6_parse_address(const char* text, ipv6_address_t* address) {
  if (!text || !address) return false;
  const char* gap = strstr(text, "::");
  if (gap && strstr(gap + 2, "::")) return false;

  uint16_t groups[8] = {0};
  size_t left_count = 0;
  size_t right_count = 0;
  const char* end = text + strlen(text);
  if (gap) {
    if (!parse_groups(text, gap, groups, &left_count)) return false;
    if (!parse_groups(gap + 2, end, groups + 8, &right_count)) return false;
    if (left_count + right_count > 8) return false;
    for (size_t i = 0; i < right_count; ++i) {
      groups[8 - right_count + i] = groups[8 + i];
    }
    for (size_t i = left_count; i < 8 - right_count; ++i) groups[i] = 0;
  } else if (!parse_groups(text, end, groups, &left_count) || left_count != 8) {
    return false;
  }

  for (size_t i = 0; i < 8; ++i) {
    address->bytes[i * 2] = (uint8_t)(groups[i] >> 8);
    address->bytes[i * 2 + 1] = (uint8_t)(groups[i] & 0xFFu);
  }
  return true;
}

bool ipv6_address_is_unspecified(const ipv6_address_t* address) {
  static const ipv6_address_t zero = {0};
  return ipv6_address_equal(address, &zero);
}

bool ipv6_address_is_link_local(const ipv6_address_t* address) {
  return address && address->bytes[0] == 0xFEu && (address->bytes[1] & 0xC0u) == 0x80u;
}

bool ipv6_address_is_multicast(const ipv6_address_t* address) {
  return address && address->bytes[0] == 0xFFu;
}

bool ipv6_address_equal(const ipv6_address_t* left, const ipv6_address_t* right) {
  return left && right && memcmp(left->bytes, right->bytes, sizeof(left->bytes)) == 0;
}

bool ipv6_address_in_prefix(const ipv6_address_t* address, const ipv6_address_t* prefix, uint8_t prefix_length) {
  if (!address || !prefix || prefix_length > 128) return false;
  const size_t whole_bytes = prefix_length / 8;
  const uint8_t remaining_bits = (uint8_t)(prefix_length % 8);
  if (whole_bytes > 0 && memcmp(address->bytes, prefix->bytes, whole_bytes) != 0) return false;
  if (!remaining_bits) return true;
  const uint8_t mask = (uint8_t)(0xFFu << (8 - remaining_bits));
  return (address->bytes[whole_bytes] & mask) == (prefix->bytes[whole_bytes] & mask);
}

void ipv6_address_copy(ipv6_address_t* destination, const ipv6_address_t* source) {
  if (destination && source) memcpy(destination->bytes, source->bytes, sizeof(destination->bytes));
}

void ipv6_address_print(FILE* destination, const ipv6_address_t* address) {
  uint16_t groups[8] = {0};
  size_t best_start = 8;
  size_t best_length = 0;
  size_t current_start = 0;
  size_t current_length = 0;
  for (size_t i = 0; i < 8; ++i) {
    groups[i] = (uint16_t)(((uint16_t)address->bytes[i * 2] << 8) | address->bytes[i * 2 + 1]);
    if (groups[i] == 0) {
      if (!current_length) current_start = i;
      ++current_length;
      if (current_length > best_length) {
        best_start = current_start;
        best_length = current_length;
      }
    } else {
      current_length = 0;
    }
  }
  if (best_length < 2) best_start = 8;
  for (size_t i = 0; i < 8; ++i) {
    if (i == best_start) {
      fputs(i == 0 ? "::" : ":", destination);
      i += best_length - 1;
      if (i == 7) break;
      continue;
    }
    if (i > 0) fputc(':', destination);
    fprintf(destination, "%x", groups[i]);
  }
}

void ipv6_interface_identifier_from_mac(const mac_address_t mac, uint8_t interface_identifier[8]) {
  interface_identifier[0] = (uint8_t)(mac[0] ^ 0x02u);
  interface_identifier[1] = mac[1];
  interface_identifier[2] = mac[2];
  interface_identifier[3] = 0xFFu;
  interface_identifier[4] = 0xFEu;
  interface_identifier[5] = mac[3];
  interface_identifier[6] = mac[4];
  interface_identifier[7] = mac[5];
}

void ipv6_link_local_from_mac(const mac_address_t mac, ipv6_address_t* address) {
  memset(address, 0, sizeof(*address));
  address->bytes[0] = 0xFEu;
  address->bytes[1] = 0x80u;
  ipv6_interface_identifier_from_mac(mac, address->bytes + 8);
}

bool ipv6_slaac_address_from_prefix(const ipv6_address_t* prefix, uint8_t prefix_length, const mac_address_t mac, ipv6_address_t* address) {
  if (!prefix || !address || prefix_length != 64) return false;
  memset(address, 0, sizeof(*address));
  memcpy(address->bytes, prefix->bytes, 8);
  ipv6_interface_identifier_from_mac(mac, address->bytes + 8);
  return true;
}

void ipv6_ula_prefix_from_ipv4_network(uint32_t network, ipv6_address_t* prefix) {
  memset(prefix, 0, sizeof(*prefix));
  prefix->bytes[0] = 0xFDu;
  prefix->bytes[2] = (uint8_t)(network & 0xFFu);
  prefix->bytes[3] = (uint8_t)((network >> 8) & 0xFFu);
  prefix->bytes[4] = (uint8_t)((network >> 16) & 0xFFu);
  prefix->bytes[5] = (uint8_t)((network >> 24) & 0xFFu);
}

void ipv6_multicast_mac(const ipv6_address_t* address, mac_address_t mac) {
  mac[0] = 0x33u;
  mac[1] = 0x33u;
  mac[2] = address->bytes[12];
  mac[3] = address->bytes[13];
  mac[4] = address->bytes[14];
  mac[5] = address->bytes[15];
}

void ipv6_solicited_node_multicast(const ipv6_address_t* target, ipv6_address_t* multicast) {
  memset(multicast, 0, sizeof(*multicast));
  multicast->bytes[0] = 0xFFu;
  multicast->bytes[1] = 0x02u;
  multicast->bytes[11] = 0x01u;
  multicast->bytes[12] = 0xFFu;
  multicast->bytes[13] = target->bytes[13];
  multicast->bytes[14] = target->bytes[14];
  multicast->bytes[15] = target->bytes[15];
}

void ipv6_solicited_node_multicast_mac(const ipv6_address_t* target, mac_address_t mac) {
  ipv6_address_t group = {0};
  ipv6_solicited_node_multicast(target, &group);
  ipv6_multicast_mac(&group, mac);
}

bool ipv6_write_ethernet_packet(FILE* destination, const ipv6_packet_data_t* packet_data) {
  if (!destination || !packet_data || packet_data->data_length > ETHERNET_MAX_DATA_LEN - sizeof(ipv6_header_t)) return false;
  uint8_t packet[sizeof(ipv6_header_t) + ETHERNET_MAX_DATA_LEN] = {0};
  ipv6_header_t header = {
      .version_traffic_class_flow_label = IPV6_VERSION_FIELD << 28,
      .payload_length = packet_data->data_length,
      .next_header = packet_data->next_header,
      .hop_limit = packet_data->hop_limit ? packet_data->hop_limit : IPV6_DEFAULT_HOP_LIMIT,
      .src_addr = packet_data->src_addr,
      .dst_addr = packet_data->dst_addr,
  };
  memcpy(packet, &header, sizeof(header));
  memcpy(packet + sizeof(header), packet_data->data, packet_data->data_length);
  ethernet_frame_data_t frame = {
      .type_or_length = ETHERNET_ETHERTYPE_IPV6,
      .data_length = (uint16_t)(sizeof(header) + packet_data->data_length),
      .data = packet,
  };
  memcpy(frame.dst_addr, packet_data->dst_mac_addr, sizeof(frame.dst_addr));
  memcpy(frame.src_addr, packet_data->src_mac_addr, sizeof(frame.src_addr));
  return ethernet_write_frame(destination, &frame);
}

bool ipv6_parse_packet(const uint8_t* bytes, size_t byte_count, ipv6_packet_view_t* packet) {
  if (!bytes || !packet || byte_count < sizeof(packet->header)) return false;
  memcpy(&packet->header, bytes, sizeof(packet->header));
  if ((packet->header.version_traffic_class_flow_label >> 28) != IPV6_VERSION_FIELD || byte_count < sizeof(packet->header) + packet->header.payload_length) return false;
  packet->payload = bytes + sizeof(packet->header);
  packet->payload_length = packet->header.payload_length;
  return true;
}
