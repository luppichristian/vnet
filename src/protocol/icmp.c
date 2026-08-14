#include <icmp.h>
#include <math.h>
#include <string.h>

bool icmp_type_is_error(uint8_t type) {
  switch (type) {
    case ICMP_TYPE_DESTINATION_UNREACHABLE:
    case 4:
    case 5:
    case ICMP_TYPE_TIME_EXCEEDED:
    case 12: return true;
  }
  return false;
}

bool icmp_packet_is_error(const uint8_t* bytes, size_t byte_count) {
  icmp_header_t header = {0};
  if (byte_count < sizeof(header) || checksum16(bytes, byte_count) != 0) {
    return false;
  }
  memcpy(&header, bytes, sizeof(header));
  return icmp_type_is_error(header.type);
}

bool icmp_write_error_payload(
    uint8_t* destination,
    size_t destination_size,
    const ipv4_header_t* quoted_header,
    const uint8_t* quoted_payload,
    uint16_t quoted_payload_length,
    uint8_t type,
    uint8_t code,
    uint16_t* payload_length) {
  const uint16_t quote_length = quoted_payload_length < ICMP_ERROR_QUOTE_DATA_LEN ? quoted_payload_length : ICMP_ERROR_QUOTE_DATA_LEN;
  const size_t total_length = sizeof(icmp_error_header_t) + sizeof(*quoted_header) + quote_length;
  if (!destination || !quoted_header || !payload_length || destination_size < total_length || !icmp_type_is_error(type)) {
    return false;
  }
  icmp_error_header_t header = {.type = type, .code = code};
  memcpy(destination, &header, sizeof(header));
  memcpy(destination + sizeof(header), quoted_header, sizeof(*quoted_header));
  if (quote_length > 0) {
    memcpy(destination + sizeof(header) + sizeof(*quoted_header), quoted_payload, quote_length);
  }
  ((icmp_error_header_t*)destination)->checksum = checksum16(destination, total_length);
  *payload_length = (uint16_t)total_length;
  return true;
}

static bool icmp_write_ethernet_echo(FILE* destination, const icmp_echo_request_data_t* request_data, uint8_t type) {
  if (request_data->data_length > ETHERNET_MAX_DATA_LEN - sizeof(ipv4_header_t) - sizeof(icmp_echo_header_t)) {
    return false;
  }

  uint8_t packet[sizeof(icmp_echo_header_t) + ETHERNET_MAX_DATA_LEN] = {0};
  icmp_echo_header_t header = {
      .type = type,
      .code = ICMP_CODE_ECHO,
      .identifier = request_data->identifier,
      .sequence_number = request_data->sequence_number,
  };
  memcpy(packet, &header, sizeof(header));
  memcpy(packet + sizeof(header), request_data->data, request_data->data_length);
  ((icmp_echo_header_t*)packet)->checksum = checksum16(packet, sizeof(header) + request_data->data_length);

  ipv4_packet_data_t ipv4_packet = {
      .src_addr = request_data->src_addr,
      .dst_addr = request_data->dst_addr,
      .protocol = ICMP_IPV4_PROTOCOL,
      .data = packet,
      .data_length = sizeof(header) + request_data->data_length,
  };
  memcpy(ipv4_packet.dst_mac_addr, request_data->dst_mac_addr, sizeof(ipv4_packet.dst_mac_addr));
  memcpy(ipv4_packet.src_mac_addr, request_data->src_mac_addr, sizeof(ipv4_packet.src_mac_addr));
  return ipv4_write_ethernet_packet(destination, &ipv4_packet);
}

bool icmp_write_ethernet_echo_request(FILE* destination, const icmp_echo_request_data_t* request_data) {
  return icmp_write_ethernet_echo(destination, request_data, ICMP_TYPE_ECHO_REQUEST);
}

bool icmp_write_ethernet_echo_reply(FILE* destination, const icmp_echo_request_data_t* request_data) {
  return icmp_write_ethernet_echo(destination, request_data, ICMP_TYPE_ECHO_REPLY);
}

bool icmp_parse_echo_packet(const uint8_t* bytes, size_t byte_count, icmp_echo_header_t* header, const uint8_t** data, size_t* data_length) {
  if (byte_count < sizeof(*header)) {
    return false;
  }
  memcpy(header, bytes, sizeof(*header));
  if ((header->type != ICMP_TYPE_ECHO_REQUEST && header->type != ICMP_TYPE_ECHO_REPLY) || header->code != ICMP_CODE_ECHO || checksum16(bytes, byte_count) != 0) {
    return false;
  }
  *data = bytes + sizeof(*header);
  *data_length = byte_count - sizeof(*header);
  return true;
}
