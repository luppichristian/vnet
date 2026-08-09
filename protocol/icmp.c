#include <icmp.h>
#include <string.h>

uint16_t icmp_checksum(const void* data, size_t data_size) {
  const uint8_t* bytes = data;
  uint32_t sum = 0;
  for (size_t i = 0; i < data_size; i += 2) {
    const uint16_t word = bytes[i] | (uint16_t)(i + 1 < data_size ? bytes[i + 1] << 8 : 0);
    sum += word;
    sum = (sum & 0xFFFFu) + (sum >> 16);
  }
  return (uint16_t)~sum;
}

bool icmp_write_ethernet_echo_request(FILE* destination, const icmp_echo_request_data_t* request_data) {
  if (request_data->data_length > ETHERNET_MAX_DATA_LEN - sizeof(ipv4_header_t) - sizeof(icmp_echo_header_t)) {
    return false;
  }

  uint8_t packet[sizeof(icmp_echo_header_t) + ETHERNET_MAX_DATA_LEN] = {0};
  icmp_echo_header_t header = {
      .type = ICMP_TYPE_ECHO_REQUEST,
      .code = ICMP_CODE_ECHO,
      .identifier = request_data->identifier,
      .sequence_number = request_data->sequence_number,
  };
  memcpy(packet, &header, sizeof(header));
  memcpy(packet + sizeof(header), request_data->data, request_data->data_length);
  ((icmp_echo_header_t*)packet)->checksum = icmp_checksum(packet, sizeof(header) + request_data->data_length);

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

bool icmp_parse_echo_packet(const uint8_t* bytes, size_t byte_count, icmp_echo_header_t* header, const uint8_t** data, size_t* data_length) {
  if (byte_count < sizeof(*header)) {
    return false;
  }
  memcpy(header, bytes, sizeof(*header));
  if ((header->type != ICMP_TYPE_ECHO_REQUEST && header->type != ICMP_TYPE_ECHO_REPLY) || header->code != ICMP_CODE_ECHO || icmp_checksum(bytes, byte_count) != 0) {
    return false;
  }
  *data = bytes + sizeof(*header);
  *data_length = byte_count - sizeof(*header);
  return true;
}
