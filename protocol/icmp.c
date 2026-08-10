#include <icmp.h>
#include <math.h>
#include <string.h>

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
