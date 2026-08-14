#include <icmpv6.h>

#include <math.h>
#include <string.h>

typedef struct icmpv6_pseudo_header {
  ipv6_address_t source;
  ipv6_address_t destination;
  uint32_t upper_layer_length;
  uint8_t zero[3];
  uint8_t next_header;
} icmpv6_pseudo_header_t;

uint16_t icmpv6_checksum(const ipv6_address_t* source, const ipv6_address_t* destination, const void* message, uint16_t message_length) {
  uint8_t bytes[sizeof(icmpv6_pseudo_header_t) + ETHERNET_MAX_DATA_LEN] = {0};
  icmpv6_pseudo_header_t pseudo = {
      .source = *source,
      .destination = *destination,
      .upper_layer_length = message_length,
      .next_header = IPV6_NEXT_HEADER_ICMPV6,
  };
  memcpy(bytes, &pseudo, sizeof(pseudo));
  memcpy(bytes + sizeof(pseudo), message, message_length);
  return checksum16(bytes, sizeof(pseudo) + message_length);
}

bool icmpv6_parse_header(const uint8_t* bytes, size_t byte_count, const ipv6_address_t* source, const ipv6_address_t* destination, icmpv6_header_t* header) {
  if (!bytes || !source || !destination || !header || byte_count < sizeof(*header)) return false;
  memcpy(header, bytes, sizeof(*header));
  return icmpv6_checksum(source, destination, bytes, (uint16_t)byte_count) == 0;
}

static bool icmpv6_write_ethernet_echo(FILE* destination, const icmpv6_echo_packet_data_t* request_data, uint8_t type) {
  if (!destination || !request_data || request_data->data_length > ETHERNET_MAX_DATA_LEN - sizeof(ipv6_header_t) - sizeof(icmpv6_echo_header_t)) return false;
  uint8_t packet[sizeof(icmpv6_echo_header_t) + ETHERNET_MAX_DATA_LEN] = {0};
  icmpv6_echo_header_t header = {
      .type = type,
      .identifier = request_data->identifier,
      .sequence_number = request_data->sequence_number,
  };
  memcpy(packet, &header, sizeof(header));
  memcpy(packet + sizeof(header), request_data->data, request_data->data_length);
  ((icmpv6_echo_header_t*)packet)->checksum = icmpv6_checksum(&request_data->src_addr, &request_data->dst_addr, packet, (uint16_t)(sizeof(header) + request_data->data_length));
  ipv6_packet_data_t ipv6_packet = {
      .src_addr = request_data->src_addr,
      .dst_addr = request_data->dst_addr,
      .next_header = IPV6_NEXT_HEADER_ICMPV6,
      .hop_limit = request_data->hop_limit ? request_data->hop_limit : IPV6_DEFAULT_HOP_LIMIT,
      .data = packet,
      .data_length = (uint16_t)(sizeof(header) + request_data->data_length),
  };
  memcpy(ipv6_packet.dst_mac_addr, request_data->dst_mac_addr, sizeof(ipv6_packet.dst_mac_addr));
  memcpy(ipv6_packet.src_mac_addr, request_data->src_mac_addr, sizeof(ipv6_packet.src_mac_addr));
  return ipv6_write_ethernet_packet(destination, &ipv6_packet);
}

bool icmpv6_write_ethernet_echo_request(FILE* destination, const icmpv6_echo_packet_data_t* request_data) {
  return icmpv6_write_ethernet_echo(destination, request_data, ICMPV6_TYPE_ECHO_REQUEST);
}

bool icmpv6_write_ethernet_echo_reply(FILE* destination, const icmpv6_echo_packet_data_t* request_data) {
  return icmpv6_write_ethernet_echo(destination, request_data, ICMPV6_TYPE_ECHO_REPLY);
}

bool icmpv6_parse_echo_packet(const uint8_t* bytes, size_t byte_count, const ipv6_address_t* source, const ipv6_address_t* destination, icmpv6_echo_header_t* header, const uint8_t** data, size_t* data_length) {
  if (!bytes || !source || !destination || !header || !data || !data_length || byte_count < sizeof(*header)) return false;
  memcpy(header, bytes, sizeof(*header));
  if ((header->type != ICMPV6_TYPE_ECHO_REQUEST && header->type != ICMPV6_TYPE_ECHO_REPLY) || header->code != 0 || icmpv6_checksum(source, destination, bytes, (uint16_t)byte_count) != 0) return false;
  *data = bytes + sizeof(*header);
  *data_length = byte_count - sizeof(*header);
  return true;
}
