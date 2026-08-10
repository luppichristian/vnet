#include <ipv4.h>
#include <math.h>
#include <string.h>

bool ipv4_write_ethernet_packet(FILE* destination, const ipv4_packet_data_t* packet_data) {
  if (packet_data->data_length > ETHERNET_MAX_DATA_LEN - sizeof(ipv4_header_t)) {
    return false;
  }

  uint8_t packet[sizeof(ipv4_header_t) + ETHERNET_MAX_DATA_LEN] = {0};
  ipv4_header_t header = {
      .version = 4,
      .ihl = 5,
      .total_length = sizeof(header) + packet_data->data_length,
      .fragment_id = 1,
      .dont_fragment = 1,
      .ttl = IPV4_DEFAULT_TTL,
      .protocol = packet_data->protocol,
      .src_addr = packet_data->src_addr,
      .dst_addr = packet_data->dst_addr,
  };
  header.header_checksum = checksum16(&header, sizeof(header));
  memcpy(packet, &header, sizeof(header));
  memcpy(packet + sizeof(header), packet_data->data, packet_data->data_length);

  ethernet_frame_data_t frame = {
      .type_or_length = ETHERNET_ETHERTYPE_IPV4,
      .data_length = sizeof(header) + packet_data->data_length,
      .data = packet,
  };
  memcpy(frame.dst_addr, packet_data->dst_mac_addr, sizeof(frame.dst_addr));
  memcpy(frame.src_addr, packet_data->src_mac_addr, sizeof(frame.src_addr));
  return ethernet_write_frame(destination, &frame);
}

bool ipv4_parse_packet(const uint8_t* bytes, size_t byte_count, ipv4_packet_view_t* packet) {
  if (byte_count < sizeof(packet->header)) {
    return false;
  }
  memcpy(&packet->header, bytes, sizeof(packet->header));
  if (packet->header.version != 4 || packet->header.ihl != 5 || packet->header.total_length < sizeof(packet->header) || packet->header.total_length > byte_count || checksum16(&packet->header, sizeof(packet->header)) != 0) {
    return false;
  }
  packet->payload = bytes + sizeof(packet->header);
  packet->payload_length = packet->header.total_length - sizeof(packet->header);
  return true;
}
