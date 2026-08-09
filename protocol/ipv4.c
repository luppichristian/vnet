#include <ipv4.h>
#include <string.h>

uint16_t ipv4_checksum(const void* data, size_t data_size) {
  const uint8_t* bytes = data;
  uint32_t sum = 0;
  for (size_t i = 0; i < data_size; i += 2) {
    const uint16_t word = bytes[i] | (uint16_t)(i + 1 < data_size ? bytes[i + 1] << 8 : 0);
    sum += word;
    sum = (sum & 0xFFFFu) + (sum >> 16);
  }
  return (uint16_t)~sum;
}

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
  header.header_checksum = ipv4_checksum(&header, sizeof(header));
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
