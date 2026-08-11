#include <ipv4.h>
#include <math.h>
#include <string.h>

bool ipv4_parse_address(const char* text, ipv4_address_t* address) {
  unsigned int octets[4] = {0};
  char trailing = '\0';
  if (sscanf(text, "%u.%u.%u.%u%c", &octets[0], &octets[1], &octets[2], &octets[3], &trailing) != 4) {
    return false;
  }
  for (size_t i = 0; i < 4; ++i) {
    if (octets[i] > UINT8_MAX) {
      return false;
    }
  }
  *address = IPV4_ADDRESS(octets[0], octets[1], octets[2], octets[3]);
  return true;
}

bool ipv4_mask_is_contiguous(ipv4_address_t mask) {
  const uint32_t bits = ((mask & 0x000000FFu) << 24) | ((mask & 0x0000FF00u) << 8) | ((mask & 0x00FF0000u) >> 8) | ((mask & 0xFF000000u) >> 24);
  return (bits | (bits - 1u)) == UINT32_MAX;
}

bool ipv4_addresses_share_subnet(ipv4_address_t first, ipv4_address_t second, ipv4_address_t mask) {
  return (first & mask) == (second & mask);
}

void ipv4_address_print(FILE* destination, ipv4_address_t address) {
  fprintf(destination, "%u.%u.%u.%u", address & 0xFF, (address >> 8) & 0xFF, (address >> 16) & 0xFF, address >> 24);
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
