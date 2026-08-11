#include <udp.h>
#include <math.h>
#include <string.h>

#pragma pack(push, 1)
typedef struct udp_pseudo_header {
  ipv4_address_t src_addr;
  ipv4_address_t dst_addr;
  uint8_t zero;
  uint8_t protocol;
  uint16_t length;
} udp_pseudo_header_t;
#pragma pack(pop)

static uint16_t udp_checksum(const uint8_t* bytes, uint16_t length, ipv4_address_t src_addr, ipv4_address_t dst_addr) {
  uint8_t checksum_bytes[sizeof(udp_pseudo_header_t) + ETHERNET_MAX_DATA_LEN] = {0};
  const udp_pseudo_header_t pseudo_header = {
      .src_addr = src_addr,
      .dst_addr = dst_addr,
      .protocol = UDP_IPV4_PROTOCOL,
      .length = length,
  };
  memcpy(checksum_bytes, &pseudo_header, sizeof(pseudo_header));
  memcpy(checksum_bytes + sizeof(pseudo_header), bytes, length);
  return checksum16(checksum_bytes, sizeof(pseudo_header) + length);
}

bool udp_serialize_packet(const udp_packet_data_t* packet_data, uint8_t* packet, size_t capacity, uint16_t* length) {
  if (!packet_data || !packet || !length || packet_data->data_length > ETHERNET_MAX_DATA_LEN - sizeof(ipv4_header_t) - sizeof(udp_header_t) || sizeof(udp_header_t) + packet_data->data_length > capacity) return false;

  udp_header_t header = {
      .src_port = packet_data->src_port,
      .dst_port = packet_data->dst_port,
      .length = sizeof(header) + packet_data->data_length,
  };
  memcpy(packet, &header, sizeof(header));
  if (packet_data->data_length) memcpy(packet + sizeof(header), packet_data->data, packet_data->data_length);
  ((udp_header_t*)packet)->checksum = udp_checksum(packet, header.length, packet_data->src_addr, packet_data->dst_addr);
  if (((udp_header_t*)packet)->checksum == 0) ((udp_header_t*)packet)->checksum = UINT16_MAX;
  *length = header.length;
  return true;
}

bool udp_write_ethernet_packet(FILE* destination, const udp_packet_data_t* packet_data) {
  uint8_t packet[sizeof(udp_header_t) + ETHERNET_MAX_DATA_LEN] = {0};
  uint16_t length = 0;
  if (!udp_serialize_packet(packet_data, packet, sizeof(packet), &length)) return false;

  ipv4_packet_data_t ipv4_packet = {
      .src_addr = packet_data->src_addr,
      .dst_addr = packet_data->dst_addr,
      .protocol = UDP_IPV4_PROTOCOL,
      .data = packet,
      .data_length = length,
  };
  memcpy(ipv4_packet.dst_mac_addr, packet_data->dst_mac_addr, sizeof(ipv4_packet.dst_mac_addr));
  memcpy(ipv4_packet.src_mac_addr, packet_data->src_mac_addr, sizeof(ipv4_packet.src_mac_addr));
  return ipv4_write_ethernet_packet(destination, &ipv4_packet);
}

bool udp_parse_packet(const uint8_t* bytes, size_t byte_count, ipv4_address_t src_addr, ipv4_address_t dst_addr, udp_packet_view_t* packet) {
  if (byte_count < sizeof(packet->header)) {
    return false;
  }
  memcpy(&packet->header, bytes, sizeof(packet->header));
  if (packet->header.length < sizeof(packet->header) || packet->header.length != byte_count || (packet->header.checksum != 0 && udp_checksum(bytes, packet->header.length, src_addr, dst_addr) != 0)) {
    return false;
  }
  packet->data = bytes + sizeof(packet->header);
  packet->data_length = packet->header.length - sizeof(packet->header);
  return true;
}
