#include <tcp.h>
#include <math.h>
#include <string.h>

#pragma pack(push, 1)
typedef struct tcp_pseudo_header {
  ipv4_address_t src_addr;
  ipv4_address_t dst_addr;
  uint8_t zero;
  uint8_t protocol;
  uint16_t length;
} tcp_pseudo_header_t;
#pragma pack(pop)

static uint16_t tcp_checksum(const uint8_t* bytes, uint16_t length, ipv4_address_t src_addr, ipv4_address_t dst_addr) {
  uint8_t checksum_bytes[sizeof(tcp_pseudo_header_t) + ETHERNET_MAX_DATA_LEN] = {0};
  const tcp_pseudo_header_t pseudo_header = {
      .src_addr = src_addr,
      .dst_addr = dst_addr,
      .protocol = TCP_IPV4_PROTOCOL,
      .length = length,
  };
  memcpy(checksum_bytes, &pseudo_header, sizeof(pseudo_header));
  memcpy(checksum_bytes + sizeof(pseudo_header), bytes, length);
  return checksum16(checksum_bytes, sizeof(pseudo_header) + length);
}

bool tcp_write_ethernet_packet(FILE* destination, const tcp_packet_data_t* packet_data) {
  if (packet_data->data_length > ETHERNET_MAX_DATA_LEN - sizeof(ipv4_header_t) - sizeof(tcp_header_t) || (packet_data->flags & ~(TCP_FLAG_FIN | TCP_FLAG_SYN | TCP_FLAG_RST | TCP_FLAG_PSH | TCP_FLAG_ACK | TCP_FLAG_URG | TCP_FLAG_ECE | TCP_FLAG_CWR | TCP_FLAG_NS)) != 0) {
    return false;
  }

  uint8_t packet[sizeof(tcp_header_t) + ETHERNET_MAX_DATA_LEN] = {0};
  tcp_header_t header = {
      .src_port = packet_data->src_port,
      .dst_port = packet_data->dst_port,
      .sequence_number = packet_data->sequence_number,
      .acknowledgement_number = packet_data->acknowledgement_number,
      .data_offset = 5,
      .ns = (packet_data->flags & TCP_FLAG_NS) != 0,
      .fin = (packet_data->flags & TCP_FLAG_FIN) != 0,
      .syn = (packet_data->flags & TCP_FLAG_SYN) != 0,
      .rst = (packet_data->flags & TCP_FLAG_RST) != 0,
      .psh = (packet_data->flags & TCP_FLAG_PSH) != 0,
      .ack = (packet_data->flags & TCP_FLAG_ACK) != 0,
      .urg = (packet_data->flags & TCP_FLAG_URG) != 0,
      .ece = (packet_data->flags & TCP_FLAG_ECE) != 0,
      .cwr = (packet_data->flags & TCP_FLAG_CWR) != 0,
      .window_size = packet_data->window_size,
  };
  const uint16_t length = sizeof(header) + packet_data->data_length;
  memcpy(packet, &header, sizeof(header));
  memcpy(packet + sizeof(header), packet_data->data, packet_data->data_length);
  ((tcp_header_t*)packet)->checksum = tcp_checksum(packet, length, packet_data->src_addr, packet_data->dst_addr);

  ipv4_packet_data_t ipv4_packet = {
      .src_addr = packet_data->src_addr,
      .dst_addr = packet_data->dst_addr,
      .protocol = TCP_IPV4_PROTOCOL,
      .data = packet,
      .data_length = length,
  };
  memcpy(ipv4_packet.dst_mac_addr, packet_data->dst_mac_addr, sizeof(ipv4_packet.dst_mac_addr));
  memcpy(ipv4_packet.src_mac_addr, packet_data->src_mac_addr, sizeof(ipv4_packet.src_mac_addr));
  return ipv4_write_ethernet_packet(destination, &ipv4_packet);
}

bool tcp_parse_packet(const uint8_t* bytes, size_t byte_count, ipv4_address_t src_addr, ipv4_address_t dst_addr, tcp_packet_view_t* packet) {
  if (byte_count < sizeof(packet->header)) {
    return false;
  }
  memcpy(&packet->header, bytes, sizeof(packet->header));
  const size_t header_length = (size_t)packet->header.data_offset * 4;
  if (packet->header.data_offset != 5 || packet->header.reserved != 0 || header_length > byte_count || tcp_checksum(bytes, (uint16_t)byte_count, src_addr, dst_addr) != 0) {
    return false;
  }
  packet->data = bytes + header_length;
  packet->data_length = (uint16_t)(byte_count - header_length);
  return true;
}
