#include <arp.h>
#include <string.h>

bool arp_write_ethernet_request(FILE* destination, const arp_packet_data_t* packet_data) {
  arp_packet_t packet = {
      .hardware_type = ARP_HARDWARE_TYPE_ETHERNET,
      .protocol_type = ETHERNET_ETHERTYPE_IPV4,
      .hardware_address_length = sizeof(mac_address_t),
      .protocol_address_length = sizeof(ipv4_address_t),
      .operation = ARP_OPERATION_REQUEST,
      .sender_protocol_address = packet_data->sender_protocol_address,
      .target_protocol_address = packet_data->target_protocol_address,
  };
  memcpy(packet.sender_hardware_address, packet_data->sender_hardware_address, sizeof(packet.sender_hardware_address));

  ethernet_frame_data_t frame = {
      .dst_addr = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF},
      .type_or_length = ETHERNET_ETHERTYPE_ARP,
      .data_length = sizeof(packet),
      .data = &packet,
  };
  memcpy(frame.src_addr, packet_data->sender_hardware_address, sizeof(frame.src_addr));
  return ethernet_write_frame(destination, &frame);
}

bool arp_parse_packet(const uint8_t* bytes, size_t byte_count, arp_packet_t* packet) {
  if (byte_count != sizeof(*packet)) {
    return false;
  }
  memcpy(packet, bytes, sizeof(*packet));
  return packet->hardware_type == ARP_HARDWARE_TYPE_ETHERNET && packet->protocol_type == ETHERNET_ETHERTYPE_IPV4 && packet->hardware_address_length == sizeof(mac_address_t) && packet->protocol_address_length == sizeof(ipv4_address_t) && (packet->operation == ARP_OPERATION_REQUEST || packet->operation == ARP_OPERATION_REPLY);
}
