/*
 * MIT License
 *
 * Copyright (c) 2026 Christian Luppi
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
#include <rarp.h>
#include <string.h>

bool rarp_write_ethernet_request(FILE* destination, const rarp_request_data_t* request_data) {
  rarp_packet_t packet = {
      .hardware_type = RARP_HARDWARE_TYPE_ETHERNET,
      .protocol_type = ETHERNET_ETHERTYPE_IPV4,
      .hardware_address_length = sizeof(mac_address_t),
      .protocol_address_length = sizeof(ipv4_address_t),
      .operation = RARP_OPERATION_REQUEST,
  };
  memcpy(packet.sender_hardware_address, request_data->client_hardware_address, sizeof(packet.sender_hardware_address));
  memcpy(packet.target_hardware_address, request_data->client_hardware_address, sizeof(packet.target_hardware_address));

  ethernet_frame_data_t frame = {
      .dst_addr = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF},
      .type_or_length = ETHERNET_ETHERTYPE_RARP,
      .data_length = sizeof(packet),
      .data = &packet,
  };
  memcpy(frame.src_addr, request_data->client_hardware_address, sizeof(frame.src_addr));
  return ethernet_write_frame(destination, &frame);
}

bool rarp_write_ethernet_reply(FILE* destination, const rarp_reply_data_t* reply_data) {
  rarp_packet_t packet = {
      .hardware_type = RARP_HARDWARE_TYPE_ETHERNET,
      .protocol_type = ETHERNET_ETHERTYPE_IPV4,
      .hardware_address_length = sizeof(mac_address_t),
      .protocol_address_length = sizeof(ipv4_address_t),
      .operation = RARP_OPERATION_REPLY,
      .sender_protocol_address = reply_data->server_protocol_address,
      .target_protocol_address = reply_data->client_protocol_address,
  };
  memcpy(packet.sender_hardware_address, reply_data->server_hardware_address, sizeof(packet.sender_hardware_address));
  memcpy(packet.target_hardware_address, reply_data->client_hardware_address, sizeof(packet.target_hardware_address));

  ethernet_frame_data_t frame = {
      .type_or_length = ETHERNET_ETHERTYPE_RARP,
      .data_length = sizeof(packet),
      .data = &packet,
  };
  memcpy(frame.dst_addr, reply_data->client_hardware_address, sizeof(frame.dst_addr));
  memcpy(frame.src_addr, reply_data->server_hardware_address, sizeof(frame.src_addr));
  return ethernet_write_frame(destination, &frame);
}

bool rarp_parse_packet(const uint8_t* bytes, size_t byte_count, rarp_packet_t* packet) {
  if (byte_count != sizeof(*packet)) {
    return false;
  }
  memcpy(packet, bytes, sizeof(*packet));
  return packet->hardware_type == RARP_HARDWARE_TYPE_ETHERNET && packet->protocol_type == ETHERNET_ETHERTYPE_IPV4 && packet->hardware_address_length == sizeof(mac_address_t) && packet->protocol_address_length == sizeof(ipv4_address_t) && (packet->operation == RARP_OPERATION_REQUEST || packet->operation == RARP_OPERATION_REPLY);
}
