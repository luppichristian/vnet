#include <socket_udp.h>

#include <udp.h>

#include <string.h>

static socket_entry_t* udp_entry(socket_context_t* context, socket_handle_t handle) {
  return !context || handle == SOCKET_INVALID_HANDLE || handle > SOCKET_CAPACITY ? NULL : &context->entries[handle - 1];
}

static socket_entry_t* udp_find(socket_context_t* context, uint16_t local_port) {
  for (size_t i = 0; i < SOCKET_CAPACITY; ++i) {
    socket_entry_t* entry = &context->entries[i];
    if (entry->active && entry->protocol == SOCKET_PROTOCOL_UDP && entry->local_port == local_port) return entry;
  }
  return NULL;
}

bool socket_udp_connect(socket_context_t* context, socket_handle_t handle, ipv4_address_t destination, uint16_t destination_port) {
  socket_entry_t* entry = udp_entry(context, handle);
  if (!entry || !entry->active || entry->state != SOCKET_STATE_BOUND) return false;
  entry->remote_address = destination;
  entry->remote_port = destination_port;
  entry->state = SOCKET_STATE_ESTABLISHED;
  return true;
}

bool socket_udp_send(socket_context_t* context, socket_handle_t handle, ipv4_address_t destination, uint16_t destination_port, const void* data, uint16_t data_length) {
  socket_entry_t* entry = udp_entry(context, handle);
  if (!entry || !entry->active || (entry->state != SOCKET_STATE_BOUND && entry->state != SOCKET_STATE_ESTABLISHED) || !destination || !destination_port || !data || !data_length) return false;
  uint8_t bytes[sizeof(udp_header_t) + SOCKET_RECEIVE_CAPACITY] = {0};
  uint16_t length = 0;
  const udp_packet_data_t packet = {
      .src_addr = context->local_address,
      .dst_addr = destination,
      .src_port = entry->local_port,
      .dst_port = destination_port,
      .data = data,
      .data_length = data_length,
  };
  return udp_serialize_packet(&packet, bytes, sizeof(bytes), &length) && context->emit_ipv4(context->emit_argument, destination, UDP_IPV4_PROTOCOL, bytes, length);
}

bool socket_udp_receive_ipv4(socket_context_t* context, const ipv4_packet_view_t* packet) {
  udp_packet_view_t datagram = {0};
  if (!udp_parse_packet(packet->payload, packet->payload_length, packet->header.src_addr, packet->header.dst_addr, &datagram)) return false;
  socket_entry_t* entry = udp_find(context, datagram.header.dst_port);
  if (!entry || datagram.data_length > SOCKET_RECEIVE_CAPACITY) return false;
  if (entry->state == SOCKET_STATE_ESTABLISHED && (entry->remote_address != packet->header.src_addr || entry->remote_port != datagram.header.src_port)) return false;
  if (entry->receive_length) return false;
  memcpy(entry->receive_buffer, datagram.data, datagram.data_length);
  entry->receive_length = datagram.data_length;
  entry->received_address = packet->header.src_addr;
  entry->received_port = datagram.header.src_port;
  return true;
}

bool socket_udp_tick(socket_context_t* context, uint32_t now) {
  (void)context;
  (void)now;
  return true;
}
