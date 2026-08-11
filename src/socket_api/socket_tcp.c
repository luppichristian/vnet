#include <socket_tcp.h>

#include <tcp.h>

#include <string.h>

static socket_entry_t* tcp_entry(socket_context_t* context, socket_handle_t handle) {
  return !context || handle == SOCKET_INVALID_HANDLE || handle > SOCKET_CAPACITY ? NULL : &context->entries[handle - 1];
}

static bool tcp_emit(socket_context_t* context, socket_entry_t* entry, uint32_t sequence_number, uint16_t flags, const void* data, uint16_t data_length) {
  uint8_t bytes[sizeof(tcp_header_t) + SOCKET_RECEIVE_CAPACITY] = {0};
  uint16_t length = 0;
  const tcp_packet_data_t packet = {
      .src_addr = context->local_address,
      .dst_addr = entry->remote_address,
      .src_port = entry->local_port,
      .dst_port = entry->remote_port,
      .sequence_number = sequence_number,
      .acknowledgement_number = entry->receive_sequence,
      .flags = flags,
      .window_size = SOCKET_RECEIVE_CAPACITY - entry->receive_length,
      .data = data,
      .data_length = data_length,
  };
  return tcp_serialize_packet(&packet, bytes, sizeof(bytes), &length) && context->emit_ipv4(context->emit_argument, entry->remote_address, TCP_IPV4_PROTOCOL, bytes, length);
}

static socket_entry_t* tcp_find_connection(socket_context_t* context, uint16_t local_port, ipv4_address_t remote_address, uint16_t remote_port) {
  for (size_t i = 0; i < SOCKET_CAPACITY; ++i) {
    socket_entry_t* entry = &context->entries[i];
    if (entry->active && entry->protocol == SOCKET_PROTOCOL_TCP && entry->state != SOCKET_STATE_LISTEN && entry->local_port == local_port && entry->remote_address == remote_address && entry->remote_port == remote_port) return entry;
  }
  return NULL;
}

static socket_entry_t* tcp_find_listener(socket_context_t* context, uint16_t local_port, socket_handle_t* handle) {
  for (size_t i = 0; i < SOCKET_CAPACITY; ++i) {
    socket_entry_t* entry = &context->entries[i];
    if (entry->active && entry->protocol == SOCKET_PROTOCOL_TCP && entry->state == SOCKET_STATE_LISTEN && entry->local_port == local_port) {
      if (handle) *handle = (socket_handle_t)(i + 1);
      return entry;
    }
  }
  return NULL;
}

static socket_entry_t* tcp_allocate(socket_context_t* context, socket_handle_t* handle) {
  for (size_t i = 0; i < SOCKET_CAPACITY; ++i) {
    if (!context->entries[i].active) {
      memset(&context->entries[i], 0, sizeof(context->entries[i]));
      context->entries[i].active = true;
      context->entries[i].protocol = SOCKET_PROTOCOL_TCP;
      if (handle) *handle = (socket_handle_t)(i + 1);
      return &context->entries[i];
    }
  }
  return NULL;
}

bool socket_tcp_connect(socket_context_t* context, socket_handle_t handle, ipv4_address_t destination, uint16_t destination_port) {
  socket_entry_t* entry = tcp_entry(context, handle);
  if (!entry || !entry->active || entry->state != SOCKET_STATE_BOUND) return false;
  entry->remote_address = destination;
  entry->remote_port = destination_port;
  entry->send_sequence = 1;
  entry->state = SOCKET_STATE_SYN_SENT;
  const uint32_t sequence_number = entry->send_sequence++;
  if (tcp_emit(context, entry, sequence_number, TCP_FLAG_SYN, NULL, 0)) return true;
  entry->remote_address = 0;
  entry->remote_port = 0;
  entry->send_sequence = 0;
  entry->state = SOCKET_STATE_BOUND;
  return false;
}

bool socket_tcp_listen(socket_context_t* context, socket_handle_t handle) {
  socket_entry_t* entry = tcp_entry(context, handle);
  if (!entry || !entry->active || entry->state != SOCKET_STATE_BOUND) return false;
  entry->state = SOCKET_STATE_LISTEN;
  return true;
}

bool socket_tcp_send(socket_context_t* context, socket_handle_t handle, const void* data, uint16_t length) {
  socket_entry_t* entry = tcp_entry(context, handle);
  if (!entry || !entry->active || entry->state != SOCKET_STATE_ESTABLISHED || !data || !length || length > SOCKET_RECEIVE_CAPACITY) return false;
  const uint32_t sequence_number = entry->send_sequence;
  entry->send_sequence += length;
  return tcp_emit(context, entry, sequence_number, TCP_FLAG_ACK | TCP_FLAG_PSH, data, length);
}

bool socket_tcp_receive_ipv4(socket_context_t* context, const ipv4_packet_view_t* packet) {
  tcp_packet_view_t segment = {0};
  if (!tcp_parse_packet(packet->payload, packet->payload_length, packet->header.src_addr, packet->header.dst_addr, &segment)) return false;
  socket_entry_t* entry = tcp_find_connection(context, segment.header.dst_port, packet->header.src_addr, segment.header.src_port);

  if (!entry && segment.header.syn && !segment.header.ack) {
    socket_handle_t listener_handle = SOCKET_INVALID_HANDLE;
    socket_entry_t* listener = tcp_find_listener(context, segment.header.dst_port, &listener_handle);
    socket_handle_t child_handle = SOCKET_INVALID_HANDLE;
    if (!listener || listener->accepted || !(entry = tcp_allocate(context, &child_handle))) return false;
    entry->local_port = segment.header.dst_port;
    entry->remote_address = packet->header.src_addr;
    entry->remote_port = segment.header.src_port;
    entry->send_sequence = 1;
    entry->receive_sequence = segment.header.sequence_number + 1;
    entry->state = SOCKET_STATE_SYN_RECEIVED;
    const uint32_t sequence_number = entry->send_sequence++;
    if (!tcp_emit(context, entry, sequence_number, TCP_FLAG_SYN | TCP_FLAG_ACK, NULL, 0)) {
      memset(entry, 0, sizeof(*entry));
      return false;
    }
    listener->accepted = child_handle;
    (void)listener_handle;
    return true;
  }
  if (!entry) return false;

  if (entry->state == SOCKET_STATE_SYN_SENT && segment.header.syn && segment.header.ack && segment.header.acknowledgement_number == entry->send_sequence) {
    entry->receive_sequence = segment.header.sequence_number + 1;
    entry->acknowledged_sequence = segment.header.acknowledgement_number;
    entry->state = SOCKET_STATE_ESTABLISHED;
    return tcp_emit(context, entry, entry->send_sequence, TCP_FLAG_ACK, NULL, 0);
  }
  if (entry->state == SOCKET_STATE_SYN_RECEIVED && segment.header.ack && !segment.header.syn && segment.header.acknowledgement_number == entry->send_sequence) {
    entry->acknowledged_sequence = segment.header.acknowledgement_number;
    entry->state = SOCKET_STATE_ESTABLISHED;
    return true;
  }
  if (entry->state != SOCKET_STATE_ESTABLISHED && entry->state != SOCKET_STATE_CLOSE_WAIT) return false;

  if (segment.header.ack) entry->acknowledged_sequence = segment.header.acknowledgement_number;
  if (segment.data_length) {
    if (segment.header.sequence_number != entry->receive_sequence || segment.data_length > SOCKET_RECEIVE_CAPACITY - entry->receive_length) return false;
    memcpy(entry->receive_buffer + entry->receive_length, segment.data, segment.data_length);
    entry->receive_length += segment.data_length;
    entry->receive_sequence += segment.data_length;
    entry->received_address = packet->header.src_addr;
    entry->received_port = segment.header.src_port;
    return tcp_emit(context, entry, entry->send_sequence, TCP_FLAG_ACK, NULL, 0);
  }
  if (segment.header.fin && segment.header.sequence_number == entry->receive_sequence) {
    ++entry->receive_sequence;
    entry->state = SOCKET_STATE_CLOSE_WAIT;
    return tcp_emit(context, entry, entry->send_sequence, TCP_FLAG_ACK, NULL, 0);
  }
  return true;
}

bool socket_tcp_close(socket_context_t* context, socket_handle_t handle) {
  socket_entry_t* entry = tcp_entry(context, handle);
  return !entry || !entry->active || entry->state != SOCKET_STATE_ESTABLISHED || tcp_emit(context, entry, entry->send_sequence, TCP_FLAG_ACK | TCP_FLAG_FIN, NULL, 0);
}

bool socket_tcp_tick(socket_context_t* context, uint32_t now) {
  (void)context;
  (void)now;
  return true;
}
